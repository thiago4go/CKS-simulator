"""Command line implementation for the local CKS simulator."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .grading import grade_scenario, summarize_grades


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "scenarios" / "catalog.json"
DEFAULT_CLUSTER = "cks-simulator"
DEFAULT_IMAGE = "kindest/node:v1.35.1"
EXPECTED_NODE_COUNT = 3
LIVE_FIXTURE_IDS = {"04", "06", "07", "11", "15"}


def load_catalog() -> List[Dict[str, Any]]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def state_dir() -> Path:
    value = os.environ.get("CKS_STATE_DIR")
    return Path(value).expanduser().resolve() if value else ROOT / ".cks-state"


def cluster_name(args: argparse.Namespace) -> str:
    return args.name or os.environ.get("CKS_CLUSTER_NAME", DEFAULT_CLUSTER)


def kubeconfig_path(name: str) -> Path:
    return state_dir() / f"kubeconfig-{name}"


def metadata_path(name: str) -> Path:
    return state_dir() / f"cluster-{name}.json"


def e2e_claim_path(name: str) -> Path:
    return state_dir() / f"e2e-claim-{name}"


def state_is_owned(name: str) -> bool:
    metadata = metadata_path(name)
    if not metadata.is_file():
        return False
    try:
        value = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (
        value.get("managed_by") == "cks-simulator"
        and value.get("cluster_name") == name
        and value.get("status") in {None, "ready", "nodes-not-ready"}
    )


def global_kind() -> Optional[str]:
    return shutil.which("kind")


def kind_command() -> List[str]:
    explicit = os.environ.get("CKS_KIND_BIN")
    if explicit:
        return [explicit]
    if os.environ.get("CKS_KIND_USE_GLOBAL", "1") != "0" and global_kind():
        return [global_kind() or "kind"]
    return [str(ROOT / "tools" / "kind")]


def kubectl_command() -> Optional[str]:
    return shutil.which(os.environ.get("KUBECTL_BIN", "kubectl"))


def docker_command() -> Optional[str]:
    return shutil.which(os.environ.get("DOCKER_BIN", "docker"))


def curl_command() -> Optional[str]:
    return shutil.which("curl")


def checksum_command() -> Optional[str]:
    return shutil.which("shasum") or shutil.which("sha256sum")


def openssl_command() -> Optional[str]:
    return shutil.which("openssl")


def generate_tls_fixture(destination: Path) -> None:
    openssl = openssl_command()
    if not openssl:
        raise RuntimeError("openssl is required to generate the scenario 15 TLS fixture; run 'doctor'")
    destination.mkdir(parents=True, exist_ok=True)
    result = command_output(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(destination / "tls.key"),
            "-out", str(destination / "tls.crt"),
            "-subj", "/CN=secure-ingress.test", "-days", "3650",
        ],
        announce=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"openssl failed while generating scenario 15 TLS fixture: {result.stderr.strip()}")
    os.chmod(destination / "tls.key", 0o600)


def acquire_e2e_claim(name: str) -> Optional[str]:
    state_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir(), 0o700)
    token = uuid.uuid4().hex
    try:
        descriptor = os.open(e2e_claim_path(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return None
    with os.fdopen(descriptor, "w", encoding="utf-8") as claim:
        claim.write(token + "\n")
    return token


def e2e_claim_is_owned(name: str, token: Optional[str]) -> bool:
    if not token:
        return False
    try:
        return e2e_claim_path(name).read_text(encoding="utf-8").strip() == token
    except OSError:
        return False


def run_command(
    command: List[str], *, check: bool = True, announce: bool = True
) -> subprocess.CompletedProcess[str]:
    if announce:
        print("$ " + " ".join(command))
    return subprocess.run(command, check=check, text=True, capture_output=not announce)


def command_output(command: List[str], *, announce: bool = True) -> subprocess.CompletedProcess[str]:
    if announce:
        print("$ " + " ".join(command))
    return subprocess.run(command, check=False, text=True, capture_output=True)


def cluster_presence(name: str, *, announce: bool = True) -> Optional[bool]:
    result = command_output(kind_command() + ["get", "clusters"], announce=announce)
    return None if result.returncode != 0 else name in result.stdout.splitlines()


def cluster_exists(name: str, *, announce: bool = True) -> bool:
    return cluster_presence(name, announce=announce) is True


def node_statuses(name: str, *, announce: bool = True) -> List[Dict[str, Any]]:
    kube = kubeconfig_path(name)
    binary = kubectl_command()
    if not kube.is_file() or not binary:
        return []
    result = command_output(
        [binary, "--kubeconfig", str(kube), "--context", f"kind-{name}", "get", "nodes", "-o", "json"],
        announce=announce,
    )
    if result.returncode != 0:
        return []
    try:
        items = json.loads(result.stdout)["items"]
        return [
            {
                "name": item["metadata"]["name"],
                "ready": any(
                    condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in item.get("status", {}).get("conditions", [])
                ),
            }
            for item in items
        ]
    except (KeyError, TypeError, ValueError):
        return []


def cluster_healthy(name: str, *, announce: bool = True) -> bool:
    return nodes_healthy(node_statuses(name, announce=announce))


def nodes_healthy(nodes: List[Dict[str, Any]]) -> bool:
    return len(nodes) == EXPECTED_NODE_COUNT and all(node["ready"] for node in nodes)


def scenario_by_id(identifier: str) -> Dict[str, Any]:
    normalized = identifier.zfill(2)
    for item in load_catalog():
        if item["id"] == normalized:
            return item
    raise ValueError(f"unknown scenario {identifier!r}; use 'list' to see the catalog")


def print_catalog(as_json: bool = False) -> int:
    catalog = load_catalog()
    if as_json:
        print(json.dumps(catalog, indent=2, sort_keys=True))
        return 0
    for item in catalog:
        print(f"{item['id']}  {item['title']}  [{item['kind_support']}]  {item['compatibility']}")
    return 0


def doctor(as_json: bool = False) -> int:
    kind_fallback = ROOT / "tools" / "kind"
    fallback_selected = os.environ.get("CKS_KIND_USE_GLOBAL", "1") == "0" or global_kind() is None
    docker = docker_command()
    docker_detail = "not found"
    docker_ok = False
    if docker:
        docker_result = command_output([docker, "info", "--format", "{{.ServerVersion}}"], announce=not as_json)
        docker_ok = docker_result.returncode == 0
        docker_detail = docker_result.stdout.strip() if docker_ok else (docker_result.stderr.strip() or "daemon unavailable")
    checks = [
        {"name": "python3", "ok": sys.version_info >= (3, 9), "detail": sys.version.split()[0]},
        {"name": "docker daemon", "ok": docker_ok, "detail": docker_detail},
        {"name": "kubectl", "ok": kubectl_command() is not None, "detail": kubectl_command() or "not found"},
        {"name": "curl", "ok": (not fallback_selected) or curl_command() is not None, "detail": curl_command() or "not found"},
        {"name": "awk", "ok": (not fallback_selected) or shutil.which("awk") is not None, "detail": shutil.which("awk") or "not found"},
        {"name": "checksum tool", "ok": (not fallback_selected) or checksum_command() is not None, "detail": checksum_command() or "not found"},
        {"name": "openssl", "ok": openssl_command() is not None, "detail": openssl_command() or "not found"},
        {"name": "kind (global)", "ok": global_kind() is not None, "detail": global_kind() or "not found"},
        {"name": "kind (pinned fallback)", "ok": (not fallback_selected) or (kind_fallback.is_file() and os.access(kind_fallback, os.X_OK)), "detail": str(kind_fallback)},
    ]
    result = {"project": str(ROOT), "state_dir": str(state_dir()), "cluster_name": os.environ.get("CKS_CLUSTER_NAME", DEFAULT_CLUSTER), "checks": checks}
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"project: {ROOT}")
        print(f"state:   {state_dir()}")
        for check in checks:
            print(f"{'OK' if check['ok'] else 'MISSING':7} {check['name']}: {check['detail']}")
        print("note: Docker Desktop is required for a live kind cluster; unsupported scenarios remain artifact-checkable.")
    return 0 if all(check["ok"] for check in checks if check["name"] != "kind (global)") else 1


def provision(args: argparse.Namespace) -> int:
    name = cluster_name(args)
    quiet = getattr(args, "quiet", False)
    state_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir(), 0o700)
    config = ROOT / "kind" / "cluster.yaml"
    kube = kubeconfig_path(name)
    if cluster_exists(name, announce=not quiet):
        if not state_is_owned(name):
            print(f"refusing to manage unowned cluster {name!r}; choose another --name or delete it explicitly", file=sys.stderr)
            return 1
        if cluster_healthy(name, announce=not quiet):
            if not quiet:
                print(f"cluster already ready: {name}")
                print(f"kubeconfig: {kube}")
            return 0
        print(f"cluster {name!r} exists but is not healthy with project state; use 'reset' to recreate it", file=sys.stderr)
        return 1
    command = kind_command() + [
        "create", "cluster", "--name", name, "--config", str(config),
        "--image", args.image, "--kubeconfig", str(kube), "--wait", args.wait,
    ]
    metadata_path(name).write_text(
        json.dumps({"cluster_name": name, "image": args.image, "managed_by": "cks-simulator", "status": "creating"}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(metadata_path(name), 0o600)
    try:
        run_command(command, announce=not quiet)
    except FileNotFoundError as exc:
        metadata_path(name).unlink(missing_ok=True)
        print(f"unable to run kind: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        if kube.exists() and not kube.is_symlink():
            kube.unlink()
        metadata_path(name).unlink(missing_ok=True)
        print(f"kind failed while provisioning {name!r} (exit {exc.returncode}); partial kubeconfig removed", file=sys.stderr)
        return exc.returncode or 1
    os.chmod(kube, 0o600)
    try:
        ready_result = command_output(
            cluster_kubectl(name, ["wait", "--for=condition=Ready", "nodes", "--all", f"--timeout={args.wait}"]),
            announce=not quiet,
        )
    except RuntimeError as exc:
        ready_result = subprocess.CompletedProcess(command, 1, "", str(exc))
    if ready_result.returncode != 0:
        metadata_path(name).write_text(
            json.dumps({"cluster_name": name, "image": args.image, "managed_by": "cks-simulator", "status": "nodes-not-ready"}, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(metadata_path(name), 0o600)
        print(f"cluster {name!r} was created but all nodes did not become Ready; use 'reset' to retry", file=sys.stderr)
        return 1
    metadata_path(name).write_text(
        json.dumps({"cluster_name": name, "image": args.image, "managed_by": "cks-simulator", "status": "ready"}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(metadata_path(name), 0o600)
    if not quiet:
        print(f"cluster ready: {name}")
        print(f"kubeconfig: {kube}")
    return 0


def delete(args: argparse.Namespace) -> int:
    name = cluster_name(args)
    quiet = getattr(args, "quiet", False)
    kube = kubeconfig_path(name)
    if cluster_exists(name, announce=not quiet) and not state_is_owned(name) and not args.force:
        print(f"refusing to delete unowned cluster {name!r}; pass --force only if you explicitly intend to remove it", file=sys.stderr)
        return 1
    command = kind_command() + ["delete", "cluster", "--name", name]
    if kube.exists():
        command += ["--kubeconfig", str(kube)]
    try:
        result = run_command(command, check=False, announce=not quiet)
    except FileNotFoundError as exc:
        print(f"unable to run kind: {exc}", file=sys.stderr)
        return 1
    if result.returncode == 0:
        if kube.exists() and not kube.is_symlink():
            kube.unlink()
        if metadata_path(name).exists() and not metadata_path(name).is_symlink():
            metadata_path(name).unlink()
        if e2e_claim_path(name).exists() and not e2e_claim_path(name).is_symlink():
            e2e_claim_path(name).unlink()
    return result.returncode


def reset_cluster(args: argparse.Namespace) -> int:
    delete_args = argparse.Namespace(name=args.name, force=args.force)
    if delete(delete_args) != 0:
        return 1
    return provision(args)


def cluster_kubectl(name: str, args: Iterable[str]) -> List[str]:
    binary = kubectl_command()
    if not binary:
        raise RuntimeError("kubectl is required; run 'doctor'")
    return [binary, "--kubeconfig", str(kubeconfig_path(name)), "--context", f"kind-{name}", *args]


def open_shell(args: argparse.Namespace) -> int:
    name = cluster_name(args)
    node = args.node or f"{name}-control-plane"
    docker = docker_command()
    if not docker:
        print("docker is required; run 'doctor'", file=sys.stderr)
        return 1
    shell = args.shell or "/bin/bash"
    return run_command([docker, "exec", "-it", node, shell], check=False).returncode


def scenario_root(item: Dict[str, Any]) -> Path:
    return state_dir() / "scenarios" / item["id"]


def create_scenario(identifier: str, apply: bool = False, cluster: Optional[str] = None, reset: bool = False) -> int:
    item = scenario_by_id(identifier)
    destination = scenario_root(item)
    fixture_source = ROOT / "scenarios" / "fixtures" / item["id"]
    tls_temporary: Optional[tempfile.TemporaryDirectory[str]] = None
    try:
        if item["id"] == "15":
            tls_temporary = tempfile.TemporaryDirectory(prefix="cks-simulator-scenario-15-")
            generate_tls_fixture(Path(tls_temporary.name))
        if destination.exists():
            if not reset:
                print(f"scenario {item['id']} already exists; use 'scenario reset {item['id']}' to replace it", file=sys.stderr)
                return 1
            shutil.rmtree(destination)
        (destination / "artifacts").mkdir(parents=True)
        fixture_destination = destination / "fixture"
        if fixture_source.exists():
            shutil.copytree(fixture_source, fixture_destination)
        else:
            fixture_destination.mkdir()
        if tls_temporary:
            shutil.copy2(Path(tls_temporary.name) / "tls.crt", fixture_destination / "tls.crt")
            shutil.copy2(Path(tls_temporary.name) / "tls.key", fixture_destination / "tls.key")
            os.chmod(fixture_destination / "tls.key", 0o600)
    finally:
        if tls_temporary:
            tls_temporary.cleanup()
    (destination / "TASK.md").write_text(
        f"# Scenario {item['id']}: {item['title']}\n\n"
        f"Compatibility: **{item['kind_support']}** — {item['compatibility']}\n\n"
        f"{item['prompt']}\n\n"
        "Put your answer artifacts under `artifacts/`, then run `cks-simulator check "
        f"{item['id']}`.\n",
        encoding="utf-8",
    )
    print(f"created scenario {item['id']} at {destination}")
    if item["kind_support"] == "unsupported":
        print("compatibility: unsupported on stock kind; use the fixture as a command/configuration exercise")
    if apply:
        if item["kind_support"] == "unsupported":
            print("not applying unsupported fixture")
            return 0
        resources = fixture_destination / "resources.json"
        if not resources.exists():
            print("no resources.json fixture; nothing to apply")
            return 0
        target_cluster = cluster or os.environ.get("CKS_CLUSTER_NAME", DEFAULT_CLUSTER)
        if not state_is_owned(target_cluster) or not cluster_healthy(target_cluster):
            print(f"cluster {target_cluster!r} is not a healthy CKS-simulator cluster; run provision first", file=sys.stderr)
            return 1
        try:
            return run_command(cluster_kubectl(target_cluster, ["apply", "-f", str(resources)]), check=False).returncode
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    return 0


def check_scenario(identifier: str, root: Optional[str] = None) -> int:
    item = scenario_by_id(identifier)
    artifact_root = artifact_root_for_grade(item, root, all_scenarios=False)
    grade = grade_scenario(item, artifact_root)
    print(f"scenario {item['id']} [{item['kind_support']}] artifacts: {artifact_root}")
    for rule in grade["rules"]:
        print(f"{'PASS' if rule['passed'] else 'FAIL'}  {rule['path']} ({rule['earned']}/{rule['possible']} criteria)")
    print(f"artifact score: {grade['score']:.1f}/100 ({grade['status']})")
    print("scope: artifact evidence only; use 'e2e' for live kind validation")
    return 0 if grade["status"] == "complete" else 1


def artifact_root_for_grade(item: Dict[str, Any], root: Optional[str], *, all_scenarios: bool) -> Path:
    if not root:
        return scenario_root(item) / "artifacts"
    base = Path(root).expanduser().resolve()
    if not all_scenarios:
        return base
    candidate = base / item["id"] / "artifacts"
    return candidate if candidate.is_dir() else base / item["id"]


def grade_artifacts(identifier: str, root: Optional[str] = None, as_json: bool = False) -> int:
    all_scenarios = identifier.lower() == "all"
    items = load_catalog() if all_scenarios else [scenario_by_id(identifier)]
    grades = [
        grade_scenario(item, artifact_root_for_grade(item, root, all_scenarios=all_scenarios))
        for item in items
    ]
    payload: Dict[str, Any] = summarize_grades(grades) if all_scenarios else grades[0]
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif all_scenarios:
        for grade in grades:
            print(f"{grade['id']}  {grade['score']:5.1f}/100  {grade['status']:10}  [{grade['kind_support']}] {grade['title']}")
        print(f"overall artifact score: {payload['score']:.1f}/100; {payload['complete']}/{payload['scenario_count']} complete")
        print("scope: artifact evidence only; not an official CKS exam score")
    else:
        grade = grades[0]
        print(f"scenario {grade['id']} [{grade['kind_support']}] artifact score: {grade['score']:.1f}/100")
        for rule in grade["rules"]:
            for criterion in rule["criteria"]:
                print(f"{'PASS' if criterion['passed'] else 'FAIL'}  {criterion['label']}")
        print(f"status: {grade['status']}")
        print(f"scope: {grade['validation_scope']}")
    return 0 if payload["status"] == "complete" else 1


def _e2e_check(checks: List[Dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "passed": passed, "detail": detail})


def _validate_fixture(
    name: str, item: Dict[str, Any], *, announce: bool, tls_dir: Optional[Path] = None
) -> tuple[bool, str]:
    resources = ROOT / "scenarios" / "fixtures" / item["id"] / "resources.json"
    expected = json.loads(resources.read_text(encoding="utf-8"))
    expected_items = expected.get("items", [expected]) if isinstance(expected, dict) else []
    if item["id"] == "07":
        namespace_result = run_command(
            cluster_kubectl(name, ["create", "namespace", "team-sepia"]),
            check=False,
            announce=announce,
        )
        if namespace_result.returncode != 0:
            return False, namespace_result.stderr.strip() if namespace_result.stderr else "namespace creation failed"
        dry_run = command_output(
            cluster_kubectl(name, ["apply", "--dry-run=server", "-f", str(resources)]),
            announce=announce,
        )
        if dry_run.returncode != 0:
            return False, dry_run.stderr.strip() or "server-side dry-run failed"
        return True, f"server-side validated {len(expected_items)} objects without scheduling the privileged Pod"
    apply_result = run_command(
        cluster_kubectl(name, ["apply", "-f", str(resources)]),
        check=False,
        announce=announce,
    )
    if apply_result.returncode != 0:
        detail = apply_result.stderr.strip() if apply_result.stderr else f"kubectl apply exited {apply_result.returncode}"
        return False, detail

    get_result = command_output(
        cluster_kubectl(name, ["get", "-f", str(resources), "-o", "json"]),
        announce=announce,
    )
    if get_result.returncode != 0:
        return False, get_result.stderr.strip() or f"kubectl get exited {get_result.returncode}"
    try:
        actual = json.loads(get_result.stdout)
        actual_items = actual.get("items", [actual]) if isinstance(actual, dict) else []
    except ValueError as exc:
        return False, f"kubectl returned invalid JSON: {exc}"
    if len(actual_items) != len(expected_items):
        return False, f"expected {len(expected_items)} objects, found {len(actual_items)}"

    for resource in expected_items:
        kind = resource.get("kind")
        metadata = resource.get("metadata", {})
        resource_name = metadata.get("name")
        namespace = metadata.get("namespace")
        if kind not in {"Deployment", "Pod"} or not resource_name:
            continue
        condition = "Available" if kind == "Deployment" else "Ready"
        target = f"{kind.lower()}/{resource_name}"
        wait_args = ["wait", f"--for=condition={condition}", "--timeout=120s"]
        if namespace:
            wait_args += ["-n", namespace]
        wait_args.append(target)
        wait_result = command_output(cluster_kubectl(name, wait_args), announce=announce)
        if wait_result.returncode != 0:
            return False, wait_result.stderr.strip() or f"{target} did not reach {condition}"
    if item["id"] == "15":
        if not tls_dir:
            return False, "generated TLS fixture is missing"
        secret_result = command_output(
            cluster_kubectl(
                name,
                [
                    "create", "secret", "tls", "secure-tls", "-n", "team-pink",
                    f"--cert={tls_dir / 'tls.crt'}", f"--key={tls_dir / 'tls.key'}",
                ],
            ),
            announce=announce,
        )
        if secret_result.returncode != 0:
            return False, secret_result.stderr.strip() or "TLS Secret creation failed"
        patch_value = json.dumps({"spec": {"tls": [{"hosts": ["secure-ingress.test"], "secretName": "secure-tls"}]}})
        patch_result = command_output(
            cluster_kubectl(name, ["patch", "ingress", "secure", "-n", "team-pink", "--type=merge", "-p", patch_value]),
            announce=announce,
        )
        if patch_result.returncode != 0:
            return False, patch_result.stderr.strip() or "Ingress TLS patch failed"
        verify_result = command_output(
            cluster_kubectl(name, ["get", "ingress", "secure", "-n", "team-pink", "-o", "json"]),
            announce=announce,
        )
        try:
            secret_name = json.loads(verify_result.stdout)["spec"]["tls"][0]["secretName"]
        except (ValueError, KeyError, IndexError, TypeError):
            return False, "Ingress does not reference the generated TLS Secret"
        if verify_result.returncode != 0 or secret_name != "secure-tls":
            return False, "Ingress does not reference the generated TLS Secret"
        return True, f"applied {len(actual_items)} baseline objects and verified generated TLS Secret termination"
    return True, f"applied and observed {len(actual_items)} objects"


def _export_e2e_logs(name: str, *, announce: bool) -> Optional[Path]:
    destination = state_dir() / "e2e-logs" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = command_output(kind_command() + ["export", "logs", "--name", name, str(destination)], announce=announce)
    return destination if result.returncode == 0 and destination.is_dir() else None


def e2e(args: argparse.Namespace) -> int:
    """Run an isolated release gate against a disposable kind cluster."""
    name = args.name or f"cks-simulator-e2e-{os.getpid()}"
    announce = not args.as_json
    checks: List[Dict[str, Any]] = []
    started = time.monotonic()
    provisioned = False
    creation_attempted = False
    preexisting_run_state = False
    claim_token: Optional[str] = None
    logs_path: Optional[Path] = None
    tls_temporary: Optional[tempfile.TemporaryDirectory[str]] = None
    tls_fixture_dir: Optional[Path] = None
    catalog = load_catalog()
    catalog_by_id = {item["id"]: item for item in catalog}
    missing_live_fixtures = [
        identifier
        for identifier in sorted(LIVE_FIXTURE_IDS)
        if identifier not in catalog_by_id
        or not (ROOT / "scenarios" / "fixtures" / identifier / "resources.json").is_file()
    ]
    live_fixtures = [catalog_by_id[identifier] for identifier in sorted(LIVE_FIXTURE_IDS) if identifier in catalog_by_id]

    docker = docker_command()
    docker_result = command_output([docker, "info"], announce=announce) if docker else None
    _e2e_check(checks, "docker daemon", bool(docker_result and docker_result.returncode == 0), "available" if docker_result and docker_result.returncode == 0 else "unavailable")
    kubectl = kubectl_command()
    kubectl_result = command_output([kubectl, "version", "--client", "-o", "json"], announce=announce) if kubectl else None
    _e2e_check(checks, "kubectl client", bool(kubectl_result and kubectl_result.returncode == 0), "available" if kubectl_result and kubectl_result.returncode == 0 else "unavailable")
    kind_result = command_output(kind_command() + ["version"], announce=announce)
    _e2e_check(checks, "kind client", kind_result.returncode == 0, kind_result.stdout.strip() or kind_result.stderr.strip())
    _e2e_check(checks, "openssl client", openssl_command() is not None, openssl_command() or "unavailable")
    _e2e_check(
        checks,
        "live fixture declaration",
        not missing_live_fixtures,
        "04, 06, 07, 11, 15 present" if not missing_live_fixtures else f"missing: {', '.join(missing_live_fixtures)}",
    )
    try:
        tls_temporary = tempfile.TemporaryDirectory(prefix="cks-simulator-e2e-tls-")
        tls_fixture_dir = Path(tls_temporary.name)
        generate_tls_fixture(tls_fixture_dir)
        tls_ok = (tls_fixture_dir / "tls.crt").is_file() and (tls_fixture_dir / "tls.key").stat().st_mode & 0o777 == 0o600
        _e2e_check(checks, "scenario 15 TLS generation", tls_ok, "certificate and mode-0600 key generated" if tls_ok else "generated files invalid")
    except (OSError, RuntimeError) as exc:
        _e2e_check(checks, "scenario 15 TLS generation", False, str(exc))

    prerequisites_ok = all(check["passed"] for check in checks)
    try:
        if prerequisites_ok:
            presence = cluster_presence(name, announce=announce)
            preexisting_run_state = presence is True or metadata_path(name).exists()
            if presence is None:
                _e2e_check(checks, "cluster provision", False, "unable to query existing kind clusters")
            elif preexisting_run_state:
                _e2e_check(checks, "cluster provision", False, f"refusing pre-existing cluster or state for {name}")
            else:
                claim_token = acquire_e2e_claim(name)
                if not claim_token:
                    _e2e_check(checks, "cluster provision", False, f"another E2E run claimed {name}")
                else:
                    creation_attempted = True
                    provision_args = argparse.Namespace(name=name, image=args.image, wait=args.wait, quiet=args.as_json)
                    provision_code = provision(provision_args)
                    provisioned = provision_code == 0
                    _e2e_check(checks, "cluster provision", provisioned, f"cluster {name}" if provisioned else f"exit {provision_code}")

            idempotent_code = provision(provision_args) if provisioned else 1
            _e2e_check(checks, "idempotent provision", idempotent_code == 0, "second provision reused the healthy owned cluster" if idempotent_code == 0 else "second provision failed")

            nodes = node_statuses(name, announce=announce) if provisioned else []
            nodes_ok = nodes_healthy(nodes)
            _e2e_check(checks, "three Ready nodes", nodes_ok, ", ".join(f"{node['name']}={'Ready' if node['ready'] else 'NotReady'}" for node in nodes) or "no nodes")

            for item in live_fixtures:
                if provisioned and nodes_ok:
                    ok, detail = _validate_fixture(name, item, announce=announce, tls_dir=tls_fixture_dir)
                else:
                    ok, detail = False, "skipped because the cluster was not Ready"
                _e2e_check(checks, f"scenario {item['id']} fixture", ok, detail)
        else:
            _e2e_check(checks, "cluster provision", False, "skipped because prerequisites failed")
            _e2e_check(checks, "idempotent provision", False, "skipped because prerequisites failed")
            _e2e_check(checks, "three Ready nodes", False, "skipped because prerequisites failed")
            for item in live_fixtures:
                _e2e_check(checks, f"scenario {item['id']} fixture", False, "skipped because prerequisites failed")
    finally:
        failed_before_cleanup = any(not check["passed"] for check in checks)
        owns_claim = e2e_claim_is_owned(name, claim_token)
        if creation_attempted and owns_claim and failed_before_cleanup and cluster_presence(name, announce=False) is True and state_is_owned(name):
            logs_path = _export_e2e_logs(name, announce=announce)
        if preexisting_run_state:
            _e2e_check(checks, "cluster cleanup", True, "pre-existing cluster or state left untouched")
        elif args.keep and provisioned:
            _e2e_check(checks, "cluster cleanup", True, f"retained by request: {name}")
        elif creation_attempted and owns_claim:
            delete_code = delete(argparse.Namespace(name=name, force=False, quiet=args.as_json)) if state_is_owned(name) or cluster_exists(name, announce=False) else 0
            presence_after_delete = cluster_presence(name, announce=False)
            cleaned = delete_code == 0 and presence_after_delete is False
            _e2e_check(checks, "cluster cleanup", cleaned, "deleted" if cleaned else f"delete exited {delete_code}")
            if not cleaned and logs_path is None and presence_after_delete is True and state_is_owned(name):
                logs_path = _export_e2e_logs(name, announce=announce)
        else:
            _e2e_check(checks, "cluster cleanup", True, "nothing created")
        if e2e_claim_is_owned(name, claim_token) and not e2e_claim_path(name).is_symlink():
            e2e_claim_path(name).unlink()
        if tls_temporary:
            tls_temporary.cleanup()

    passed = sum(1 for check in checks if check["passed"])
    score = round((passed / len(checks)) * 100, 1) if checks else 0.0
    support_counts = {
        support: sum(1 for item in catalog if item["kind_support"] == support)
        for support in ("native", "partial", "unsupported")
    }
    payload = {
        "name": name,
        "image": args.image,
        "score": score,
        "status": "pass" if passed == len(checks) else "fail",
        "passed": passed,
        "possible": len(checks),
        "duration_seconds": round(time.monotonic() - started, 1),
        "checks": checks,
        "coverage": {
            "catalog_scenarios": len(catalog),
            "support": support_counts,
            "live_fixture_scenarios": [item["id"] for item in live_fixtures],
            "artifact_grading_scenarios": len(catalog),
        },
        "diagnostic_logs": str(logs_path) if logs_path else None,
    }
    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for check in checks:
            print(f"{'PASS' if check['passed'] else 'FAIL'}  {check['name']}: {check['detail']}")
        print(f"e2e score: {score:.1f}/100 ({payload['status']}); {passed}/{len(checks)} gates passed")
        print(f"live fixtures: {', '.join(payload['coverage']['live_fixture_scenarios'])}")
        if logs_path:
            print(f"diagnostic logs: {logs_path}")
    return 0 if payload["status"] == "pass" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cks-simulator", description="Local CKS practice environment")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--json", action="store_true", dest="as_json")

    for name in ("provision", "reset"):
        command = sub.add_parser(name)
        command.add_argument("--name", default=None)
        command.add_argument("--image", default=DEFAULT_IMAGE)
        command.add_argument("--wait", default="5m")
        if name == "reset":
            command.add_argument("--force", action="store_true", help="allow deleting an unowned same-named kind cluster")

    delete_parser = sub.add_parser("delete")
    delete_parser.add_argument("--name", default=None)
    delete_parser.add_argument("--force", action="store_true", help="allow deleting an unowned same-named kind cluster")

    list_parser = sub.add_parser("list")
    list_parser.add_argument("--json", action="store_true", dest="as_json")

    shell_parser = sub.add_parser("shell")
    shell_parser.add_argument("--name", default=None)
    shell_parser.add_argument("--node", default=None)
    shell_parser.add_argument("--shell", default=None)

    check_parser = sub.add_parser("check")
    check_parser.add_argument("id")
    check_parser.add_argument("--root", default=None)

    grade_parser = sub.add_parser("grade", help="score one scenario or the complete artifact set")
    grade_parser.add_argument("id", help="scenario ID or 'all'")
    grade_parser.add_argument("--root", default=None)
    grade_parser.add_argument("--json", action="store_true", dest="as_json")

    e2e_parser = sub.add_parser("e2e", help="run the disposable live kind release gate")
    e2e_parser.add_argument("--name", default=None, help="unique disposable kind cluster name")
    e2e_parser.add_argument("--image", default=DEFAULT_IMAGE)
    e2e_parser.add_argument("--wait", default="5m")
    e2e_parser.add_argument("--keep", action="store_true", help="retain a successfully provisioned E2E cluster")
    e2e_parser.add_argument("--json", action="store_true", dest="as_json")

    scenario_parser = sub.add_parser("scenario")
    scenario_sub = scenario_parser.add_subparsers(dest="scenario_command", required=True)
    for name in ("create", "reset"):
        command = scenario_sub.add_parser(name)
        command.add_argument("id")
        command.add_argument("--apply", action="store_true")
        command.add_argument("--name", default=None, help="kind cluster name used with --apply")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return doctor(args.as_json)
        if args.command == "provision":
            return provision(args)
        if args.command == "delete":
            return delete(args)
        if args.command == "reset":
            return reset_cluster(args)
        if args.command == "list":
            return print_catalog(args.as_json)
        if args.command == "shell":
            return open_shell(args)
        if args.command == "check":
            return check_scenario(args.id, args.root)
        if args.command == "grade":
            return grade_artifacts(args.id, args.root, args.as_json)
        if args.command == "e2e":
            return e2e(args)
        if args.command == "scenario":
            if args.scenario_command == "create":
                return create_scenario(args.id, args.apply, args.name, reset=False)
            if args.scenario_command == "reset":
                return create_scenario(args.id, args.apply, args.name, reset=True)
    except (OSError, ValueError, RuntimeError) as exc:
        if getattr(args, "as_json", False):
            print(json.dumps({"status": "error", "error": {"type": type(exc).__name__, "message": str(exc)}}))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
