"""Command line implementation for the local CKS simulator."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "scenarios" / "catalog.json"
DEFAULT_CLUSTER = "cks-simulator"
DEFAULT_IMAGE = "kindest/node:v1.35.1"


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


def state_is_owned(name: str) -> bool:
    metadata = metadata_path(name)
    if not metadata.is_file():
        return False
    try:
        value = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return value.get("managed_by") == "cks-simulator" and value.get("cluster_name") == name


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


def run_command(command: List[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("$ " + " ".join(command))
    return subprocess.run(command, check=check, text=True)


def command_output(command: List[str], *, announce: bool = True) -> subprocess.CompletedProcess[str]:
    if announce:
        print("$ " + " ".join(command))
    return subprocess.run(command, check=False, text=True, capture_output=True)


def cluster_exists(name: str) -> bool:
    result = command_output(kind_command() + ["get", "clusters"])
    return result.returncode == 0 and name in result.stdout.splitlines()


def cluster_healthy(name: str) -> bool:
    kube = kubeconfig_path(name)
    binary = kubectl_command()
    if not kube.is_file() or not binary:
        return False
    result = command_output([binary, "--kubeconfig", str(kube), "--context", f"kind-{name}", "get", "nodes", "--no-headers"])
    return result.returncode == 0 and bool(result.stdout.strip())


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
    state_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir(), 0o700)
    config = ROOT / "kind" / "cluster.yaml"
    kube = kubeconfig_path(name)
    if cluster_exists(name):
        if not state_is_owned(name):
            print(f"refusing to manage unowned cluster {name!r}; choose another --name or delete it explicitly", file=sys.stderr)
            return 1
        if cluster_healthy(name):
            print(f"cluster already ready: {name}")
            print(f"kubeconfig: {kube}")
            return 0
        print(f"cluster {name!r} exists but is not healthy with project state; use 'reset' to recreate it", file=sys.stderr)
        return 1
    command = kind_command() + [
        "create", "cluster", "--name", name, "--config", str(config),
        "--image", args.image, "--kubeconfig", str(kube), "--wait", args.wait,
    ]
    try:
        run_command(command)
    except FileNotFoundError as exc:
        print(f"unable to run kind: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        if kube.exists() and not kube.is_symlink():
            kube.unlink()
        print(f"kind failed while provisioning {name!r} (exit {exc.returncode}); partial kubeconfig removed", file=sys.stderr)
        return exc.returncode or 1
    os.chmod(kube, 0o600)
    metadata_path(name).write_text(
        json.dumps({"cluster_name": name, "image": args.image, "managed_by": "cks-simulator"}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(metadata_path(name), 0o600)
    print(f"cluster ready: {name}")
    print(f"kubeconfig: {kube}")
    return 0


def delete(args: argparse.Namespace) -> int:
    name = cluster_name(args)
    kube = kubeconfig_path(name)
    if cluster_exists(name) and not state_is_owned(name) and not args.force:
        print(f"refusing to delete unowned cluster {name!r}; pass --force only if you explicitly intend to remove it", file=sys.stderr)
        return 1
    command = kind_command() + ["delete", "cluster", "--name", name]
    if kube.exists():
        command += ["--kubeconfig", str(kube)]
    try:
        result = run_command(command, check=False)
    except FileNotFoundError as exc:
        print(f"unable to run kind: {exc}", file=sys.stderr)
        return 1
    if result.returncode == 0:
        if kube.exists() and not kube.is_symlink():
            kube.unlink()
        if metadata_path(name).exists() and not metadata_path(name).is_symlink():
            metadata_path(name).unlink()
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
    if destination.exists():
        if not reset:
            print(f"scenario {item['id']} already exists; use 'scenario reset {item['id']}' to replace it", file=sys.stderr)
            return 1
        shutil.rmtree(destination)
    (destination / "artifacts").mkdir(parents=True)
    fixture_source = ROOT / "scenarios" / "fixtures" / item["id"]
    fixture_destination = destination / "fixture"
    if fixture_source.exists():
        shutil.copytree(fixture_source, fixture_destination)
    else:
        fixture_destination.mkdir()
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


def json_pointer(value: Any, pointer: str) -> Any:
    current = value
    for part in pointer.lstrip("/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    return current


def check_rule(artifact_root: Path, rule: Dict[str, Any]) -> tuple[bool, str]:
    path = artifact_root / rule["path"]
    if rule["kind"] == "file_exists":
        return path.is_file(), f"{rule['path']} exists"
    if not path.is_file():
        return False, f"{rule['path']} is missing"
    text = path.read_text(encoding="utf-8")
    if rule["kind"] == "text_contains":
        missing = [value for value in rule["values"] if value not in text]
        return not missing, f"{rule['path']} contains {len(rule['values']) - len(missing)}/{len(rule['values'])} required markers"
    if rule["kind"] == "text_not_contains":
        present = [value for value in rule["values"] if value in text]
        return not present, f"{rule['path']} has no forbidden markers" if not present else f"forbidden markers: {present}"
    if rule["kind"] == "text_exact_lines":
        actual = [line for line in text.splitlines() if line.strip()]
        expected = rule["values"]
        return actual == expected, f"{rule['path']} has expected ordered lines"
    if rule["kind"] == "json_pointer":
        try:
            actual = json_pointer(json.loads(text), rule["pointer"])
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            return False, f"{rule['path']} JSON lookup failed: {exc}"
        return actual == rule["expected"], f"{rule['path']}{rule['pointer']} == {rule['expected']!r}"
    return False, f"unknown check kind {rule['kind']}"


def check_scenario(identifier: str, root: Optional[str] = None) -> int:
    item = scenario_by_id(identifier)
    artifact_root = Path(root).expanduser().resolve() if root else scenario_root(item) / "artifacts"
    print(f"scenario {item['id']} [{item['kind_support']}] artifacts: {artifact_root}")
    failures = 0
    for rule in item["checks"]:
        ok, detail = check_rule(artifact_root, rule)
        print(f"{'PASS' if ok else 'FAIL'}  {detail}")
        failures += not ok
    return 1 if failures else 0


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
        if args.command == "scenario":
            if args.scenario_command == "create":
                return create_scenario(args.id, args.apply, args.name, reset=False)
            if args.scenario_command == "reset":
                return create_scenario(args.id, args.apply, args.name, reset=True)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
