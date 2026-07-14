#!/usr/bin/env python3
"""Disposable Lima capability-spike orchestration.

This module deliberately owns only instances recorded in its write-ahead claim.
It never discovers instances by prefix and never adopts an existing instance.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Sequence


ROOT = Path(__file__).resolve().parents[2]
VERSIONS_PATH = ROOT / "infra" / "versions.json"
TEMPLATES_DIR = ROOT / "infra" / "spike" / "lima"
GUEST_DIR = ROOT / "infra" / "spike" / "guest"
DEFAULT_STATE_ROOT = ROOT / ".cks-state" / "full-spike"
MANAGED_BY = "cks-simulator-full-spike"
LAB_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")
INSTANCE_ROLES = ("candidate", "control-plane", "worker1", "worker2")
MAX_CAPTURE_BYTES = 64 * 1024
TOKEN_PATTERN = re.compile(r"\b[a-z0-9]{6}\.[a-z0-9]{16}\b", re.IGNORECASE)
BEARER_PATTERN = re.compile(r"(?i)(bearer|token|password)([=: ]+)([^\s,;]+)")
ANSI_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class CommandResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[..., CommandResult]


def redact(value: str) -> str:
    value = ANSI_PATTERN.sub("", value)
    value = CONTROL_PATTERN.sub("?", value)
    value = TOKEN_PATTERN.sub("<redacted-kubeadm-token>", value)
    return BEARER_PATTERN.sub(r"\1\2<redacted>", value)


def _bounded(value: str, limit: int = MAX_CAPTURE_BYTES) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return redact(value)
    return redact(encoded[:limit].decode("utf-8", errors="replace") + "\n<truncated>\n")


def run_command(
    argv: Sequence[str],
    *,
    timeout: int = 900,
    check: bool = False,
    input_text: Optional[str] = None,
) -> CommandResult:
    if not argv or any(not isinstance(part, str) or "\x00" in part for part in argv):
        raise ValueError("command argv must contain non-empty strings without NUL bytes")
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            text=True,
            input=input_text,
            capture_output=True,
            timeout=timeout,
        )
        result = CommandResult(
            completed.returncode,
            _bounded(completed.stdout),
            _bounded(completed.stderr),
        )
    except subprocess.TimeoutExpired as exc:
        result = CommandResult(
            124,
            _bounded(exc.stdout or ""),
            _bounded((exc.stderr or "") + f"\ncommand timed out after {timeout}s"),
        )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {argv[0]}\n{result.stderr.strip()}"
        )
    return result


def validate_lab_id(lab_id: str) -> str:
    if not LAB_ID_PATTERN.fullmatch(lab_id):
        raise ValueError("lab id must be 1-48 lowercase letters, digits, or internal hyphens")
    return lab_id


def generated_lab_id() -> str:
    return f"cks-spike-{uuid.uuid4().hex[:12]}"


def instance_names(lab_id: str) -> List[str]:
    validate_lab_id(lab_id)
    return [f"{lab_id}-{role}" for role in INSTANCE_ROLES]


def state_root() -> Path:
    override = os.environ.get("CKS_FULL_SPIKE_STATE_DIR")
    return Path(override).expanduser().resolve() if override else DEFAULT_STATE_ROOT


def claim_path(lab_id: str) -> Path:
    return state_root() / lab_id / "claim.json"


def receipt_path(lab_id: str) -> Path:
    return state_root() / lab_id / "receipt.json"


def new_claim(lab_id: str, instances: Sequence[str]) -> Dict[str, Any]:
    validate_lab_id(lab_id)
    supplied = list(instances)
    if supplied != instance_names(lab_id):
        raise ValueError("claim instances must exactly match the declared role handles")
    return {
        "schema": 1,
        "managed_by": MANAGED_BY,
        "lab_id": lab_id,
        "claim_uuid": str(uuid.uuid4()),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "declared",
        "instances": supplied,
        "created_instances": [],
    }


def write_claim_exclusive(path: Path, claim: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(claim, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_claim(path: Path, claim: Dict[str, Any]) -> None:
    if path.is_symlink():
        raise RuntimeError("refusing symlink claim path")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".claim-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(claim, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_owned_claim(path: Path, lab_id: str) -> Dict[str, Any]:
    validate_lab_id(lab_id)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("owned claim is missing or unsafe")
    try:
        claim = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("owned claim is unreadable") from exc
    if (
        claim.get("schema") != 1
        or claim.get("managed_by") != MANAGED_BY
        or claim.get("lab_id") != lab_id
        or not isinstance(claim.get("claim_uuid"), str)
        or not isinstance(claim.get("instances"), list)
        or not isinstance(claim.get("created_instances"), list)
    ):
        raise RuntimeError("claim identity does not match this simulator")
    if claim["instances"] != instance_names(lab_id):
        raise RuntimeError("claim provider handles do not match the declared lab")
    if any(name not in claim["instances"] for name in claim["created_instances"]):
        raise RuntimeError("claim contains an unowned created handle")
    return claim


def load_versions() -> Dict[str, Any]:
    try:
        versions = json.loads(VERSIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("infra/versions.json is missing or invalid") from exc
    expected = {
        "lima": "2.1.4",
        "kubernetes": "1.35.6",
        "cilium": "1.19.5",
    }
    for key, version in expected.items():
        if versions.get(key, {}).get("version") != version:
            raise RuntimeError(f"unexpected {key} pin")
    ubuntu = versions.get("ubuntu", {})
    if ubuntu.get("arch") != "aarch64" or ubuntu.get("release") != "release-20260615":
        raise RuntimeError("unexpected Ubuntu image identity")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(ubuntu.get("image_digest", ""))):
        raise RuntimeError("Ubuntu image has no immutable sha256 digest")
    return versions


def _sysctl_number(name: str) -> int:
    result = run_command(["sysctl", "-n", name], timeout=10, check=True)
    return int(result.stdout.strip())


def _lima_instances(*, runner: Runner = run_command) -> Dict[str, str]:
    result = runner(["limactl", "list", "--json"], timeout=30)
    if result.returncode != 0 and "No instance found" not in result.stderr:
        raise RuntimeError(f"unable to discover Lima instances: {result.stderr.strip()}")
    instances: Dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise RuntimeError("Lima returned invalid instance inventory") from exc
        name = item.get("name") or item.get("Name")
        status = item.get("status") or item.get("Status") or "Unknown"
        if isinstance(name, str):
            instances[name] = str(status)
    return instances


def preflight(lab_id: str, *, runner: Runner = run_command) -> List[Dict[str, Any]]:
    versions = load_versions()
    checks: List[Dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": _bounded(detail, 4096)})

    binary = shutil.which("limactl")
    add("limactl available", binary is not None, binary or "not found")
    if binary:
        version = runner([binary, "--version"], timeout=10)
        add("limactl version", version.returncode == 0 and versions["lima"]["version"] in version.stdout, version.stdout or version.stderr)
        drivers = runner([binary, "start", "--list-drivers"], timeout=30)
        add("Lima VZ driver", drivers.returncode == 0 and "vz" in drivers.stdout.split(), drivers.stdout or drivers.stderr)
    machine = platform.machine().lower()
    add("ARM64 host", machine in {"arm64", "aarch64"}, machine)
    try:
        cpus = _sysctl_number("hw.logicalcpu")
        memory = _sysctl_number("hw.memsize")
        free = shutil.disk_usage(ROOT).free
        add("host CPU", cpus >= 16, f"{cpus} logical CPUs; 16 required")
        add("host memory", memory >= 40 * 1024**3, f"{memory / 1024**3:.1f} GiB; 40 required")
        add("host disk", free >= 200 * 1024**3, f"{free / 1024**3:.1f} GiB free; 200 required")
    except (OSError, RuntimeError, ValueError) as exc:
        add("host capacity", False, str(exc))
    for template in sorted(TEMPLATES_DIR.glob("*.yaml")):
        result = runner(["limactl", "validate", str(template)], timeout=30)
        add(f"template {template.stem}", result.returncode == 0, result.stderr or "valid")
    try:
        existing = _lima_instances(runner=runner)
        collisions = [name for name in instance_names(lab_id) if name in existing]
        add("instance collision", not collisions, "none" if not collisions else ", ".join(collisions))
    except RuntimeError as exc:
        add("instance discovery", False, str(exc))
    return checks


def require_checks(checks: Iterable[Dict[str, Any]]) -> None:
    failed = [check for check in checks if not check["passed"]]
    if failed:
        raise RuntimeError("preflight failed: " + "; ".join(f"{item['name']}: {item['detail']}" for item in failed))


def shell(instance: str, argv: Sequence[str], *, runner: Runner = run_command, timeout: int = 1800) -> CommandResult:
    return runner(["limactl", "shell", instance, "--", *argv], timeout=timeout, check=True)


def provision_vms(lab_id: str, *, runner: Runner = run_command) -> Dict[str, Any]:
    names = instance_names(lab_id)
    path = claim_path(lab_id)
    claim = new_claim(lab_id, names)
    write_claim_exclusive(path, claim)
    try:
        checks = preflight(lab_id, runner=runner)
        require_checks(checks)
        for role, name in zip(INSTANCE_ROLES, names):
            template = TEMPLATES_DIR / f"{role}.yaml"
            runner(
                ["limactl", "start", "--yes", "--name", name, str(template)],
                timeout=1800,
                check=True,
            )
            claim["created_instances"].append(name)
            claim["status"] = "vms-created"
            write_claim(path, claim)
        claim["status"] = "vms-ready"
        claim["preflight"] = checks
        write_claim(path, claim)
        return claim
    except BaseException:
        claim["status"] = "degraded"
        write_claim(path, claim)
        raise


def stage_guest_assets(claim: Dict[str, Any], *, runner: Runner = run_command) -> None:
    if not GUEST_DIR.is_dir():
        raise RuntimeError("guest provisioning assets are missing")
    for name in claim["instances"]:
        shell(name, ["mkdir", "-p", "/tmp/cks-spike-guest"], runner=runner, timeout=30)
        for source in sorted(GUEST_DIR.glob("*")):
            if source.is_file() and not source.is_symlink():
                runner(
                    ["limactl", "copy", str(source), f"{name}:/tmp/cks-spike-guest/{source.name}"],
                    timeout=300,
                    check=True,
                )
        runner(["limactl", "copy", str(VERSIONS_PATH), f"{name}:/tmp/cks-spike-versions.json"], timeout=300, check=True)


def guest_ip(instance: str, *, runner: Runner = run_command) -> str:
    result = shell(instance, ["hostname", "-I"], runner=runner, timeout=30)
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result.stdout)
    for candidate in candidates:
        octets = [int(part) for part in candidate.split(".")]
        if all(0 <= part <= 255 for part in octets) and not candidate.startswith("127."):
            return candidate
    raise RuntimeError(f"no routable IPv4 address reported by {instance}")


def guest_account(instance: str, *, runner: Runner = run_command) -> Dict[str, str]:
    uid = shell(instance, ["id", "-u"], runner=runner, timeout=30).stdout.strip()
    gid = shell(instance, ["id", "-g"], runner=runner, timeout=30).stdout.strip()
    if not uid.isdigit() or not gid.isdigit():
        raise RuntimeError(f"unable to resolve the operator identity on {instance}")
    passwd = shell(instance, ["getent", "passwd", uid], runner=runner, timeout=30)
    fields = passwd.stdout.strip().split(":")
    if len(fields) < 6 or not re.fullmatch(r"/[A-Za-z0-9_./-]+", fields[5]):
        raise RuntimeError(f"unable to resolve the operator home on {instance}")
    return {"uid": uid, "gid": gid, "home": fields[5]}


def run_guest_script(
    instance: str,
    script: str,
    env: Dict[str, str],
    *,
    runner: Runner = run_command,
    timeout: int = 1800,
) -> CommandResult:
    if not re.fullmatch(r"[0-9a-z][0-9a-z.-]*\.sh", script):
        raise ValueError("unsafe guest script name")
    environment = {"CKS_VERSION_MANIFEST": "/tmp/cks-spike-guest/versions.env", **env}
    env_argv: List[str] = []
    for key in sorted(environment):
        value = environment[key]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\x00" in value or "\n" in value:
            raise ValueError("unsafe guest environment value")
        env_argv.append(f"{key}={value}")
    return shell(
        instance,
        ["sudo", "env", *env_argv, "bash", f"/tmp/cks-spike-guest/{script}"],
        runner=runner,
        timeout=timeout,
    )


def bootstrap_base_stack(lab_id: str, *, runner: Runner = run_command) -> Dict[str, Any]:
    path = claim_path(lab_id)
    claim = load_owned_claim(path, lab_id)
    if claim.get("status") not in {"vms-ready", "assets-staged", "bootstrap-degraded"}:
        raise RuntimeError(f"lab is not ready for bootstrap: {claim.get('status')}")
    roles = dict(zip(INSTANCE_ROLES, claim["instances"]))
    stage_guest_assets(claim, runner=runner)
    addresses = {role: guest_ip(name, runner=runner) for role, name in roles.items()}
    accounts = {role: guest_account(name, runner=runner) for role, name in roles.items()}
    claim["addresses"] = addresses
    claim["operator_accounts"] = accounts
    claim["status"] = "assets-staged"
    write_claim(path, claim)
    common_env = {
        role: {"NODE_IP": addresses[role], "NODE_NAME": roles[role]}
        for role in ("control-plane", "worker1", "worker2")
    }
    try:
        for role in ("control-plane", "worker1", "worker2"):
            run_guest_script(roles[role], "10-common.sh", common_env[role], runner=runner, timeout=2400)
        endpoint = f"{addresses['control-plane']}:6443"
        run_guest_script(
            roles["control-plane"],
            "30-control-plane.sh",
            {
                **common_env["control-plane"],
                "CONTROL_PLANE_ENDPOINT": endpoint,
                "POD_CIDR": "10.244.0.0/16",
                "SERVICE_CIDR": "10.96.0.0/12",
            },
            runner=runner,
            timeout=2400,
        )
        secret_dir = path.parent / "bootstrap"
        secret_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(secret_dir, 0o700)
        join_manifest = secret_dir / "join.env"
        shell(
            roles["control-plane"],
            ["sudo", "install", "-m", "0600", "-o", accounts["control-plane"]["uid"], "-g", accounts["control-plane"]["gid"], "/var/lib/cks-simulator/join.env", "/tmp/cks-join-export"],
            runner=runner,
            timeout=30,
        )
        runner(
            ["limactl", "copy", f"{roles['control-plane']}:/tmp/cks-join-export", str(join_manifest)],
            timeout=60,
            check=True,
        )
        shell(roles["control-plane"], ["rm", "-f", "/tmp/cks-join-export"], runner=runner, timeout=30)
        os.chmod(join_manifest, 0o600)
        for role in ("worker1", "worker2"):
            runner(["limactl", "copy", str(join_manifest), f"{roles[role]}:/tmp/cks-join.env"], timeout=60, check=True)
            run_guest_script(
                roles[role],
                "40-worker.sh",
                {**common_env[role], "CKS_JOIN_MANIFEST": "/tmp/cks-join.env"},
                runner=runner,
                timeout=1800,
            )
            shell(roles[role], ["rm", "-f", "/tmp/cks-join.env"], runner=runner, timeout=30)
        join_manifest.unlink(missing_ok=True)

        run_guest_script(roles["candidate"], "20-candidate-tools.sh", {}, runner=runner, timeout=2400)
        kubeconfig = secret_dir / "candidate-kubeconfig"
        shell(
            roles["control-plane"],
            ["sudo", "install", "-m", "0600", "-o", accounts["control-plane"]["uid"], "-g", accounts["control-plane"]["gid"], "/etc/kubernetes/admin.conf", "/tmp/cks-admin-export"],
            runner=runner,
            timeout=30,
        )
        runner(
            ["limactl", "copy", f"{roles['control-plane']}:/tmp/cks-admin-export", str(kubeconfig)],
            timeout=60,
            check=True,
        )
        shell(roles["control-plane"], ["rm", "-f", "/tmp/cks-admin-export"], runner=runner, timeout=30)
        os.chmod(kubeconfig, 0o600)
        runner(["limactl", "copy", str(kubeconfig), f"{roles['candidate']}:/tmp/cks-kubeconfig"], timeout=60, check=True)
        candidate_home = accounts["candidate"]["home"]
        shell(
            roles["candidate"],
            ["sudo", "install", "-D", "-m", "0600", "-o", accounts["candidate"]["uid"], "-g", accounts["candidate"]["gid"], "/tmp/cks-kubeconfig", f"{candidate_home}/.kube/config"],
            runner=runner,
            timeout=30,
        )
        shell(roles["candidate"], ["rm", "-f", "/tmp/cks-kubeconfig"], runner=runner, timeout=30)
        kubeconfig.unlink(missing_ok=True)
        claim["status"] = "base-ready"
        write_claim(path, claim)
        return claim
    except BaseException:
        claim["status"] = "bootstrap-degraded"
        write_claim(path, claim)
        raise


def validate_base_stack(lab_id: str, *, runner: Runner = run_command) -> Dict[str, Any]:
    path = claim_path(lab_id)
    claim = load_owned_claim(path, lab_id)
    roles = dict(zip(INSTANCE_ROLES, claim["instances"]))
    checks: List[Dict[str, Any]] = []

    def execute(name: str, instance: str, argv: Sequence[str], contains: Optional[str] = None) -> None:
        try:
            result = shell(instance, argv, runner=runner, timeout=900)
            passed = result.returncode == 0 and (contains is None or contains in result.stdout)
            detail = result.stdout.strip() or result.stderr.strip() or "passed"
        except RuntimeError as exc:
            passed = False
            detail = str(exc)
        checks.append({"name": name, "passed": passed, "detail": _bounded(detail, 4096)})

    execute(
        "three Ready nodes",
        roles["control-plane"],
        ["sudo", "env", "KUBECONFIG=/etc/kubernetes/admin.conf", "kubectl", "get", "nodes", "--no-headers"],
    )
    if checks[-1]["passed"]:
        lines = [line for line in checks[-1]["detail"].splitlines() if line.strip()]
        checks[-1]["passed"] = len(lines) == 3 and all(" Ready " in f" {line} " for line in lines)
    execute(
        "Cilium healthy",
        roles["control-plane"],
        ["sudo", "env", "KUBECONFIG=/etc/kubernetes/admin.conf", "cilium", "status", "--wait", "--wait-duration", "5m"],
    )
    execute(
        "candidate Kubernetes access",
        roles["candidate"],
        ["kubectl", "get", "nodes", "--no-headers"],
    )
    if checks[-1]["passed"]:
        checks[-1]["passed"] = len([line for line in checks[-1]["detail"].splitlines() if line.strip()]) == 3
    receipt = {
        "schema": 1,
        "lab_id": lab_id,
        "validated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": "base Lima, kubeadm and Cilium capability spike",
        "checks": checks,
        "passed": all(check["passed"] for check in checks),
    }
    receipt_path(lab_id).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(receipt_path(lab_id), 0o600)
    claim["status"] = "base-validated" if receipt["passed"] else "validation-degraded"
    write_claim(path, claim)
    return receipt


def destroy_instances(claim: Dict[str, Any], *, runner: Runner = run_command) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    instances = claim.get("created_instances")
    if not isinstance(instances, list):
        raise RuntimeError("claim has no exact created provider handles")
    for name in reversed(instances):
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
            raise RuntimeError("claim contains an unsafe provider handle")
        stopped = runner(["limactl", "stop", "--force", name], timeout=180)
        deleted = runner(["limactl", "delete", "--force", name], timeout=180)
        results.append(
            {
                "instance": name,
                "stop_returncode": stopped.returncode,
                "delete_returncode": deleted.returncode,
            }
        )
    return results


def destroy_lab(lab_id: str, *, runner: Runner = run_command) -> List[Dict[str, Any]]:
    path = claim_path(lab_id)
    claim = load_owned_claim(path, lab_id)
    results = destroy_instances(claim, runner=runner)
    remaining = _lima_instances(runner=runner)
    still_present = [name for name in claim["created_instances"] if name in remaining]
    if still_present:
        claim["status"] = "cleanup-pending"
        claim["cleanup"] = results
        write_claim(path, claim)
        raise RuntimeError("owned instances remain after cleanup: " + ", ".join(still_present))
    claim["status"] = "destroyed"
    claim["cleanup"] = results
    write_claim(path, claim)
    return results


def render(payload: Any, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if isinstance(payload, list):
        for item in payload:
            marker = "PASS" if item.get("passed") else "FAIL"
            print(f"{marker:4} {item.get('name', item.get('instance'))}: {item.get('detail', '')}")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Run the disposable CKS full-tier capability spike")
    result.add_argument("--json", action="store_true", dest="as_json")
    subparsers = result.add_subparsers(dest="command", required=True)
    for command in ("preflight", "provision", "stage", "bootstrap", "validate", "destroy"):
        child = subparsers.add_parser(command)
        child.add_argument("--lab-id")
    all_parser = subparsers.add_parser("all")
    all_parser.add_argument("--lab-id")
    all_parser.add_argument("--keep", action="store_true")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    lab_id = validate_lab_id(args.lab_id) if args.lab_id else generated_lab_id()
    try:
        if args.command == "preflight":
            checks = preflight(lab_id)
            render({"lab_id": lab_id, "checks": checks} if args.as_json else checks, as_json=args.as_json)
            return 0 if all(check["passed"] for check in checks) else 1
        if args.command == "provision":
            render(provision_vms(lab_id), as_json=args.as_json)
            return 0
        if args.command == "stage":
            claim = load_owned_claim(claim_path(lab_id), lab_id)
            stage_guest_assets(claim)
            render({"lab_id": lab_id, "status": "assets-staged"}, as_json=args.as_json)
            return 0
        if args.command == "bootstrap":
            render(bootstrap_base_stack(lab_id), as_json=args.as_json)
            return 0
        if args.command == "validate":
            receipt = validate_base_stack(lab_id)
            render(receipt, as_json=args.as_json)
            return 0 if receipt["passed"] else 1
        if args.command == "destroy":
            render(destroy_lab(lab_id), as_json=args.as_json)
            return 0
        if args.command == "all":
            try:
                provision_vms(lab_id)
                bootstrap_base_stack(lab_id)
                receipt = validate_base_stack(lab_id)
                render(receipt, as_json=args.as_json)
                return 0 if receipt["passed"] else 1
            finally:
                if not args.keep and claim_path(lab_id).is_file():
                    destroy_lab(lab_id)
    except (OSError, RuntimeError, ValueError) as exc:
        error = {"status": "error", "lab_id": lab_id, "error": _bounded(str(exc), 8192)}
        if args.as_json:
            print(json.dumps(error, indent=2, sort_keys=True))
        else:
            print(f"error: {error['error']}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
