#!/usr/bin/env python3
"""Disposable Lima capability-spike orchestration.

This module deliberately owns only instances recorded in its write-ahead claim.
It never discovers instances by prefix and never adopts an existing instance.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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


HOST_PATH = Path(__file__).resolve()
ROOT = HOST_PATH.parents[2]
VERSIONS_PATH = ROOT / "infra" / "versions.json"
TEMPLATES_DIR = ROOT / "infra" / "spike" / "lima"
GUEST_DIR = ROOT / "infra" / "spike" / "guest"
DEFAULT_STATE_ROOT = ROOT / ".cks-state" / "full-spike"
MANAGED_BY = "cks-simulator-full-spike"
LAB_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")
INSTANCE_ROLES = ("candidate", "control-plane", "worker1", "worker2")
MAX_CAPTURE_BYTES = 64 * 1024
TOKEN_PATTERN = re.compile(r"\b[a-z0-9]{6}\.[a-z0-9]{16}\b", re.IGNORECASE)
SENSITIVE_FIELD_PATTERN = re.compile(
    r"(?i)(bearer|token|password|secret|certificate[-_ ]?key)([=: ]+)([^\s,;]+)"
)
KUBECONFIG_DATA_PATTERN = re.compile(r"(?im)^(\s*[a-z0-9_.-]+-data\s*:\s*)(\S+).*$")
BASIC_AUTH_PATTERN = re.compile(r"(?i)(authorization\s*:\s*basic\s+)([^\s,;]+)")
PEM_PATTERN = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----",
    re.DOTALL,
)
ANSI_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PROBE_RESULT_PATTERN = re.compile(r"PROBE_RESULT ([a-z0-9][a-z0-9-]*) (PASS|FAIL)\Z")
EXPECTED_PROBE_IDS = {
    "baseline": (
        "kubernetes-version",
        "nodes-ready",
        "cilium-version",
        "cilium-connectivity-before-docker",
        "cilium-network-policy",
        "apparmor-denial",
        "gvisor-systrap",
        "falco-modern-ebpf-event",
        "trivy-config",
        "kube-bench-training-only",
        "ingress-tls",
    ),
    "post-docker": (
        "nodes-ready-after-docker",
        "cilium-connectivity-after-docker",
    ),
}


class CommandResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[..., CommandResult]


def redact(value: str) -> str:
    value = ANSI_PATTERN.sub("", value)
    value = CONTROL_PATTERN.sub("?", value)
    value = PEM_PATTERN.sub(
        lambda match: f"-----BEGIN {match.group(1)}-----\n<redacted>\n-----END {match.group(1)}-----",
        value,
    )
    value = KUBECONFIG_DATA_PATTERN.sub(r"\1<redacted>", value)
    value = BASIC_AUTH_PATTERN.sub(r"\1<redacted>", value)
    value = TOKEN_PATTERN.sub("<redacted-kubeadm-token>", value)
    return SENSITIVE_FIELD_PATTERN.sub(r"\1\2<redacted>", value)


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None:
        return ""
    return str(value)


def _bounded(value: Any, limit: int = MAX_CAPTURE_BYTES) -> str:
    if limit < 0:
        raise ValueError("capture limit must be non-negative")
    sanitized = redact(_as_text(value))
    encoded = sanitized.encode("utf-8")
    if len(encoded) <= limit:
        return sanitized
    marker = b"\n<truncated>\n"
    if limit <= len(marker):
        return marker[:limit].decode("ascii")
    prefix = encoded[: limit - len(marker)].decode("utf-8", errors="ignore")
    return prefix + marker.decode("ascii")


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
        timeout_stderr = _as_text(exc.stderr)
        if timeout_stderr and not timeout_stderr.endswith("\n"):
            timeout_stderr += "\n"
        result = CommandResult(
            124,
            _bounded(exc.stdout or ""),
            _bounded(timeout_stderr + f"command timed out after {timeout}s"),
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


def instance_names(lab_id: str, claim_uuid: str) -> List[str]:
    validate_lab_id(lab_id)
    try:
        canonical_uuid = str(uuid.UUID(claim_uuid))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("claim UUID must be canonical") from exc
    if canonical_uuid != claim_uuid:
        raise ValueError("claim UUID must be canonical")
    namespace = hashlib.sha256(f"{lab_id}\0{claim_uuid}".encode("utf-8")).hexdigest()[:16]
    return [f"cks-{namespace}-{role}" for role in INSTANCE_ROLES]


def state_root() -> Path:
    override = os.environ.get("CKS_FULL_SPIKE_STATE_DIR")
    return Path(override).expanduser().resolve() if override else DEFAULT_STATE_ROOT


def claim_path(lab_id: str) -> Path:
    return state_root() / lab_id / "claim.json"


def receipt_path(lab_id: str) -> Path:
    return state_root() / lab_id / "receipt.json"


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"provenance input is missing or unsafe: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_sha256_identities() -> Dict[str, str]:
    if GUEST_DIR.is_symlink() or not GUEST_DIR.is_dir():
        raise RuntimeError("guest provisioning assets are missing or unsafe")
    if TEMPLATES_DIR.is_symlink() or not TEMPLATES_DIR.is_dir():
        raise RuntimeError("Lima templates are missing or unsafe")
    identities = {
        "infra/spike/host.py": _sha256_file(HOST_PATH),
        "infra/versions.json": _sha256_file(VERSIONS_PATH),
    }
    for role in INSTANCE_ROLES:
        template = TEMPLATES_DIR / f"{role}.yaml"
        identities[f"infra/spike/lima/{template.name}"] = _sha256_file(template)
    guest_sources = [source for source in sorted(GUEST_DIR.glob("*")) if source.is_file() and not source.is_symlink()]
    if not guest_sources:
        raise RuntimeError("guest provisioning assets are empty")
    for source in guest_sources:
        identities[f"infra/spike/guest/{source.name}"] = _sha256_file(source)
    return dict(sorted(identities.items()))


def _validate_claim_provenance(claim: Dict[str, Any]) -> None:
    provenance = claim.get("provenance")
    identities = provenance.get("sha256") if isinstance(provenance, dict) else None
    if (
        not isinstance(provenance, dict)
        or provenance.get("claim_uuid") != claim.get("claim_uuid")
        or not isinstance(identities, dict)
        or "infra/spike/host.py" not in identities
        or "infra/versions.json" not in identities
        or not any(key.startswith("infra/spike/guest/") for key in identities)
        or any(f"infra/spike/lima/{role}.yaml" not in identities for role in INSTANCE_ROLES)
        or any(
            not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", str(value))
            for key, value in identities.items()
        )
    ):
        raise RuntimeError("claim provenance identity does not match this simulator")


def new_claim(lab_id: str, *, claim_uuid: Optional[str] = None) -> Dict[str, Any]:
    validate_lab_id(lab_id)
    claim_uuid = claim_uuid or str(uuid.uuid4())
    supplied = instance_names(lab_id, claim_uuid)
    return {
        "schema": 1,
        "managed_by": MANAGED_BY,
        "lab_id": lab_id,
        "claim_uuid": claim_uuid,
        "provenance": {
            "claim_uuid": claim_uuid,
            "sha256": source_sha256_identities(),
        },
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "declared",
        "instances": supplied,
        "created_instances": [],
        "pending_instance": None,
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


def write_receipt(lab_id: str, claim: Dict[str, Any], receipt: Dict[str, Any]) -> None:
    validate_lab_id(lab_id)
    _validate_claim_provenance(claim)
    if receipt.get("lab_id") != lab_id or receipt.get("provenance") != claim.get("provenance"):
        raise RuntimeError("receipt identity does not match claim")
    path = receipt_path(lab_id)
    if path.is_symlink():
        raise RuntimeError("refusing symlink receipt path")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
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
        or "pending_instance" not in claim
    ):
        raise RuntimeError("claim identity does not match this simulator")
    try:
        expected_instances = instance_names(lab_id, claim["claim_uuid"])
    except ValueError as exc:
        raise RuntimeError("claim identity does not match this simulator") from exc
    if claim["instances"] != expected_instances:
        raise RuntimeError("claim provider handles do not match the declared lab")
    if any(name not in claim["instances"] for name in claim["created_instances"]):
        raise RuntimeError("claim contains an unowned created handle")
    pending = claim["pending_instance"]
    if pending is not None and (
        not isinstance(pending, str)
        or pending not in claim["instances"]
        or pending in claim["created_instances"]
    ):
        raise RuntimeError("claim contains an unowned pending provider handle")
    _validate_claim_provenance(claim)
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
    for section in ("helm", "cilium", "falco", "trivy", "kube_bench", "docker", "ingress_nginx"):
        value = versions.get(section, {})
        url_keys = [key for key in value if key.endswith("url")]
        digest_keys = [key for key in value if key.endswith("sha256")]
        if not url_keys or not digest_keys:
            raise RuntimeError(f"{section} has no authenticated artifact identity")
        if any(not str(value[key]).startswith("https://") for key in url_keys):
            raise RuntimeError(f"{section} has a non-HTTPS artifact URL")
        if any(not re.fullmatch(r"[0-9a-f]{64}", str(value[key])) for key in digest_keys):
            raise RuntimeError(f"{section} has an invalid sha256 identity")
    gvisor = versions.get("gvisor", {})
    for prefix in ("runsc", "shim"):
        if "generation=" not in str(gvisor.get(f"{prefix}_url", "")) or not re.fullmatch(
            r"[0-9a-f]{128}", str(gvisor.get(f"{prefix}_sha512", ""))
        ):
            raise RuntimeError("gVisor artifacts are not generation-pinned and sha512-authenticated")
    if versions.get("docker", {}).get("ip_forward_no_drop") is not True:
        raise RuntimeError("Docker forwarding safety is not pinned")
    if versions.get("kube_bench", {}).get("mode") != "training-only":
        raise RuntimeError("kube-bench must remain training-only on Kubernetes 1.35")
    if not re.fullmatch(
        r"docker\.io/falcosecurity/falco:[0-9.]+@sha256:[0-9a-f]{64}",
        str(versions.get("falco", {}).get("image", "")),
    ):
        raise RuntimeError("Falco runtime image must be digest-pinned")
    images = versions.get("workload_images", {})
    if not images or any(not re.search(r"@sha256:[0-9a-f]{64}\Z", str(image)) for image in images.values()):
        raise RuntimeError("probe workload images must be digest-pinned")
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


def preflight(
    lab_id: str,
    *,
    instances: Optional[Sequence[str]] = None,
    runner: Runner = run_command,
) -> List[Dict[str, Any]]:
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
    if instances is None:
        existing_state = claim_path(lab_id)
        available = not existing_state.exists() and not existing_state.is_symlink()
        add(
            "lab id available",
            available,
            "available" if available else "an existing or unsafe claim already reserves this lab id",
        )
    else:
        try:
            existing = _lima_instances(runner=runner)
            collision_candidates = list(instances)
            collisions = [name for name in collision_candidates if name in existing]
            add("instance collision", not collisions, "none" if not collisions else ", ".join(collisions))
        except RuntimeError as exc:
            add("instance discovery", False, str(exc))
    return checks


def require_checks(checks: Iterable[Dict[str, Any]]) -> None:
    failed = [check for check in checks if not check["passed"]]
    if failed:
        raise RuntimeError("preflight failed: " + "; ".join(f"{item['name']}: {item['detail']}" for item in failed))


def shell(
    instance: str,
    argv: Sequence[str],
    *,
    runner: Runner = run_command,
    timeout: int = 1800,
    check: bool = True,
) -> CommandResult:
    return runner(["limactl", "shell", instance, "--", *argv], timeout=timeout, check=check)


def provision_vms(lab_id: str, *, runner: Runner = run_command) -> Dict[str, Any]:
    path = claim_path(lab_id)
    claim = new_claim(lab_id)
    names = claim["instances"]
    write_claim_exclusive(path, claim)
    try:
        checks = preflight(lab_id, instances=names, runner=runner)
        require_checks(checks)
        for role, name in zip(INSTANCE_ROLES, names):
            template = TEMPLATES_DIR / f"{role}.yaml"
            claim["pending_instance"] = name
            claim["status"] = "vm-creation-pending"
            write_claim(path, claim)
            try:
                result = runner(
                    ["limactl", "start", "--yes", "--name", name, str(template)],
                    timeout=1800,
                    check=False,
                )
            except OSError:
                # The provider may have registered the exact handle before the
                # client observed a transport failure. Keep it claimed until
                # cleanup proves that exact handle is absent.
                raise
            if result.returncode != 0:
                raise RuntimeError(f"failed to start exact claimed instance {name} ({result.returncode})")
            claim["created_instances"].append(name)
            claim["pending_instance"] = None
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
    _validate_claim_provenance(claim)
    if source_sha256_identities() != claim["provenance"]["sha256"]:
        raise RuntimeError("source identity changed after the lab claim was created")
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
    script_args: Sequence[str] = (),
    runner: Runner = run_command,
    timeout: int = 1800,
    check: bool = True,
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
    if any("\x00" in value or "\n" in value for value in script_args):
        raise ValueError("unsafe guest script argument")
    return shell(
        instance,
        ["sudo", "env", *env_argv, "bash", f"/tmp/cks-spike-guest/{script}", *script_args],
        runner=runner,
        timeout=timeout,
        check=check,
    )


def scrub_bootstrap_secrets(lab_id: str) -> Dict[str, str]:
    secret_dir = claim_path(lab_id).parent / "bootstrap"
    errors: List[str] = []
    if secret_dir.is_symlink():
        try:
            secret_dir.unlink()
        except OSError as exc:
            errors.append(f"unable to remove unsafe bootstrap symlink: {exc}")
        else:
            errors.append("unsafe bootstrap symlink removed without following its target")
        return {"status": "failed", "detail": _bounded("; ".join(errors), 4096)}
    for name in ("join.env", "candidate-kubeconfig"):
        secret = secret_dir / name
        if secret.is_dir() and not secret.is_symlink():
            errors.append(f"refusing unexpected directory at bootstrap secret path: {name}")
            continue
        try:
            secret.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(f"unable to remove {name}: {exc}")
    if secret_dir.is_dir():
        try:
            secret_dir.rmdir()
        except OSError:
            pass
    return {
        "status": "failed" if errors else "passed",
        "detail": _bounded("; ".join(errors) if errors else "host bootstrap secrets removed", 4096),
    }


def finalize_bootstrap_secret_cleanup(
    lab_id: str,
    path: Path,
    claim: Optional[Dict[str, Any]],
    active_error: Optional[BaseException],
) -> None:
    outcome = scrub_bootstrap_secrets(lab_id)
    if claim is not None:
        claim["host_secret_cleanup"] = outcome
        try:
            write_claim(path, claim)
        except (OSError, RuntimeError, ValueError):
            if active_error is None:
                raise
    if outcome["status"] != "passed" and active_error is None:
        raise RuntimeError("host bootstrap secret cleanup failed: " + outcome["detail"])


def bootstrap_base_stack(lab_id: str, *, runner: Runner = run_command) -> Dict[str, Any]:
    path = claim_path(lab_id)
    claim = load_owned_claim(path, lab_id)
    if claim.get("status") not in {"vms-ready", "assets-staged", "bootstrap-degraded"}:
        raise RuntimeError(f"lab is not ready for bootstrap: {claim.get('status')}")
    roles = dict(zip(INSTANCE_ROLES, claim["instances"]))
    try:
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
        run_guest_script(
            roles["control-plane"],
            "30-control-plane.sh",
            {},
            script_args=["revoke-token"],
            runner=runner,
            timeout=300,
        )
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
    finally:
        finalize_bootstrap_secret_cleanup(lab_id, path, claim, sys.exc_info()[1])


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
        "all nodes Ready wait",
        roles["control-plane"],
        [
            "sudo",
            "env",
            "KUBECONFIG=/etc/kubernetes/admin.conf",
            "kubectl",
            "wait",
            "--for=condition=Ready",
            "nodes",
            "--all",
            "--timeout=5m",
        ],
    )
    execute(
        "three Ready nodes",
        roles["control-plane"],
        ["sudo", "env", "KUBECONFIG=/etc/kubernetes/admin.conf", "kubectl", "get", "nodes", "--no-headers"],
    )
    if checks[-1]["passed"]:
        lines = [line for line in checks[-1]["detail"].splitlines() if line.strip()]
        checks[-1]["passed"] = len(lines) == 3 and all(" Ready " in f" {line} " for line in lines)
    execute(
        "Cilium agents rollout",
        roles["control-plane"],
        [
            "sudo",
            "env",
            "KUBECONFIG=/etc/kubernetes/admin.conf",
            "kubectl",
            "-n",
            "kube-system",
            "rollout",
            "status",
            "daemonset/cilium",
            "--timeout=5m",
        ],
    )
    execute(
        "Cilium Envoy rollout",
        roles["control-plane"],
        [
            "sudo",
            "env",
            "KUBECONFIG=/etc/kubernetes/admin.conf",
            "kubectl",
            "-n",
            "kube-system",
            "rollout",
            "status",
            "daemonset/cilium-envoy",
            "--timeout=5m",
        ],
    )
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
        "provenance": claim["provenance"],
    }
    write_receipt(lab_id, claim, receipt)
    claim["status"] = "base-validated" if receipt["passed"] else "validation-degraded"
    write_claim(path, claim)
    return receipt


def parse_probe_results(phase: str, transcript: Any) -> List[Dict[str, str]]:
    expected = EXPECTED_PROBE_IDS.get(phase)
    if expected is None:
        raise ValueError(f"unknown probe phase: {phase}")
    seen: Dict[str, List[str]] = {}
    malformed: List[str] = []
    for line in _as_text(transcript).splitlines():
        if not line.startswith("PROBE_RESULT"):
            continue
        match = PROBE_RESULT_PATTERN.fullmatch(line)
        if not match:
            malformed.append(_bounded(line, 256))
            continue
        probe_id, status = match.groups()
        seen.setdefault(probe_id, []).append(status)

    expected_set = set(expected)
    missing = [probe_id for probe_id in expected if probe_id not in seen]
    unknown = sorted(probe_id for probe_id in seen if probe_id not in expected_set)
    duplicates = sorted(probe_id for probe_id, statuses in seen.items() if len(statuses) != 1)
    failed = [probe_id for probe_id in expected if seen.get(probe_id) == ["FAIL"]]
    problems: List[str] = []
    if malformed:
        problems.append("malformed markers: " + "; ".join(malformed))
    if missing:
        problems.append("missing: " + ", ".join(missing))
    if unknown:
        problems.append("unknown: " + ", ".join(unknown))
    if duplicates:
        problems.append("duplicate: " + ", ".join(duplicates))
    if failed:
        problems.append("failed: " + ", ".join(failed))
    if problems:
        raise RuntimeError(f"invalid {phase} PROBE_RESULT denominator: " + "; ".join(problems))
    return [{"id": probe_id, "status": seen[probe_id][0]} for probe_id in expected]


def _command_detail(result: CommandResult, error: Optional[str] = None) -> str:
    parts: List[str] = []
    if error:
        parts.append(error)
    if result.stderr.strip():
        parts.append(result.stderr.strip())
    if result.stdout.strip():
        stdout = result.stdout.strip()
        if len(stdout) > 2048:
            stdout = stdout[:512] + "\n<transcript-middle-omitted>\n" + stdout[-1536:]
        parts.append(stdout)
    return _bounded("\n".join(parts) or "passed", 4096)


def validate_security_capabilities(lab_id: str, *, runner: Runner = run_command) -> Dict[str, Any]:
    path = claim_path(lab_id)
    claim = load_owned_claim(path, lab_id)
    if claim.get("status") != "base-validated":
        raise RuntimeError(f"base lab must be validated before capability probes: {claim.get('status')}")
    roles = dict(zip(INSTANCE_ROLES, claim["instances"]))
    addresses = claim.get("addresses", {})
    if not isinstance(addresses, dict) or "worker1" not in addresses:
        raise RuntimeError("validated lab has no recorded worker address")
    checks: List[Dict[str, Any]] = []
    try:
        receipt = json.loads(receipt_path(lab_id).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("base validation receipt is missing or unreadable") from exc
    if receipt.get("passed") is not True or receipt.get("provenance") != claim.get("provenance"):
        raise RuntimeError("base validation receipt identity does not match claim")
    receipt["scope"] = "full ARM64 Lima, Kubernetes and CKS security capability spike"
    receipt["base_passed"] = True
    receipt["capability_checks"] = checks

    def persist(status: str) -> None:
        receipt["capability_status"] = status
        receipt["passed"] = status == "complete" and all(check["passed"] for check in checks)
        receipt["validated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_receipt(lab_id, claim, receipt)
        claim["status"] = {
            "incomplete": "capability-validating",
            "failed": "capability-degraded",
            "complete": "capabilities-validated",
        }[status]
        write_claim(path, claim)

    def completed(
        name: str,
        action: Callable[[], CommandResult],
        *,
        probe_phase: Optional[str] = None,
    ) -> None:
        try:
            result = action()
        except (OSError, RuntimeError, ValueError) as exc:
            checks.append({"name": name, "passed": False, "detail": _bounded(str(exc), 4096)})
            persist("failed")
            raise RuntimeError(f"{name} failed") from exc

        validation_error: Optional[str] = None
        probe_results: Optional[List[Dict[str, str]]] = None
        if probe_phase is not None:
            try:
                probe_results = parse_probe_results(probe_phase, result.stdout)
            except RuntimeError as exc:
                validation_error = str(exc)
                probe_results = [
                    {"id": match.group(1), "status": match.group(2)}
                    for line in result.stdout.splitlines()
                    if (match := PROBE_RESULT_PATTERN.fullmatch(line)) is not None
                ]
        passed = result.returncode == 0 and validation_error is None
        check: Dict[str, Any] = {
            "name": name,
            "passed": passed,
            "returncode": result.returncode,
            "detail": _command_detail(result, validation_error),
        }
        if probe_phase is not None:
            check["probe_phase"] = probe_phase
            check["expected_probe_ids"] = list(EXPECTED_PROBE_IDS[probe_phase])
            if probe_results is not None:
                check["probe_results"] = probe_results
        checks.append(check)
        persist("incomplete" if passed else "failed")
        if not passed:
            raise RuntimeError(f"{name} failed with return code {result.returncode}")

    persist("incomplete")
    completed(
        "control-plane probe assets",
        lambda: run_guest_script(
            roles["control-plane"],
            "50-runtime-extras.sh",
            {},
            script_args=["control-plane"],
            runner=runner,
            timeout=2400,
            check=False,
        ),
    )
    completed(
        "gVisor systrap installation",
        lambda: run_guest_script(
            roles["worker1"],
            "50-runtime-extras.sh",
            {},
            script_args=["gvisor"],
            runner=runner,
            timeout=1200,
            check=False,
        ),
    )
    completed(
        "Docker isolated installation",
        lambda: run_guest_script(
            roles["worker2"],
            "50-runtime-extras.sh",
            {},
            script_args=["docker"],
            runner=runner,
            timeout=1200,
            check=False,
        ),
    )
    completed(
        "AppArmor profile installation",
        lambda: run_guest_script(
            roles["worker1"],
            "50-runtime-extras.sh",
            {},
            script_args=["apparmor"],
            runner=runner,
            timeout=300,
            check=False,
        ),
    )
    completed(
        "pre-Docker security capability matrix",
        lambda: run_guest_script(
            roles["control-plane"],
            "60-validate-capabilities.sh",
            {},
            script_args=["baseline", roles["worker1"], roles["worker2"], addresses["worker1"]],
            runner=runner,
            timeout=3600,
            check=False,
        ),
        probe_phase="baseline",
    )
    completed(
        "Docker daemon behavioral probe",
        lambda: run_guest_script(
            roles["worker2"],
            "50-runtime-extras.sh",
            {},
            script_args=["start-docker"],
            runner=runner,
            timeout=900,
            check=False,
        ),
    )
    completed(
        "post-Docker Cilium connectivity",
        lambda: run_guest_script(
            roles["control-plane"],
            "60-validate-capabilities.sh",
            {},
            script_args=["post-docker", roles["worker1"], roles["worker2"], addresses["worker1"]],
            runner=runner,
            timeout=1800,
            check=False,
        ),
        probe_phase="post-docker",
    )
    persist("complete")
    return receipt


def claimed_cleanup_handles(claim: Dict[str, Any]) -> List[str]:
    instances = claim.get("created_instances")
    if not isinstance(instances, list):
        raise RuntimeError("claim has no exact created provider handles")
    handles = list(instances)
    pending = claim.get("pending_instance")
    if pending is not None:
        if not isinstance(pending, str) or pending not in claim.get("instances", ()) or pending in handles:
            raise RuntimeError("claim contains an unsafe pending provider handle")
        handles.append(pending)
    return handles


def destroy_instances(claim: Dict[str, Any], *, runner: Runner = run_command) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for name in reversed(claimed_cleanup_handles(claim)):
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
    claim: Optional[Dict[str, Any]] = None
    try:
        claim = load_owned_claim(path, lab_id)
        results = destroy_instances(claim, runner=runner)
        remaining = _lima_instances(runner=runner)
        still_present = [name for name in claimed_cleanup_handles(claim) if name in remaining]
        if still_present:
            claim["status"] = "cleanup-pending"
            claim["cleanup"] = results
            write_claim(path, claim)
            raise RuntimeError("owned instances remain after cleanup: " + ", ".join(still_present))
        claim["status"] = "destroyed"
        claim["pending_instance"] = None
        claim["cleanup"] = results
        write_claim(path, claim)
        return results
    finally:
        finalize_bootstrap_secret_cleanup(lab_id, path, claim, sys.exc_info()[1])


def run_full_lifecycle(
    lab_id: str,
    *,
    keep: bool = False,
    runner: Runner = run_command,
) -> Dict[str, Any]:
    receipt: Optional[Dict[str, Any]] = None
    claim: Optional[Dict[str, Any]] = None
    primary_error: Optional[str] = None
    cleanup_error: Optional[str] = None
    deferred_exception: Optional[BaseException] = None
    validation_passed = False
    path = claim_path(lab_id)

    def remember_primary(exc: BaseException) -> None:
        nonlocal primary_error
        message = str(exc) or type(exc).__name__
        detail = _bounded(message, 8192)
        primary_error = _bounded(f"{primary_error}; {detail}" if primary_error else detail, 8192)

    try:
        try:
            provision_vms(lab_id, runner=runner)
            bootstrap_base_stack(lab_id, runner=runner)
            base_receipt = validate_base_stack(lab_id, runner=runner)
            if base_receipt.get("passed") is not True:
                raise RuntimeError("base validation failed")
            receipt = validate_security_capabilities(lab_id, runner=runner)
            if receipt.get("passed") is not True:
                raise RuntimeError("security capability validation failed")
            validation_passed = True
        except BaseException as exc:
            remember_primary(exc)
            if not isinstance(exc, (OSError, RuntimeError, ValueError)):
                deferred_exception = exc

        if path.is_file() and not path.is_symlink():
            try:
                claim = load_owned_claim(path, lab_id)
            except BaseException as exc:
                remember_primary(exc)
                if not isinstance(exc, (OSError, RuntimeError, ValueError)) and deferred_exception is None:
                    deferred_exception = exc

        if claim is not None:
            if receipt is None:
                try:
                    candidate = json.loads(receipt_path(lab_id).read_text(encoding="utf-8"))
                    if candidate.get("provenance") != claim.get("provenance"):
                        raise RuntimeError("receipt identity does not match claim")
                    receipt = candidate
                except OSError:
                    receipt = {
                        "schema": 1,
                        "lab_id": lab_id,
                        "scope": "full ARM64 Lima, Kubernetes and CKS security capability spike",
                        "provenance": claim["provenance"],
                    }
                except BaseException as exc:
                    remember_primary(exc)
                    if not isinstance(exc, (RuntimeError, ValueError)) and deferred_exception is None:
                        deferred_exception = exc
                    receipt = {
                        "schema": 1,
                        "lab_id": lab_id,
                        "scope": "full ARM64 Lima, Kubernetes and CKS security capability spike",
                        "provenance": claim["provenance"],
                    }

            receipt["validation_passed"] = validation_passed
            receipt["passed"] = False
            receipt["lifecycle_status"] = "cleanup-pending"
            receipt["cleanup"] = {"status": "pending", "results": []}
            try:
                write_receipt(lab_id, claim, receipt)
            except BaseException as exc:
                remember_primary(exc)
                if deferred_exception is None:
                    deferred_exception = exc
    except BaseException as exc:
        remember_primary(exc)
        if deferred_exception is None:
            deferred_exception = exc
    finally:
        if receipt is None:
            receipt = {
                "schema": 1,
                "lab_id": lab_id,
                "scope": "full ARM64 Lima, Kubernetes and CKS security capability spike",
            }
            if claim is not None:
                receipt["provenance"] = claim["provenance"]

        if keep:
            cleanup: Dict[str, Any] = {"status": "skipped", "results": [], "detail": "lab retained by --keep"}
        elif claim is None:
            cleanup = {"status": "not-required", "results": []}
        else:
            try:
                results = destroy_lab(lab_id, runner=runner)
                cleanup = {"status": "passed", "results": results}
            except BaseException as exc:
                cleanup_error = _bounded(str(exc) or type(exc).__name__, 8192)
                cleanup = {"status": "failed", "results": [], "detail": cleanup_error}
                if not isinstance(exc, (OSError, RuntimeError, ValueError)) and deferred_exception is None:
                    deferred_exception = exc
                try:
                    current_claim = load_owned_claim(path, lab_id)
                    if isinstance(current_claim.get("cleanup"), list):
                        cleanup["results"] = current_claim["cleanup"]
                except RuntimeError:
                    pass
        cleanup["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()

    receipt["cleanup"] = cleanup
    receipt["errors"] = {"primary": primary_error, "cleanup": cleanup_error}
    receipt["validation_passed"] = validation_passed
    receipt["passed"] = validation_passed and primary_error is None and cleanup["status"] == "passed"
    receipt["lifecycle_status"] = "complete" if receipt["passed"] else "failed"
    receipt["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    if claim is not None:
        try:
            write_receipt(lab_id, claim, receipt)
        except BaseException as exc:
            if deferred_exception is None:
                deferred_exception = exc
    if deferred_exception is not None:
        raise deferred_exception
    return receipt


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
    for command in ("preflight", "provision", "stage", "bootstrap", "validate", "capabilities", "destroy"):
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
        if args.command == "capabilities":
            receipt = validate_security_capabilities(lab_id)
            render(receipt, as_json=args.as_json)
            return 0 if receipt["passed"] else 1
        if args.command == "destroy":
            render(destroy_lab(lab_id), as_json=args.as_json)
            return 0
        if args.command == "all":
            receipt = run_full_lifecycle(lab_id, keep=args.keep)
            render(receipt, as_json=args.as_json)
            return 0 if receipt["passed"] else 1
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
