#!/usr/bin/env bash

# Shared, non-executing helpers for the candidate/toolchain provisioning layer.
# Version manifests are parsed as data; they are never sourced as shell code.

die() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

log() {
  printf 'tools-provision: %s\n' "$*" >&2
}

require_root() {
  [[ ${EUID} -eq 0 ]] || { die "must run as root"; return 1; }
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || { die "required command not found: $1"; return 1; }
}

require_vars() {
  local name
  for name in "$@"; do
    [[ -n ${!name:-} ]] || { die "required input is missing: ${name}"; return 1; }
  done
}

trim_space() {
  local value=$1
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

validate_tools_manifest_key() {
  case "$1" in
    SOURCE_SHA256|HELM_VERSION|HELM_URL|HELM_SHA256|HELM_INSTALLED_SHA256|CILIUM_VERSION|CILIUM_CLI_VERSION|CILIUM_CLI_URL|CILIUM_CLI_SHA256|CILIUM_CLI_INSTALLED_SHA256|ETCDCTL_VERSION|ETCDCTL_URL|ETCDCTL_SHA256|ETCDCTL_INSTALLED_SHA256|KUBE_BENCH_VERSION|KUBE_BENCH_MODE|KUBE_BENCH_URL|KUBE_BENCH_SHA256|KUBE_BENCH_BINARY_INSTALLED_SHA256|KUBE_BENCH_CONFIG_INSTALLED_SHA256|GVISOR_VERSION|GVISOR_PLATFORM|GVISOR_RUNSC_URL|GVISOR_RUNSC_SHA512|GVISOR_RUNSC_INSTALLED_SHA256|GVISOR_SHIM_URL|GVISOR_SHIM_SHA512|GVISOR_SHIM_INSTALLED_SHA256|DOCKER_VERSION|DOCKER_URL|DOCKER_SHA256|DOCKER_INSTALLED_SHA256|FALCO_VERSION|FALCO_CHART_VERSION|FALCO_IMAGE|FALCO_CHART_URL|FALCO_CHART_SHA256|FALCO_CHART_INSTALLED_SHA256|INGRESS_NGINX_VERSION|INGRESS_NGINX_CHART_VERSION|INGRESS_NGINX_CHART_URL|INGRESS_NGINX_CHART_SHA256|INGRESS_NGINX_CHART_INSTALLED_SHA256|BUSYBOX_IMAGE|AGNHOST_IMAGE|NGINX_ALPINE_IMAGE|KUBERNETES_VERSION|CKS_CONTROL_PLANE_NODE|CKS_WORKER1_NODE|CKS_WORKER1_IP|CKS_WORKER2_NODE|CKS_WORKER2_IP)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

load_tools_manifest() {
  local manifest_path=$1 line key value seen='|'
  [[ -f "$manifest_path" && ! -L "$manifest_path" ]] || {
    die "manifest is not a regular non-symlink file: ${manifest_path}"
    return 1
  }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=$(trim_space "$line")
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || { die "invalid manifest line"; return 1; }
    key=$(trim_space "${line%%=*}")
    value=$(trim_space "${line#*=}")
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || { die "invalid manifest key"; return 1; }
    validate_tools_manifest_key "$key" || { die "manifest key is not allowlisted: ${key}"; return 1; }
    [[ "$seen" != *"|${key}|"* ]] || { die "duplicate manifest key: ${key}"; return 1; }
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || { die "unsafe manifest value: ${key}"; return 1; }
    if [[ -n ${!key+x} && ${!key} != "$value" ]]; then
      die "environment and manifest disagree for ${key}"
      return 1
    fi
    printf -v "$key" '%s' "$value"
    export "$key"
    seen="${seen}${key}|"
  done < "$manifest_path"
}

load_tools_inputs() {
  if [[ -n ${CKS_TOOLS_MANIFEST:-} ]]; then
    load_tools_manifest "$CKS_TOOLS_MANIFEST"
    [[ ${SOURCE_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || { die "tool manifest source digest is invalid"; return 1; }
  fi
}

validate_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || { die "invalid SHA-256 value"; return 1; }
}

validate_sha512() {
  [[ "$1" =~ ^[0-9a-f]{128}$ ]] || { die "invalid SHA-512 value"; return 1; }
}

validate_https_url() {
  [[ "$1" =~ ^https://[^[:space:]]+$ ]] || { die "artifact URL must use HTTPS"; return 1; }
}

validate_positive_timeout() {
  local name=$1 value=$2 maximum=$3
  [[ "$value" =~ ^[0-9]+$ ]] || { die "${name} must be an integer"; return 1; }
  (( value >= 1 && value <= maximum )) || { die "${name} is outside its safe bound"; return 1; }
}

download_with_digest() {
  local algorithm=$1 name=$2 url=$3 expected=$4 destination=$5
  local connect_timeout=${CKS_CONNECT_TIMEOUT_SECONDS:-15}
  local download_timeout=${CKS_DOWNLOAD_TIMEOUT_SECONDS:-300}
  local observed
  validate_https_url "$url" || return 1
  validate_positive_timeout CKS_CONNECT_TIMEOUT_SECONDS "$connect_timeout" 120 || return 1
  validate_positive_timeout CKS_DOWNLOAD_TIMEOUT_SECONDS "$download_timeout" 1800 || return 1
  case "$algorithm" in
    sha256) validate_sha256 "$expected" || return 1 ;;
    sha512) validate_sha512 "$expected" || return 1 ;;
    *) die "unsupported digest algorithm"; return 1 ;;
  esac
  rm -f -- "$destination"
  curl --fail --location --silent --show-error \
    --retry 3 --retry-all-errors --connect-timeout "$connect_timeout" \
    --max-time "$download_timeout" --output "$destination" -- "$url" || {
      rm -f -- "$destination"
      die "download failed for ${name}"
      return 1
    }
  observed=$("${algorithm}sum" "$destination" 2>/dev/null | awk '{print $1}') || observed=
  [[ "$observed" == "$expected" ]] || {
    rm -f -- "$destination"
    die "checksum verification failed for ${name}"
    return 1
  }
}

download_sha256() {
  download_with_digest sha256 "$@"
}

download_sha512() {
  download_with_digest sha512 "$@"
}

assert_safe_tar_archive() {
  local archive=$1
  python3 - "$archive" <<'PY'
import pathlib
import gzip
import os
import sys
import tarfile
import unicodedata

archive = pathlib.Path(sys.argv[1])

MAX_CONTENT_BYTES = 1024 * 1024 * 1024
MAX_TAR_METADATA_READ_BYTES = 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_TAR_STRUCTURAL_BYTES = (
    MAX_ARCHIVE_MEMBERS * (512 + 511)
    + (MAX_ARCHIVE_MEMBERS + 1) * (512 + MAX_TAR_METADATA_READ_BYTES)
    + 1024
)
MAX_TAR_STREAM_BYTES = MAX_CONTENT_BYTES + MAX_TAR_STRUCTURAL_BYTES

class BoundedTarStream:
    def __init__(self, stream):
        self.stream = stream

    def read(self, size=-1):
        if size < 0:
            raise ValueError("unbounded tar stream read is not allowed")
        if size > MAX_TAR_METADATA_READ_BYTES:
            raise ValueError("tar extension metadata exceeds 1 KiB")
        position = self.tell()
        if size > MAX_TAR_STREAM_BYTES - position:
            raise ValueError("decompressed tar stream exceeds its safe bound")
        return self.stream.read(size)

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        else:
            raise ValueError("end-relative tar seeks are not allowed")
        if target < 0 or target > MAX_TAR_STREAM_BYTES:
            raise ValueError("decompressed tar stream exceeds its safe bound")
        observed = self.stream.seek(offset, whence)
        if observed != target:
            raise ValueError("tar stream seek did not reach the requested offset")
        return observed

    def tell(self):
        return self.stream.tell()

    def readable(self):
        return True

    def seekable(self):
        return True

with gzip.open(archive, "rb") as decompressed, tarfile.open(
    fileobj=BoundedTarStream(decompressed), mode="r:"
) as stream:
    members = []
    total_size = 0
    for member in stream:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise SystemExit("archive has too many members")
        if member.size < 0 or member.size > 1024 * 1024 * 1024:
            raise SystemExit("archive member is too large")
        total_size += member.size
        if total_size > 1024 * 1024 * 1024:
            raise SystemExit("archive expands beyond 1 GiB")
        members.append(member)
    if not members:
        raise SystemExit("archive is empty")
    kinds = {}
    prefix_aliases = {}
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise SystemExit("archive has an unsafe path")
        if (
            len(path.as_posix().encode("utf-8")) > 768
            or any(len(part.encode("utf-8")) > 255 for part in path.parts)
            or len(path.parts) > 64
        ):
            raise SystemExit("archive path exceeds safe bounds")
        if not (member.isfile() or member.isdir()):
            raise SystemExit("archive has a non-regular member")
        normalized = path.as_posix()
        allowed = {normalized, normalized + "/"} if member.isdir() else {normalized}
        if (
            member.name not in allowed
            or unicodedata.normalize("NFC", normalized) != normalized
            or normalized in kinds
        ):
            raise SystemExit("archive has a non-canonical or duplicate path")
        prefixes = [path, *(parent for parent in path.parents if parent.parts)]
        for prefix in prefixes:
            canonical_prefix = prefix.as_posix()
            alias = unicodedata.normalize("NFC", canonical_prefix).casefold()
            if alias in prefix_aliases and prefix_aliases[alias] != canonical_prefix:
                raise SystemExit("archive has a casefold path-prefix collision")
            prefix_aliases[alias] = canonical_prefix
        kinds[normalized] = "directory" if member.isdir() else "file"
    for name in kinds:
        for parent in pathlib.PurePosixPath(name).parents:
            if not parent.parts:
                break
            if kinds.get(parent.as_posix()) == "file":
                raise SystemExit("archive has a regular-file ancestor")
PY
}

extract_safe_tar() {
  local archive=$1 destination=$2
  assert_safe_tar_archive "$archive" || { die "archive structure is unsafe"; return 1; }
  mkdir -p -- "$destination"
  tar --extract --gzip --file "$archive" --directory "$destination" \
    --no-same-owner --no-same-permissions
}

install_text_if_changed() {
  local source=$1 destination=$2 mode=${3:-0644} parent temporary
  CKS_INSTALL_TEXT_CHANGED=0
  if [[ -f "$destination" && ! -L "$destination" ]] && cmp --silent "$source" "$destination"; then
    chmod "$mode" -- "$destination"
    return 0
  fi
  [[ ! -L "$destination" ]] || { die "refusing symlink destination: ${destination}"; return 1; }
  parent=$(dirname -- "$destination")
  mkdir -p -- "$parent"
  temporary=$(mktemp "${parent}/.cks-tools.XXXXXX")
  install -m "$mode" -- "$source" "$temporary"
  mv -fT -- "$temporary" "$destination"
  CKS_INSTALL_TEXT_CHANGED=1
}

readonly CKS_TOOLS_STATE_DIR=${CKS_TOOLS_STATE_DIR:-/var/lib/cks-simulator/tools}

artifact_content_sha256() {
  local installed=$1
  python3 - "$installed" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
MAX_DESCENDANTS = 4096
MAX_BYTES = 2 * 1024 * 1024 * 1024

digest = hashlib.sha256()
total = 0
descendants = 0

def add(kind: bytes, label: str, mode: int) -> None:
    digest.update(kind + b"\0" + label.encode("utf-8") + b"\0")
    digest.update(f"{mode:o}".encode("ascii") + b"\0")

def add_file(path: Path, label: str) -> None:
    global total
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        observed = os.fstat(stream.fileno())
        if not stat.S_ISREG(observed.st_mode):
            raise SystemExit(1)
        add(b"F", label, stat.S_IMODE(observed.st_mode))
        content_digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_BYTES:
                raise SystemExit(1)
            content_digest.update(chunk)
    # Fixed-width content framing prevents one member's bytes from being
    # reinterpreted as the next member's metadata.
    digest.update(content_digest.digest())

def walk(directory: Path, prefix: str, depth: int = 0) -> None:
    global descendants
    if depth > 64:
        raise SystemExit(1)
    entries = []
    with os.scandir(directory) as iterator:
        for entry in iterator:
            descendants += 1
            if descendants > MAX_DESCENDANTS:
                raise SystemExit(1)
            entries.append(entry)
    entries.sort(key=lambda entry: entry.name)
    for entry in entries:
        label = f"{prefix}/{entry.name}" if prefix else entry.name
        observed = entry.stat(follow_symlinks=False)
        path = Path(entry.path)
        if stat.S_ISDIR(observed.st_mode):
            add(b"D", label, stat.S_IMODE(observed.st_mode))
            walk(path, label, depth + 1)
        elif stat.S_ISREG(observed.st_mode):
            add_file(path, label)
        else:
            raise SystemExit(1)

observed = root.lstat()
if stat.S_ISREG(observed.st_mode):
    add_file(root, ".")
elif stat.S_ISDIR(observed.st_mode) and not stat.S_ISLNK(observed.st_mode):
    add(b"D", ".", stat.S_IMODE(observed.st_mode))
    walk(root, "")
else:
    raise SystemExit(1)
digest.update(b"E\0" + str(descendants + 1).encode("ascii") + b"\0")
print(digest.hexdigest())
PY
}

artifact_is_current() {
  local expected=$1 installed=$2 observed
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ -e "$installed" && ! -L "$installed" ]] || return 1
  observed=$(artifact_content_sha256 "$installed") || return 1
  [[ "$observed" == "$expected" ]]
}

assert_output_contains() {
  local name=$1 expected=$2 output
  shift 2
  output=$("$@" 2>&1) || { die "${name} version check failed"; return 1; }
  [[ "$output" == *"$expected"* ]] || { die "${name} version mismatch: expected ${expected}"; return 1; }
}

assert_digest_pinned_image() {
  [[ "$1" =~ ^[^[:space:]@]+(:[^[:space:]@]+)?@sha256:[0-9a-f]{64}$ ]] || {
    die "container image is not digest pinned"
    return 1
  }
}

assert_rendered_images_pinned() {
  local rendered=$1 expected=${2:-}
  python3 - "$rendered" "$expected" <<'PY'
import re
import sys

path, expected = sys.argv[1:]
images = []
with open(path, "r", encoding="utf-8") as stream:
    for raw in stream:
        match = re.match(r"^\s*image:\s*[\"']?([^\"'\s]+)", raw)
        if match:
            images.append(match.group(1))
if not images:
    raise SystemExit("rendered chart has no images")
digest = re.compile(r"^[^\s@]+(?::[^\s@]+)?@sha256:[0-9a-f]{64}$")
if any(digest.fullmatch(image) is None for image in images):
    raise SystemExit("rendered chart contains an unpinned image")
if expected and any(image != expected for image in images):
    raise SystemExit("rendered chart contains an unexpected image")
PY
}

wait_until() {
  local timeout_seconds=$1 interval_seconds=$2
  shift 2
  local deadline=$((SECONDS + timeout_seconds))
  until "$@"; do
    (( SECONDS < deadline )) || return 1
    sleep "$interval_seconds"
  done
}
