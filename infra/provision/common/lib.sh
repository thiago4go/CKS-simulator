#!/usr/bin/env bash

# Shared functions for production Ubuntu guest convergence. This file does not
# execute provisioning when sourced.

die() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

log() {
  printf 'common-provision: %s\n' "$*" >&2
}

require_root() {
  [[ ${EUID} -eq 0 ]] || { die "must run as root"; return 1; }
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || { die "required command not found: $1"; return 1; }
}

assert_secure_root_file() {
  local path=$1 owner mode
  [[ -f "$path" && ! -L "$path" ]] || { die "required regular non-symlink file is missing: ${path}"; return 1; }
  owner=$(stat -c '%u:%g' -- "$path") || { die "cannot inspect file ownership: ${path}"; return 1; }
  mode=$(stat -c '%a' -- "$path") || { die "cannot inspect file mode: ${path}"; return 1; }
  [[ "$owner" == "0:0" ]] || { die "file must be root-owned: ${path}"; return 1; }
  (( (8#$mode & 8#022) == 0 )) || { die "file must not be group/world writable: ${path}"; return 1; }
}

validate_manifest_key() {
  case "$1" in
    MANIFEST_SCHEMA|SOURCE_SHA256|UBUNTU_VERSION|UBUNTU_IMAGE_ARCH|DEBIAN_ARCH|KUBERNETES_MINOR|KUBERNETES_VERSION|KUBERNETES_PACKAGE_VERSION|KUBERNETES_APT_KEY_URL|KUBERNETES_APT_KEY_SHA256|KUBERNETES_APT_REPOSITORY|CONTAINERD_PACKAGE_NAME|CONTAINERD_PACKAGE_VERSION|CONTAINERD_RUNTIME_VERSION|CRI_TOOLS_VERSION|CRI_TOOLS_PACKAGE_VERSION|SANDBOX_IMAGE|DOCKER_APT_KEY_URL|DOCKER_APT_KEY_SHA256|DOCKER_APT_REPOSITORY)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

trim_space() {
  local value=$1
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

load_manifest() {
  local manifest_path=$1 line key value seen='|'
  [[ -f "$manifest_path" && ! -L "$manifest_path" ]] || { die "manifest is not a regular non-symlink file: ${manifest_path}"; return 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=$(trim_space "$line")
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || { die "invalid manifest line"; return 1; }
    key=$(trim_space "${line%%=*}")
    value=$(trim_space "${line#*=}")
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || { die "invalid manifest key"; return 1; }
    validate_manifest_key "$key" || { die "manifest key is not allowlisted: ${key}"; return 1; }
    [[ "$seen" != *"|${key}|"* ]] || { die "duplicate manifest key: ${key}"; return 1; }
    # Bash variables cannot contain NUL bytes. Newline and carriage return are
    # rejected explicitly so one manifest record cannot create another.
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || { die "unsafe manifest value: ${key}"; return 1; }
    seen="${seen}${key}|"
    printf -v "$key" '%s' "$value"
    export "$key"
  done < "$manifest_path"

  local required
  for required in \
    MANIFEST_SCHEMA SOURCE_SHA256 UBUNTU_VERSION UBUNTU_IMAGE_ARCH DEBIAN_ARCH \
    KUBERNETES_MINOR KUBERNETES_VERSION KUBERNETES_PACKAGE_VERSION \
    KUBERNETES_APT_KEY_URL KUBERNETES_APT_KEY_SHA256 KUBERNETES_APT_REPOSITORY \
    CONTAINERD_PACKAGE_NAME CONTAINERD_PACKAGE_VERSION CONTAINERD_RUNTIME_VERSION \
    CRI_TOOLS_VERSION CRI_TOOLS_PACKAGE_VERSION SANDBOX_IMAGE \
    DOCKER_APT_KEY_URL DOCKER_APT_KEY_SHA256 DOCKER_APT_REPOSITORY; do
    [[ "$seen" == *"|${required}|"* ]] || { die "manifest value is missing: ${required}"; return 1; }
  done
  [[ "$MANIFEST_SCHEMA" == 1 ]] || { die "unsupported guest manifest schema"; return 1; }
  [[ "$SOURCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { die "invalid source manifest digest"; return 1; }
  validate_loaded_manifest || return 1
}

validate_loaded_manifest() {
  local kubernetes_semver=${KUBERNETES_VERSION#v}
  [[ "$UBUNTU_VERSION" == 24.04 && "$UBUNTU_IMAGE_ARCH" == aarch64 && "$DEBIAN_ARCH" == arm64 ]] ||
    { die "unsupported Ubuntu manifest target"; return 1; }
  [[ "$KUBERNETES_MINOR" =~ ^v[0-9]+\.[0-9]+$ && "$KUBERNETES_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    { die "invalid Kubernetes version manifest"; return 1; }
  [[ "$KUBERNETES_VERSION" == "${KUBERNETES_MINOR}."* ]] ||
    { die "Kubernetes minor and full versions disagree"; return 1; }
  [[ "$KUBERNETES_PACKAGE_VERSION" == "${kubernetes_semver}-1.1" ]] ||
    { die "Kubernetes package version does not match the release"; return 1; }
  [[ "$KUBERNETES_APT_KEY_URL" == "https://pkgs.k8s.io/core:/stable:/${KUBERNETES_MINOR}/deb/Release.key" ]] ||
    { die "unexpected Kubernetes repository key URL"; return 1; }
  [[ "$KUBERNETES_APT_REPOSITORY" == "https://pkgs.k8s.io/core:/stable:/${KUBERNETES_MINOR}/deb/" ]] ||
    { die "unexpected Kubernetes repository URL"; return 1; }
  [[ "$KUBERNETES_APT_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    { die "invalid Kubernetes repository key digest"; return 1; }
  [[ "$CONTAINERD_PACKAGE_NAME" == containerd.io && "$CONTAINERD_RUNTIME_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    { die "invalid containerd manifest"; return 1; }
  [[ "$CONTAINERD_PACKAGE_VERSION" == "${CONTAINERD_RUNTIME_VERSION}-1~ubuntu.24.04~noble" ]] ||
    { die "containerd package version does not match the runtime release"; return 1; }
  [[ "$CRI_TOOLS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$CRI_TOOLS_PACKAGE_VERSION" == "${CRI_TOOLS_VERSION}-1.1" ]] ||
    { die "invalid CRI tools manifest"; return 1; }
  [[ "$SANDBOX_IMAGE" =~ ^registry\.k8s\.io/pause:[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    { die "invalid sandbox image manifest"; return 1; }
  [[ "$DOCKER_APT_KEY_URL" == https://download.docker.com/linux/ubuntu/gpg ]] ||
    { die "unexpected containerd repository key URL"; return 1; }
  [[ "$DOCKER_APT_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    { die "invalid containerd repository key digest"; return 1; }
  [[ "$DOCKER_APT_REPOSITORY" == 'https://download.docker.com/linux/ubuntu noble stable' ]] ||
    { die "unexpected containerd repository"; return 1; }
}

assert_ubuntu_arm64() {
  local release arch
  [[ -r /etc/os-release ]] || { die "/etc/os-release is missing"; return 1; }
  # shellcheck disable=SC1091
  source /etc/os-release
  release=${VERSION_ID:-}
  arch=$(dpkg --print-architecture)
  [[ ${ID:-} == ubuntu && "$release" == "$UBUNTU_VERSION" ]] ||
    { die "requires Ubuntu ${UBUNTU_VERSION}; found ${ID:-unknown} ${release:-unknown}"; return 1; }
  [[ "$arch" == "$DEBIAN_ARCH" ]] || { die "requires ${DEBIAN_ARCH}; found ${arch}"; return 1; }
}

validate_identity_args() {
  local identity_role=$1 identity_lab_id=$2 identity_handle=$3 identity_node_name=$4 identity_node_ip=$5 compact expected
  case "$identity_role" in
    candidate|control-plane|worker1|worker2) ;;
    *) die "invalid machine role: ${identity_role}"; return 1 ;;
  esac
  [[ "$identity_lab_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    { die "lab id must be a canonical lowercase UUID"; return 1; }
  compact=${identity_lab_id//-/}
  expected="cks-${compact:0:16}-${identity_role}"
  [[ "$identity_handle" == "$expected" ]] || { die "provider handle does not match immutable lab identity"; return 1; }
  [[ "$identity_node_name" == "$identity_handle" ]] || { die "node name must equal the stable provider handle"; return 1; }
  [[ ${#identity_node_name} -le 63 && "$identity_node_name" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] ||
    { die "node name is not a DNS label"; return 1; }
  python3 - "$identity_node_ip" <<'PY' || { die "node IP must be a usable IPv4 address"; return 1; }
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
    raise SystemExit(1)
PY
}

assert_guest_identity_marker() {
  local marker=$1 marker_role=$2 marker_lab_id=$3 marker_handle=$4 marker_mode
  assert_secure_root_file "$marker" || return 1
  marker_mode=$(stat -c '%a' -- "$marker") || { die "cannot inspect guest identity marker mode"; return 1; }
  [[ "$marker_mode" == 600 ]] || { die "guest identity marker must have mode 0600"; return 1; }
  python3 - "$marker" "$marker_role" "$marker_lab_id" "$marker_handle" <<'PY' || { die "guest identity marker does not match provision arguments"; return 1; }
import json
import os
import sys
import uuid

path, role, lab_id, handle = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    value = json.load(stream)
expected = {
    "schema_version": 1,
    "managed_by": "cks-simulator",
    "lab_id": lab_id,
    "role": role,
    "provider": "lima",
    "handle": handle,
}
if any(value.get(key) != expected_value for key, expected_value in expected.items()):
    raise SystemExit(1)
machine_id = value.get("machine_id")
try:
    canonical_machine_id = str(uuid.UUID(machine_id))
except (AttributeError, ValueError):
    raise SystemExit(1)
if machine_id != canonical_machine_id:
    raise SystemExit(1)
PY
}

assert_node_hostname() {
  local expected=$1 observed=${2:-}
  if [[ -z "$observed" ]]; then
    observed=$(hostname --short) || { die "cannot read node hostname"; return 1; }
  fi
  [[ "$observed" == "$expected" || "$observed" == "lima-${expected}" ]] ||
    { die "node hostname does not match its stable Lima identity"; return 1; }
}

required_ports_for_role() {
  case "$1" in
    control-plane) printf '%s' '6443,2379,2380,10250,10257,10259' ;;
    worker1|worker2) printf '%s' '10250,10256' ;;
    *) die "ports are not defined for role: $1"; return 1 ;;
  esac
}

validate_cluster_inputs() {
  local cluster_role=$1 cluster_node_ip=$2 cluster_pod_cidr=$3 cluster_service_cidr=$4 cluster_required_ports=$5 expected_ports
  expected_ports=$(required_ports_for_role "$cluster_role") || return 1
  [[ "$cluster_required_ports" == "$expected_ports" ]] || { die "required ports do not match role ${cluster_role}"; return 1; }
  python3 - "$cluster_node_ip" "$cluster_pod_cidr" "$cluster_service_cidr" <<'PY' || { die "pod/service CIDRs are invalid, overlapping, or contain the node IP"; return 1; }
import ipaddress
import sys

node = ipaddress.ip_address(sys.argv[1])
pod = ipaddress.ip_network(sys.argv[2], strict=True)
service = ipaddress.ip_network(sys.argv[3], strict=True)
if node.version != 4 or pod.version != 4 or service.version != 4:
    raise SystemExit(1)
if pod.overlaps(service) or node in pod or node in service:
    raise SystemExit(1)
PY
}

assert_cgroup_v2() {
  local controllers=${1:-/sys/fs/cgroup/cgroup.controllers}
  [[ -r "$controllers" ]] || { die "cgroup v2 unified hierarchy is required"; return 1; }
}

assert_swap_disabled() {
  local proc_swaps=${1:-/proc/swaps} fstab=${2:-/etc/fstab} zram_guard=${3:-}
  [[ -r "$proc_swaps" && -r "$fstab" ]] || { die "swap state is not readable"; return 1; }
  [[ $(awk 'NR > 1 && NF { count++ } END { print count + 0 }' "$proc_swaps") == 0 ]] ||
    { die "active swap is not allowed on Kubernetes nodes"; return 1; }
  ! awk 'NF && $1 !~ /^#/ && $3 == "swap" { found=1 } END { exit !found }' "$fstab" ||
    { die "persistent swap entry remains in /etc/fstab"; return 1; }
  if [[ -n "$zram_guard" ]]; then
    [[ -f "$zram_guard" && ! -L "$zram_guard" ]] ||
      { die "persistent zram swap guard is missing or unsafe"; return 1; }
  fi
}

assert_forwarding_sysctls() {
  local root=${1:-/proc/sys} relative
  for relative in \
    net/ipv4/ip_forward \
    net/bridge/bridge-nf-call-iptables \
    net/bridge/bridge-nf-call-ip6tables; do
    [[ -r "$root/$relative" && $(<"$root/$relative") == 1 ]] ||
      { die "required sysctl is not enabled: ${relative}"; return 1; }
  done
}

assert_required_modules() {
  local modules=${1:-/proc/modules}
  [[ -r "$modules" ]] || { die "kernel module state is not readable"; return 1; }
  grep -Eq '^overlay[[:space:]]' "$modules" || { die "overlay module is not loaded"; return 1; }
  grep -Eq '^br_netfilter[[:space:]]' "$modules" || { die "br_netfilter module is not loaded"; return 1; }
}

assert_containerd_configuration() {
  local containerd_config=${1:-/etc/containerd/config.toml} crictl_config=${2:-/etc/crictl.yaml}
  local sandbox_image=${3:-}
  [[ -f "$containerd_config" && ! -L "$containerd_config" ]] || { die "containerd config is missing or unsafe"; return 1; }
  [[ -f "$crictl_config" && ! -L "$crictl_config" ]] || { die "crictl config is missing or unsafe"; return 1; }
  grep -Fq 'address = "/run/containerd/containerd.sock"' "$containerd_config" ||
    { die "containerd CRI socket is not explicit"; return 1; }
  grep -Fq 'SystemdCgroup = true' "$containerd_config" || { die "containerd must use systemd cgroups"; return 1; }
  grep -Fxq 'runtime-endpoint: unix:///run/containerd/containerd.sock' "$crictl_config" ||
    { die "crictl runtime endpoint is not explicit"; return 1; }
  grep -Fxq 'image-endpoint: unix:///run/containerd/containerd.sock' "$crictl_config" ||
    { die "crictl image endpoint is not explicit"; return 1; }
  if [[ -n "$sandbox_image" ]]; then
    grep -Fq "sandbox = \"${sandbox_image}\"" "$containerd_config" ||
      { die "containerd sandbox image does not match the immutable manifest"; return 1; }
  fi
}

assert_kubelet_defaults() {
  local kubelet_node_ip=$1 defaults=${2:-/etc/default/kubelet} expected
  expected="KUBELET_EXTRA_ARGS=--container-runtime-endpoint=unix:///run/containerd/containerd.sock --node-ip=${kubelet_node_ip}"
  [[ -f "$defaults" && ! -L "$defaults" ]] || { die "kubelet defaults are missing or unsafe"; return 1; }
  grep -Fxq "$expected" "$defaults" || { die "kubelet CRI endpoint or node IP does not match"; return 1; }
}

assert_ports_available() {
  local ports_required=$1 listeners=${2:-} port
  local temporary=
  if [[ -z "$listeners" ]]; then
    temporary=$(mktemp)
    ss -H -lnt > "$temporary"
    listeners=$temporary
  fi
  [[ -f "$listeners" && ! -L "$listeners" ]] || { rm -f -- "$temporary"; die "listener inventory is unsafe"; return 1; }
  IFS=',' read -r -a ports <<< "$ports_required"
  for port in "${ports[@]}"; do
    [[ "$port" =~ ^[0-9]{1,5}$ && "$port" -ge 1 && "$port" -le 65535 ]] ||
      { rm -f -- "$temporary"; die "invalid required port: ${port}"; return 1; }
    if grep -Eq "[:.]${port}([[:space:]]|$)" "$listeners"; then
      rm -f -- "$temporary"
      die "required port is already listening: ${port}"
      return 1
    fi
  done
  rm -f -- "$temporary"
}

validate_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || { die "invalid SHA-256 value"; return 1; }
}

download_verified() {
  local name=$1 url=$2 sha256=$3 destination=$4
  validate_sha256 "$sha256"
  curl --fail --location --silent --show-error --retry 3 --output "$destination" -- "$url" ||
    { rm -f -- "$destination"; die "download failed for ${name}"; return 1; }
  printf '%s  %s\n' "$sha256" "$destination" | sha256sum --check --status ||
    { rm -f -- "$destination"; die "checksum verification failed for ${name}"; return 1; }
}

install_text_if_changed() {
  local source=$1 destination=$2 mode=${3:-0644} parent temporary
  CKS_INSTALL_TEXT_CHANGED=0
  if [[ -f "$destination" && ! -L "$destination" ]] && cmp --silent "$source" "$destination"; then
    chmod "$mode" -- "$destination"
    return 0
  fi
  parent=$(dirname -- "$destination")
  mkdir -p -- "$parent"
  temporary=$(mktemp "${parent}/.cks-common.XXXXXX")
  install -m "$mode" -- "$source" "$temporary"
  mv -fT -- "$temporary" "$destination"
  CKS_INSTALL_TEXT_CHANGED=1
}

assert_package_version() {
  local package=$1 expected=$2 observed
  observed=$(dpkg-query --show --showformat='${Version}' "$package" 2>/dev/null) ||
    { die "required package is not installed: ${package}"; return 1; }
  [[ "$observed" == "$expected" ]] ||
    { die "package version mismatch for ${package}: expected ${expected}"; return 1; }
}

assert_output_contains() {
  local name=$1 expected=$2 output
  shift 2
  output=$("$@" 2>&1) || { die "${name} version check failed"; return 1; }
  [[ "$output" == *"$expected"* ]] || { die "${name} version mismatch: expected ${expected}"; return 1; }
}
