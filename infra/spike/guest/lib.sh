#!/usr/bin/env bash

# Shared, non-executing helpers for the disposable Ubuntu ARM64 guest spike.

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'guest-provision: %s\n' "$*" >&2
}

require_root() {
  [[ ${EUID} -eq 0 ]] || die "must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_env() {
  local name
  for name in "$@"; do
    [[ -n ${!name:-} ]] || die "required environment or manifest value is missing: ${name}"
  done
}

validate_manifest_key() {
  case "$1" in
    KUBERNETES_*|CONTAINERD_*|CRI_TOOLS_*|SANDBOX_IMAGE|NODE_IP|NODE_NAME|POD_CIDR|SERVICE_CIDR|CONTROL_PLANE_ENDPOINT|BOOTSTRAP_TOKEN|DISCOVERY_TOKEN_CA_CERT_HASH|JOIN_MANIFEST_PATH|KUBECTL_*|HELM_*|CILIUM_*|TRIVY_*|KUBE_BENCH_*|RUNSC_*|FALCO_*|DOCKER_*|GVISOR_*|CKS_NODE_ROLE)
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
  local manifest=${1:-}
  local line key value

  [[ -n "$manifest" ]] || return 0
  [[ -r "$manifest" ]] || die "manifest is not readable: ${manifest}"

  while IFS= read -r line || [[ -n "$line" ]]; do
    line=$(trim_space "$line")
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || die "invalid manifest line (expected KEY=VALUE): ${line}"
    key=$(trim_space "${line%%=*}")
    value=$(trim_space "${line#*=}")
    [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "invalid manifest key: ${key}"
    validate_manifest_key "$key" || die "manifest key is not allowlisted: ${key}"

    # Explicit process environment wins over copied manifest values.
    if [[ ! -v "$key" ]]; then
      printf -v "$key" '%s' "$value"
      export "$key"
    fi
  done < "$manifest"
}

load_default_manifests() {
  load_manifest "${CKS_VERSION_MANIFEST:-}"
}

assert_ubuntu_arm64() {
  local release arch
  [[ -r /etc/os-release ]] || die "/etc/os-release is missing"
  # shellcheck disable=SC1091
  source /etc/os-release
  release=${VERSION_ID:-}
  arch=$(dpkg --print-architecture)
  [[ ${ID:-} == ubuntu && "$release" == 24.04 ]] || die "requires Ubuntu 24.04; found ${ID:-unknown} ${release:-unknown}"
  [[ "$arch" == arm64 ]] || die "requires ARM64; found ${arch}"
}

validate_sha256() {
  [[ "$1" =~ ^[[:xdigit:]]{64}$ ]] || die "invalid SHA-256 value"
}

download_verified() {
  local name=$1 url=$2 sha256=$3 destination=$4
  validate_sha256 "$sha256"
  require_command curl
  require_command sha256sum

  log "downloading ${name}"
  if ! curl --fail --location --silent --show-error --retry 3 --output "$destination" "$url"; then
    die "download failed for ${name}: ${url}"
  fi
  if ! printf '%s  %s\n' "$sha256" "$destination" | sha256sum --check --status; then
    rm -f -- "$destination"
    die "checksum verification failed for ${name}"
  fi
}

install_downloaded_binary() {
  local name=$1 url=$2 sha256=$3 destination=$4
  local work artifact
  work=$(mktemp -d)
  artifact="${work}/${name}"
  download_verified "$name" "$url" "$sha256" "$artifact"
  install -D -m 0755 "$artifact" "$destination" || die "install failed for ${name}"
  rm -rf -- "$work"
}

install_tar_binary() {
  local name=$1 url=$2 sha256=$3 member=$4 destination=$5
  local work archive extracted
  work=$(mktemp -d)
  archive="${work}/${name}.tar.gz"
  download_verified "$name" "$url" "$sha256" "$archive"
  if ! tar --extract --gzip --file "$archive" --directory "$work" --no-same-owner -- "$member"; then
    rm -rf -- "$work"
    die "archive extraction failed for ${name} member ${member}"
  fi
  extracted="${work}/${member}"
  [[ -f "$extracted" ]] || die "archive member missing for ${name}: ${member}"
  install -D -m 0755 "$extracted" "$destination" || die "install failed for ${name}"
  rm -rf -- "$work"
}

install_verified_deb() {
  local name=$1 url=$2 sha256=$3
  local work package
  work=$(mktemp -d)
  package="${work}/${name}.deb"
  download_verified "$name" "$url" "$sha256" "$package"
  if ! dpkg --install "$package"; then
    DEBIAN_FRONTEND=noninteractive apt-get install --fix-broken --yes || die "dependency repair failed for ${name}"
    dpkg --install "$package" || die "package install failed for ${name}"
  fi
  rm -rf -- "$work"
}

install_text_if_changed() {
  local source=$1 destination=$2 mode=${3:-0644}
  if [[ -f "$destination" ]] && cmp --silent "$source" "$destination"; then
    return 0
  fi
  install -D -m "$mode" "$source" "$destination"
}

assert_output_contains() {
  local name=$1 expected=$2
  shift 2
  local output
  if ! output=$("$@" 2>&1); then
    die "${name} version check failed: ${output}"
  fi
  [[ "$output" == *"$expected"* ]] || die "${name} version mismatch: expected ${expected}; got ${output}"
}
