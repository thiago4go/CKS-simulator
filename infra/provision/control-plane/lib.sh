#!/usr/bin/env bash

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'cluster-provision: %s\n' "$*" >&2
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
    [[ -n ${!name:-} ]] || die "required environment value is missing: ${name}"
  done
}

validate_dns_name() {
  local value=$1
  [[ ${#value} -le 63 ]] || die "DNS hostname exceeds 63 characters"
  [[ "$value" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "invalid exact DNS hostname: ${value}"
}

validate_control_plane_endpoint() {
  local expected_name=$1
  validate_dns_name "$expected_name"
  [[ ${CONTROL_PLANE_ENDPOINT:-} == "${expected_name}:6443" ]] \
    || die "controlPlaneEndpoint must be the exact stable hostname ${expected_name}:6443"
}

validate_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || die "invalid SHA-256 digest"
}

validate_networks() {
  local node_ip=$1 pod_cidr=$2 service_cidr=$3
  python3 -c '
import ipaddress, sys
node = ipaddress.ip_address(sys.argv[1])
pod = ipaddress.ip_network(sys.argv[2], strict=True)
service = ipaddress.ip_network(sys.argv[3], strict=True)
if node.version != 4 or pod.version != 4 or service.version != 4:
    raise SystemExit("only IPv4 node and cluster networks are supported")
if pod.overlaps(service):
    raise SystemExit("pod and service CIDRs overlap")
if node in pod or node in service:
    raise SystemExit("node IP overlaps a cluster CIDR")
' "$node_ip" "$pod_cidr" "$service_cidr" \
    || die "invalid or overlapping node/pod/service network configuration"
}

assert_exactly_one_cni() {
  local daemonsets
  daemonsets=$(mktemp)
  if ! KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system get daemonsets -o json >"$daemonsets"; then
    rm -f -- "$daemonsets"
    die "unable to inspect CNI daemonsets"
  fi
  if ! python3 - "$daemonsets" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
cni = []
for item in payload.get("items", []):
    volumes = item.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", [])
    if any(volume.get("hostPath", {}).get("path") == "/etc/cni/net.d" for volume in volumes):
        cni.append(item.get("metadata", {}).get("name", ""))
if cni != ["cilium"]:
    raise SystemExit(f"expected exactly Cilium as the CNI daemonset; found {sorted(cni)!r}")
PY
  then
    rm -f -- "$daemonsets"
    die "exactly-one-CNI health gate failed"
  fi
  rm -f -- "$daemonsets"
}

assert_no_foreign_cni() {
  local daemonsets
  daemonsets=$(mktemp)
  if ! KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system get daemonsets -o json >"$daemonsets"; then
    rm -f -- "$daemonsets"
    die "unable to inspect CNI daemonsets"
  fi
  if ! python3 - "$daemonsets" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
cni = []
for item in payload.get("items", []):
    volumes = item.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", [])
    if any(volume.get("hostPath", {}).get("path") == "/etc/cni/net.d" for volume in volumes):
        cni.append(item.get("metadata", {}).get("name", ""))
if any(name != "cilium" for name in cni):
    raise SystemExit(f"foreign CNI daemonset detected: {sorted(cni)!r}")
PY
  then
    rm -f -- "$daemonsets"
    die "foreign-CNI precondition failed"
  fi
  rm -f -- "$daemonsets"
}
