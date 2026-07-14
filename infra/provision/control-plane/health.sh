#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_root
require_env CONTROL_PLANE_NAME CONTROL_PLANE_IP WORKER1_NAME WORKER1_IP WORKER2_NAME WORKER2_IP
require_command kubectl
require_command cilium
require_command python3

nodes_json=$(mktemp)
trap 'rm -f -- "$nodes_json"' EXIT
KUBECONFIG=/etc/kubernetes/admin.conf kubectl wait \
  --for=condition=Ready \
  "node/${CONTROL_PLANE_NAME}" \
  "node/${WORKER1_NAME}" \
  "node/${WORKER2_NAME}" \
  --timeout=10m
KUBECONFIG=/etc/kubernetes/admin.conf kubectl get nodes -o json >"$nodes_json"
python3 - "$nodes_json" \
  "$CONTROL_PLANE_NAME" "$CONTROL_PLANE_IP" \
  "$WORKER1_NAME" "$WORKER1_IP" \
  "$WORKER2_NAME" "$WORKER2_IP" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
expected = dict(zip(sys.argv[2::2], sys.argv[3::2]))
items = payload.get("items", [])
actual = {item.get("metadata", {}).get("name", ""): item for item in items}
if set(actual) != set(expected) or len(items) != 3:
    raise SystemExit(f"expected exactly three expected nodes; found {sorted(actual)!r}")
for name, expected_ip in expected.items():
    item = actual[name]
    conditions = item.get("status", {}).get("conditions", [])
    if not any(condition.get("type") == "Ready" and condition.get("status") == "True" for condition in conditions):
        raise SystemExit(f"node {name} is not Ready")
    addresses = item.get("status", {}).get("addresses", [])
    internal = [address.get("address") for address in addresses if address.get("type") == "InternalIP"]
    if internal != [expected_ip]:
        raise SystemExit(f"node {name} InternalIP mismatch: {internal!r}")
PY

KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system \
  rollout status daemonset/cilium --timeout=10m
KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system \
  rollout status daemonset/cilium-envoy --timeout=10m
KUBECONFIG=/etc/kubernetes/admin.conf cilium status --wait --wait-duration 10m
assert_exactly_one_cni
KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system \
  rollout status deployment/coredns --timeout=10m
KUBECONFIG=/etc/kubernetes/admin.conf kubectl get --raw=/readyz >/dev/null
log "exact three-node cluster, Cilium, Envoy, and CoreDNS health verified"
