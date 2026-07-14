#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

readonly REQUIRED_KUBERNETES_VERSION="v1.35.6"
readonly REQUIRED_CILIUM_VERSION="1.19.5"
readonly REQUIRED_CILIUM_CLI_VERSION="v0.19.5"
readonly REQUIRED_CILIUM_CLI_URL="https://github.com/cilium/cilium-cli/releases/download/v0.19.5/cilium-linux-arm64.tar.gz"
readonly REQUIRED_CILIUM_CLI_SHA256="5498defafc248160ca44a38be39f5ba090769ef112f9ec34a19e72dfa7e7eb25"
readonly REQUIRED_CILIUM_CHART_URL="https://helm.cilium.io/cilium-1.19.5.tgz"
readonly REQUIRED_CILIUM_CHART_SHA256="56b60445a2c650b387ce2edb13cfd8d83219a9da693b0523915dba8be451a29e"
readonly CRI_SOCKET='unix:///run/containerd/containerd.sock'

require_root
require_env KUBERNETES_VERSION NODE_IP NODE_NAME POD_CIDR SERVICE_CIDR CONTROL_PLANE_ENDPOINT \
  CILIUM_VERSION CILIUM_CLI_VERSION CILIUM_CLI_URL CILIUM_CLI_SHA256 \
  CILIUM_CHART_URL CILIUM_CHART_SHA256
require_command kubeadm
require_command kubectl
require_command python3
require_command curl
require_command sha256sum
require_command tar

[[ "$KUBERNETES_VERSION" == "$REQUIRED_KUBERNETES_VERSION" ]] \
  || die "Kubernetes version must be pinned to ${REQUIRED_KUBERNETES_VERSION}"
[[ "$CILIUM_VERSION" == "$REQUIRED_CILIUM_VERSION" ]] \
  || die "Cilium version must be pinned to ${REQUIRED_CILIUM_VERSION}"
[[ "$CILIUM_CLI_VERSION" == "$REQUIRED_CILIUM_CLI_VERSION" ]] \
  || die "Cilium CLI version must be pinned to ${REQUIRED_CILIUM_CLI_VERSION}"
[[ "$CILIUM_CLI_URL" == "$REQUIRED_CILIUM_CLI_URL" ]] \
  || die "Cilium CLI URL does not match the pinned ARM64 release"
[[ "$CILIUM_CLI_SHA256" == "$REQUIRED_CILIUM_CLI_SHA256" ]] \
  || die "Cilium CLI digest does not match the pinned ARM64 release"
[[ "$CILIUM_CHART_URL" == "$REQUIRED_CILIUM_CHART_URL" ]] \
  || die "Cilium chart URL does not match the pinned release"
[[ "$CILIUM_CHART_SHA256" == "$REQUIRED_CILIUM_CHART_SHA256" ]] \
  || die "Cilium chart digest does not match the pinned release"
validate_sha256 "$CILIUM_CHART_SHA256"
validate_sha256 "$CILIUM_CLI_SHA256"
validate_control_plane_endpoint "$NODE_NAME"
validate_networks "$NODE_IP" "$POD_CIDR" "$SERVICE_CIDR"

wait_for_readyz() {
  local attempt
  for attempt in $(seq 1 120); do
    if KUBECONFIG=/etc/kubernetes/admin.conf kubectl get --raw=/readyz >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  die "control-plane readyz did not become healthy within 10 minutes"
}

verify_existing_control_plane() {
  local server node_ip kubelet_version controller_json
  [[ -f /etc/kubernetes/admin.conf && ! -L /etc/kubernetes/admin.conf ]] \
    || die "existing admin kubeconfig is not a regular trusted file"
  kubeadm certs check-expiration >/dev/null || die "existing control-plane certificates are unhealthy"
  server=$(KUBECONFIG=/etc/kubernetes/admin.conf kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  [[ "$server" == "https://${CONTROL_PLANE_ENDPOINT}" ]] \
    || die "existing API server endpoint mismatch: ${server:-missing}"
  wait_for_readyz
  node_ip=$(KUBECONFIG=/etc/kubernetes/admin.conf kubectl get node "$NODE_NAME" \
    -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
  [[ "$node_ip" == "$NODE_IP" ]] || die "existing control-plane node IP mismatch"
  kubelet_version=$(KUBECONFIG=/etc/kubernetes/admin.conf kubectl get node "$NODE_NAME" \
    -o jsonpath='{.status.nodeInfo.kubeletVersion}')
  [[ "$kubelet_version" == "$KUBERNETES_VERSION" ]] || die "existing control-plane Kubernetes version mismatch"
  controller_json=$(mktemp)
  KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system get pods \
    -l component=kube-controller-manager -o json >"$controller_json"
  python3 - "$controller_json" "$POD_CIDR" "$SERVICE_CIDR" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
items = payload.get("items", [])
if len(items) != 1:
    raise SystemExit("expected exactly one kube-controller-manager pod")
containers = items[0].get("spec", {}).get("containers", [])
if len(containers) != 1:
    raise SystemExit("expected one kube-controller-manager container")
arguments = set(containers[0].get("command", []) + containers[0].get("args", []))
for expected in (f"--cluster-cidr={sys.argv[2]}", f"--service-cluster-ip-range={sys.argv[3]}"):
    if expected not in arguments:
        raise SystemExit(f"existing control-plane network configuration mismatch: {expected}")
PY
  rm -f -- "$controller_json"
}

download_verified_chart() {
  local url=$1 digest=$2 destination=$3
  validate_sha256 "$digest"
  curl --fail --location --silent --show-error --retry 3 --output "$destination" "$url" \
    || die "Cilium chart download failed"
  printf '%s  %s\n' "$digest" "$destination" | sha256sum --check --status \
    || die "Cilium chart checksum verification failed"
}

install_verified_cilium_cli() {
  local work archive extracted temporary observed
  work=$(mktemp -d)
  archive="${work}/cilium-cli.tgz"
  extracted="${work}/extract"
  mkdir -p -- "$extracted"
  curl --fail --location --silent --show-error --retry 3 --output "$archive" "$CILIUM_CLI_URL" \
    || die "Cilium CLI download failed"
  printf '%s  %s\n' "$CILIUM_CLI_SHA256" "$archive" | sha256sum --check --status \
    || die "Cilium CLI checksum verification failed"
  tar --extract --gzip --file "$archive" --directory "$extracted" \
    --no-same-owner --no-same-permissions cilium
  [[ -f "${extracted}/cilium" && ! -L "${extracted}/cilium" ]] \
    || die "verified Cilium CLI archive has no regular cilium binary"
  temporary=$(mktemp /usr/local/bin/.cks-cilium.XXXXXX)
  install -o root -g root -m 0755 "${extracted}/cilium" "$temporary"
  mv -fT -- "$temporary" /usr/local/bin/cilium
  rm -rf -- "$work"
  observed=$(cilium version --client 2>&1)
  [[ "$observed" == *"${CILIUM_CLI_VERSION}"* ]] || die "installed Cilium CLI version mismatch"
}

install_cilium() {
  local chart_work chart_archive chart_root chart_dir chart_version release_records release_name ipam_mode
  assert_no_foreign_cni
  chart_work=$(mktemp -d)
  chart_archive="${chart_work}/cilium.tgz"
  chart_root="${chart_work}/chart"
  mkdir -p -- "$chart_root"
  download_verified_chart "$CILIUM_CHART_URL" "$CILIUM_CHART_SHA256" "$chart_archive"
  tar --extract --gzip --file "$chart_archive" --directory "$chart_root" \
    --no-same-owner --no-same-permissions
  chart_dir="${chart_root}/cilium"
  [[ -f "${chart_dir}/Chart.yaml" && ! -L "${chart_dir}/Chart.yaml" ]] \
    || die "verified Cilium chart has no regular Chart.yaml"
  chart_version=$(awk '$1 == "version:" {print $2; exit}' "${chart_dir}/Chart.yaml")
  [[ "$chart_version" == "$CILIUM_VERSION" ]] || die "verified Cilium chart version mismatch"

  release_records=$(mktemp)
  KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system get secrets \
    -l owner=helm,name=cilium -o name >"$release_records"
  while IFS= read -r release_name; do
    [[ "$release_name" =~ ^secret/sh\.helm\.release\.v1\.cilium\.v[1-9][0-9]*$ ]] \
      || die "Cilium Helm release history contains an unexpected record"
  done <"$release_records"
  if [[ ! -s "$release_records" ]]; then
    if KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system get \
      daemonset/cilium daemonset/cilium-envoy deployment/cilium-operator \
      --ignore-not-found -o name | grep -q .; then
      die "Cilium resources exist without an owned Helm release"
    fi
    KUBECONFIG=/etc/kubernetes/admin.conf cilium install \
      --chart-directory "$chart_dir" \
      --version "$CILIUM_VERSION" \
      --set ipam.mode=kubernetes
  else
    KUBECONFIG=/etc/kubernetes/admin.conf cilium upgrade \
      --chart-directory "$chart_dir" \
      --version "$CILIUM_VERSION" \
      --set ipam.mode=kubernetes
  fi
  rm -f -- "$release_records"
  rm -rf -- "$chart_work"
  KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system \
    rollout status daemonset/cilium --timeout=10m
  KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system \
    rollout status daemonset/cilium-envoy --timeout=10m
  KUBECONFIG=/etc/kubernetes/admin.conf cilium status --wait --wait-duration 10m
  ipam_mode=$(KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system \
    get configmap cilium-config -o jsonpath='{.data.ipam}')
  [[ "$ipam_mode" == "kubernetes" ]] || die "Cilium IPAM mode does not match the pinned configuration"
  assert_exactly_one_cni
}

revoke_initial_token() {
  local attempt token_id
  [[ -n "${initial_token:-}" ]] || return 0
  token_id=${initial_token%%.*}
  if [[ -f /etc/kubernetes/admin.conf && ! -L /etc/kubernetes/admin.conf ]]; then
    for attempt in $(seq 1 60); do
      if KUBECONFIG=/etc/kubernetes/admin.conf kubectl get --raw=/readyz >/dev/null 2>&1; then
        KUBECONFIG=/etc/kubernetes/admin.conf kubeadm token delete "$token_id" \
          >/dev/null 2>&1 || return 1
        unset initial_token
        return 0
      fi
      sleep 2
    done
    return 1
  fi
  unset initial_token
}

cleanup_initial_token_on_exit() {
  local status=$?
  trap - EXIT
  if ! revoke_initial_token; then
    log "initial bootstrap token revocation failed"
    status=1
  fi
  exit "$status"
}

revoke_all_bootstrap_tokens() {
  local names secret_name
  names=$(mktemp)
  KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system get secrets \
    -o 'go-template={{range .items}}{{if eq .type "bootstrap.kubernetes.io/token"}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' \
    >"$names" || die "unable to inspect bootstrap token secrets"
  while IFS= read -r secret_name; do
    [[ "$secret_name" =~ ^bootstrap-token-[a-z0-9]{6}$ ]] \
      || die "unexpected bootstrap token secret name"
    KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system \
      delete secret "$secret_name" --wait=true >/dev/null
  done < "$names"
  rm -f -- "$names"
}

if ! command -v cilium >/dev/null 2>&1 \
  || [[ "$(cilium version --client 2>&1 || true)" != *"${CILIUM_CLI_VERSION}"* ]]; then
  install_verified_cilium_cli
fi
require_command cilium

if [[ -e /etc/kubernetes/admin.conf || -L /etc/kubernetes/admin.conf ]]; then
  log "verifying the existing kubeadm control plane before replay"
  verify_existing_control_plane
else
  log "initializing Kubernetes ${KUBERNETES_VERSION} at ${CONTROL_PLANE_ENDPOINT}"
  initial_token=$(kubeadm token generate)
  [[ "$initial_token" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] \
    || die "kubeadm generated an invalid initial token"
  trap cleanup_initial_token_on_exit EXIT
  kubeadm init --config /dev/stdin --skip-token-print <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
bootstrapTokens:
  - token: "${initial_token}"
    ttl: "15m"
    usages:
      - authentication
      - signing
    groups:
      - system:bootstrappers:kubeadm:default-node-token
localAPIEndpoint:
  advertiseAddress: "${NODE_IP}"
  bindPort: 6443
nodeRegistration:
  criSocket: "${CRI_SOCKET}"
  name: "${NODE_NAME}"
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: "${KUBERNETES_VERSION}"
controlPlaneEndpoint: "${CONTROL_PLANE_ENDPOINT}"
networking:
  podSubnet: "${POD_CIDR}"
  serviceSubnet: "${SERVICE_CIDR}"
EOF
  wait_for_readyz
  revoke_initial_token
  trap - EXIT
fi

cilium_version=$(cilium version --client 2>&1)
[[ "$cilium_version" == *"${CILIUM_CLI_VERSION}"* ]] || die "Cilium CLI version mismatch"
install_cilium
revoke_all_bootstrap_tokens
log "control-plane and pinned Cilium convergence complete"
