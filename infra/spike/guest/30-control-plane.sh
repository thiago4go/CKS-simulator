#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_root
readonly MODE=${1:-bootstrap}
readonly join_manifest=${JOIN_MANIFEST_PATH:-/var/lib/cks-simulator/join.env}

if [[ "$MODE" == revoke-token ]]; then
  [[ -s "$join_manifest" ]] || die "join manifest is missing during token revocation"
  token=$(awk -F= '$1 == "BOOTSTRAP_TOKEN" {print $2}' "$join_manifest")
  [[ "$token" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || die "join manifest has no valid bootstrap token"
  kubeadm token delete "$token" >/dev/null
  rm -f -- "$join_manifest"
  log "bootstrap token revoked and join manifest removed"
  exit 0
fi
[[ "$MODE" == bootstrap ]] || die "unknown control-plane mode: $MODE"

load_default_manifests
assert_ubuntu_arm64
require_env \
  KUBERNETES_VERSION NODE_IP NODE_NAME POD_CIDR SERVICE_CIDR CONTROL_PLANE_ENDPOINT \
  CILIUM_VERSION CILIUM_CLI_VERSION CILIUM_CLI_URL CILIUM_CLI_SHA256 CILIUM_CLI_ARCHIVE_MEMBER \
  CILIUM_CHART_URL CILIUM_CHART_SHA256

readonly CRI_SOCKET='unix:///run/containerd/containerd.sock'

if [[ ! -s /etc/kubernetes/admin.conf ]]; then
  log "initializing the kubeadm control plane"
  kubeadm init \
    --kubernetes-version "$KUBERNETES_VERSION" \
    --apiserver-advertise-address "$NODE_IP" \
    --control-plane-endpoint "$CONTROL_PLANE_ENDPOINT" \
    --pod-network-cidr "$POD_CIDR" \
    --service-cidr "$SERVICE_CIDR" \
    --cri-socket "$CRI_SOCKET" \
    --node-name "$NODE_NAME"
else
  log "existing kubeadm control plane detected; skipping init"
  kubeadm certs check-expiration >/dev/null || die "existing control-plane certificates are unhealthy"
fi

if ! command -v cilium >/dev/null 2>&1; then
  install_tar_binary cilium "$CILIUM_CLI_URL" "$CILIUM_CLI_SHA256" "$CILIUM_CLI_ARCHIVE_MEMBER" /usr/local/bin/cilium
fi
assert_output_contains cilium "$CILIUM_CLI_VERSION" cilium version --client
if ! KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system get daemonset cilium >/dev/null 2>&1; then
  chart_root=/var/lib/cks-simulator/charts
  chart_dir=${chart_root}/cilium
  chart_work=$(mktemp -d)
  chart_archive=${chart_work}/cilium.tgz
  download_verified cilium-chart "$CILIUM_CHART_URL" "$CILIUM_CHART_SHA256" "$chart_archive"
  rm -rf -- "$chart_dir"
  mkdir -p -- "$chart_root"
  tar --extract --gzip --file "$chart_archive" --directory "$chart_root" \
    --no-same-owner --no-same-permissions
  rm -rf -- "$chart_work"
  [[ -f "$chart_dir/Chart.yaml" ]] || die "verified Cilium chart has no Chart.yaml"
  chart_version=$(awk '$1 == "version:" {print $2; exit}' "$chart_dir/Chart.yaml")
  [[ "$chart_version" == "$CILIUM_VERSION" ]] || die "Cilium chart version mismatch: ${chart_version:-missing}"
  log "installing Cilium ${CILIUM_VERSION}"
  KUBECONFIG=/etc/kubernetes/admin.conf cilium install \
    --chart-directory "$chart_dir" \
    --version "$CILIUM_VERSION" \
    --set ipam.mode=kubernetes
fi
KUBECONFIG=/etc/kubernetes/admin.conf cilium status --wait --wait-duration 10m

mkdir -p -- "$(dirname -- "$join_manifest")"
token=$(kubeadm token create --ttl 15m) || die "failed to create kubeadm bootstrap token"
ca_hash=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | sha256sum \
  | awk '{print $1}')
[[ "$ca_hash" =~ ^[[:xdigit:]]{64}$ ]] || die "failed to derive discovery CA hash"

join_tmp=$(mktemp)
printf 'CONTROL_PLANE_ENDPOINT=%s\n' "$CONTROL_PLANE_ENDPOINT" > "$join_tmp"
printf 'BOOTSTRAP_TOKEN=%s\n' "$token" >> "$join_tmp"
printf 'DISCOVERY_TOKEN_CA_CERT_HASH=sha256:%s\n' "$ca_hash" >> "$join_tmp"
install -D -m 0600 "$join_tmp" "$join_manifest"
rm -f -- "$join_tmp"

KUBECONFIG=/etc/kubernetes/admin.conf kubectl get --raw=/readyz >/dev/null || die "control-plane readyz probe failed"
log "control plane ready; root-only join fields written to ${join_manifest}"
