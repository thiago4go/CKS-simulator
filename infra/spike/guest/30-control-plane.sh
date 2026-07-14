#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_root
load_default_manifests
assert_ubuntu_arm64
require_env \
  KUBERNETES_VERSION NODE_IP NODE_NAME POD_CIDR SERVICE_CIDR CONTROL_PLANE_ENDPOINT \
  CILIUM_VERSION CILIUM_CLI_VERSION CILIUM_CLI_URL CILIUM_CLI_SHA256 CILIUM_CLI_ARCHIVE_MEMBER

readonly CRI_SOCKET='unix:///run/containerd/containerd.sock'
readonly join_manifest=${JOIN_MANIFEST_PATH:-/var/lib/cks-simulator/join.env}

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
  log "installing Cilium ${CILIUM_VERSION}"
  KUBECONFIG=/etc/kubernetes/admin.conf cilium install --version "$CILIUM_VERSION" --set ipam.mode=kubernetes
fi
KUBECONFIG=/etc/kubernetes/admin.conf cilium status --wait --wait-duration 10m

mkdir -p -- "$(dirname -- "$join_manifest")"
token=$(kubeadm token create) || die "failed to create kubeadm bootstrap token"
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
