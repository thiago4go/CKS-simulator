#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_root
load_default_manifests
load_manifest "${CKS_JOIN_MANIFEST:-}"
assert_ubuntu_arm64
require_env NODE_NAME CONTROL_PLANE_ENDPOINT BOOTSTRAP_TOKEN DISCOVERY_TOKEN_CA_CERT_HASH

readonly CRI_SOCKET='unix:///run/containerd/containerd.sock'
[[ "$BOOTSTRAP_TOKEN" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || die "invalid kubeadm bootstrap token format"
[[ "$DISCOVERY_TOKEN_CA_CERT_HASH" =~ ^sha256:[[:xdigit:]]{64}$ ]] || die "invalid discovery CA hash format"

if [[ ! -s /etc/kubernetes/kubelet.conf ]]; then
  log "joining worker ${NODE_NAME} to ${CONTROL_PLANE_ENDPOINT}"
  kubeadm join "$CONTROL_PLANE_ENDPOINT" \
    --token "$BOOTSTRAP_TOKEN" \
    --discovery-token-ca-cert-hash "$DISCOVERY_TOKEN_CA_CERT_HASH" \
    --cri-socket "$CRI_SOCKET" \
    --node-name "$NODE_NAME"
else
  log "existing kubeadm worker membership detected; skipping join"
fi

systemctl enable kubelet >/dev/null
systemctl restart kubelet
systemctl is-active --quiet kubelet || die "kubelet did not become active"
log "worker join complete"
