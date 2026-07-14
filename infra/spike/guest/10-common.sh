#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_root
load_default_manifests
assert_ubuntu_arm64
require_env \
  KUBERNETES_MINOR KUBERNETES_VERSION KUBERNETES_PACKAGE_VERSION \
  KUBERNETES_APT_KEY_URL KUBERNETES_APT_KEY_SHA256 KUBERNETES_APT_REPOSITORY \
  CONTAINERD_PACKAGE_VERSION CONTAINERD_RUNTIME_VERSION CRI_TOOLS_PACKAGE_VERSION SANDBOX_IMAGE \
  DOCKER_APT_KEY_URL DOCKER_APT_KEY_SHA256 DOCKER_APT_REPOSITORY

readonly CRI_SOCKET='unix:///run/containerd/containerd.sock'
readonly containerd_package=${CONTAINERD_PACKAGE_NAME:-containerd}
[[ "$containerd_package" =~ ^[a-z0-9][a-z0-9.+-]*$ ]] || die "invalid containerd package name"

log "installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes ca-certificates curl gpg openssl conntrack socat ethtool ebtables iproute2 iptables apparmor apparmor-utils

log "configuring the authenticated Docker repository for containerd.io"
docker_key_download=$(mktemp)
docker_keyring_tmp=$(mktemp)
download_verified docker-apt-key "$DOCKER_APT_KEY_URL" "$DOCKER_APT_KEY_SHA256" "$docker_key_download"
gpg --batch --yes --dearmor --output "$docker_keyring_tmp" "$docker_key_download"
install -D -m 0644 "$docker_keyring_tmp" /etc/apt/keyrings/docker.gpg
rm -f -- "$docker_key_download" "$docker_keyring_tmp"
printf 'deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] %s\n' "$DOCKER_APT_REPOSITORY" > /etc/apt/sources.list.d/docker.list

log "disabling swap and configuring kernel prerequisites"
swapoff --all
sed -ri '/^[^#].*[[:space:]]swap[[:space:]]/s/^/# cks-disabled-swap /' /etc/fstab
cat > /etc/modules-load.d/cks-kubernetes.conf <<'EOF'
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter
cat > /etc/sysctl.d/99-cks-kubernetes.conf <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null

log "configuring the pinned Kubernetes package repository"
key_download=$(mktemp)
keyring_tmp=$(mktemp)
download_verified kubernetes-apt-key "$KUBERNETES_APT_KEY_URL" "$KUBERNETES_APT_KEY_SHA256" "$key_download"
gpg --batch --yes --dearmor --output "$keyring_tmp" "$key_download"
install -D -m 0644 "$keyring_tmp" /etc/apt/keyrings/kubernetes-apt-keyring.gpg
rm -f -- "$key_download" "$keyring_tmp"
printf 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] %s /\n' "$KUBERNETES_APT_REPOSITORY" > /etc/apt/sources.list.d/kubernetes.list
apt-get update

log "installing pinned containerd and Kubernetes packages"
apt-get install --yes \
  "${containerd_package}=${CONTAINERD_PACKAGE_VERSION}" \
  "kubelet=${KUBERNETES_PACKAGE_VERSION}" \
  "kubeadm=${KUBERNETES_PACKAGE_VERSION}" \
  "kubectl=${KUBERNETES_PACKAGE_VERSION}" \
  "cri-tools=${CRI_TOOLS_PACKAGE_VERSION}"
apt-mark hold "$containerd_package" kubelet kubeadm kubectl cri-tools >/dev/null

log "writing an explicit containerd 2.x CRI configuration"
mkdir -p /etc/containerd
cat > /etc/containerd/config.toml <<EOF
version = 3

[grpc]
  address = "/run/containerd/containerd.sock"

[plugins.'io.containerd.cri.v1.images'.pinned_images]
  sandbox = "${SANDBOX_IMAGE}"

[plugins.'io.containerd.cri.v1.runtime'.containerd]
  default_runtime_name = "runc"

  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
    runtime_type = "io.containerd.runc.v2"

    [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
      SystemdCgroup = true

  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]
    runtime_type = "io.containerd.runsc.v1"

    [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc.options]
      TypeUrl = "io.containerd.runsc.v1.options"
      ConfigPath = "/etc/containerd/runsc.toml"
EOF

cat > /etc/crictl.yaml <<EOF
runtime-endpoint: ${CRI_SOCKET}
image-endpoint: ${CRI_SOCKET}
timeout: 10
debug: false
EOF

node_args="--container-runtime-endpoint=${CRI_SOCKET}"
if [[ -n ${NODE_IP:-} ]]; then
  node_args+=" --node-ip=${NODE_IP}"
fi
printf 'KUBELET_EXTRA_ARGS=%q\n' "$node_args" > /etc/default/kubelet

systemctl enable containerd kubelet >/dev/null
systemctl restart containerd
systemctl is-active --quiet containerd || die "containerd did not become active"
assert_output_contains containerd "$CONTAINERD_RUNTIME_VERSION" containerd --version
assert_output_contains kubeadm "$KUBERNETES_VERSION" kubeadm version --output short
crictl --runtime-endpoint "$CRI_SOCKET" info >/dev/null || die "containerd CRI probe failed"
log "common Kubernetes node provisioning complete"
