#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

[[ $# -eq 9 ]] || die "usage: install.sh MANIFEST ROLE LAB_ID HANDLE NODE_NAME NODE_IP POD_CIDR SERVICE_CIDR REQUIRED_PORTS"
readonly manifest=$1 role=$2 lab_id=$3 handle=$4 node_name=$5 node_ip=$6
readonly pod_cidr=$7 service_cidr=$8 required_ports=$9
readonly identity_marker=/etc/cks-simulator/identity.json
readonly cri_socket=unix:///run/containerd/containerd.sock

require_root
assert_secure_root_file "$manifest"
load_manifest "$manifest"
assert_ubuntu_arm64
validate_identity_args "$role" "$lab_id" "$handle" "$node_name" "$node_ip"
assert_guest_identity_marker "$identity_marker" "$role" "$lab_id" "$handle"
assert_node_hostname "$node_name"
assert_cgroup_v2

if [[ "$role" == candidate ]]; then
  [[ "$pod_cidr" == - && "$service_cidr" == - && "$required_ports" == - ]] ||
    die "candidate common provisioning does not accept cluster CIDRs or ports"
else
  validate_cluster_inputs "$role" "$node_ip" "$pod_cidr" "$service_cidr" "$required_ports"
  ownership_file=/etc/kubernetes/kubelet.conf
  [[ "$role" != control-plane ]] || ownership_file=/etc/kubernetes/admin.conf
  if [[ ! -e "$ownership_file" ]]; then
    assert_ports_available "$required_ports"
  fi
fi

export DEBIAN_FRONTEND=noninteractive
readonly ubuntu_sources=/etc/apt/sources.list.d/ubuntu.sources
[[ -f "$ubuntu_sources" && ! -L "$ubuntu_sources" ]] ||
  die "Ubuntu deb822 package source is missing or unsafe"
ubuntu_sources_https=$(mktemp)
sed 's#^URIs: http://ports\.ubuntu\.com/ubuntu-ports$#URIs: https://ports.ubuntu.com/ubuntu-ports#' \
  "$ubuntu_sources" >"$ubuntu_sources_https"
grep -Fqx 'URIs: https://ports.ubuntu.com/ubuntu-ports' "$ubuntu_sources_https" ||
  die "Ubuntu ports HTTPS source was not configured"
install_text_if_changed "$ubuntu_sources_https" "$ubuntu_sources" 0644
rm -f -- "$ubuntu_sources_https"

log "installing common Ubuntu packages"
apt-get update
apt-get install --yes ca-certificates curl gpg openssl conntrack socat ethtool ebtables iproute2 iptables apparmor apparmor-utils python3

if [[ "$role" == candidate ]]; then
  log "candidate common OS convergence complete"
  exit 0
fi

log "disabling swap and configuring Kubernetes kernel prerequisites"
swapoff --all
sed -ri '/^[^#].*[[:space:]]swap[[:space:]]/s/^/# cks-disabled-swap /' /etc/fstab
install -D -m 0644 /dev/null /etc/systemd/zram-generator.conf
systemctl mask systemd-zram-setup@.service >/dev/null
modules_file=$(mktemp)
cat > "$modules_file" <<'EOF'
overlay
br_netfilter
EOF
install_text_if_changed "$modules_file" /etc/modules-load.d/cks-kubernetes.conf 0644
rm -f -- "$modules_file"
modprobe overlay
modprobe br_netfilter

sysctl_file=$(mktemp)
cat > "$sysctl_file" <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
install_text_if_changed "$sysctl_file" /etc/sysctl.d/99-cks-kubernetes.conf 0644
rm -f -- "$sysctl_file"
sysctl --system >/dev/null

log "configuring authenticated package repositories"
docker_key=$(mktemp)
docker_keyring=$(mktemp)
download_verified docker-apt-key "$DOCKER_APT_KEY_URL" "$DOCKER_APT_KEY_SHA256" "$docker_key"
gpg --batch --yes --dearmor --output "$docker_keyring" "$docker_key"
install_text_if_changed "$docker_keyring" /etc/apt/keyrings/docker.gpg 0644
rm -f -- "$docker_key" "$docker_keyring"
docker_repository=$(mktemp)
printf 'deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] %s\n' "$DOCKER_APT_REPOSITORY" > "$docker_repository"
install_text_if_changed "$docker_repository" /etc/apt/sources.list.d/docker.list 0644
rm -f -- "$docker_repository"

kubernetes_key=$(mktemp)
kubernetes_keyring=$(mktemp)
download_verified kubernetes-apt-key "$KUBERNETES_APT_KEY_URL" "$KUBERNETES_APT_KEY_SHA256" "$kubernetes_key"
gpg --batch --yes --dearmor --output "$kubernetes_keyring" "$kubernetes_key"
install_text_if_changed "$kubernetes_keyring" /etc/apt/keyrings/kubernetes-apt-keyring.gpg 0644
rm -f -- "$kubernetes_key" "$kubernetes_keyring"
kubernetes_repository=$(mktemp)
printf 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] %s /\n' "$KUBERNETES_APT_REPOSITORY" > "$kubernetes_repository"
install_text_if_changed "$kubernetes_repository" /etc/apt/sources.list.d/kubernetes.list 0644
rm -f -- "$kubernetes_repository"

apt-get update
log "installing pinned container runtime and Kubernetes packages"
apt-get install --yes --allow-downgrades --allow-change-held-packages \
  "${CONTAINERD_PACKAGE_NAME}=${CONTAINERD_PACKAGE_VERSION}" \
  "kubelet=${KUBERNETES_PACKAGE_VERSION}" \
  "kubeadm=${KUBERNETES_PACKAGE_VERSION}" \
  "kubectl=${KUBERNETES_PACKAGE_VERSION}" \
  "cri-tools=${CRI_TOOLS_PACKAGE_VERSION}"
apt-mark hold "$CONTAINERD_PACKAGE_NAME" kubelet kubeadm kubectl cri-tools >/dev/null

containerd_config=$(mktemp)
cat > "$containerd_config" <<EOF
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
EOF
install_text_if_changed "$containerd_config" /etc/containerd/config.toml 0644
containerd_config_changed=$CKS_INSTALL_TEXT_CHANGED
rm -f -- "$containerd_config"

crictl_config=$(mktemp)
cat > "$crictl_config" <<EOF
runtime-endpoint: ${cri_socket}
image-endpoint: ${cri_socket}
timeout: 10
debug: false
EOF
install_text_if_changed "$crictl_config" /etc/crictl.yaml 0644
rm -f -- "$crictl_config"

kubelet_defaults=$(mktemp)
printf 'KUBELET_EXTRA_ARGS=--container-runtime-endpoint=%s --node-ip=%s\n' "$cri_socket" "$node_ip" > "$kubelet_defaults"
install_text_if_changed "$kubelet_defaults" /etc/default/kubelet 0644
rm -f -- "$kubelet_defaults"

systemctl enable containerd kubelet >/dev/null
if systemctl is-active --quiet containerd; then
  if [[ "$containerd_config_changed" == 1 ]]; then
    systemctl restart containerd
  fi
else
  systemctl start containerd
fi
systemctl is-active --quiet containerd || die "containerd did not become active"
assert_swap_disabled /proc/swaps /etc/fstab /etc/systemd/zram-generator.conf
assert_required_modules
assert_forwarding_sysctls
assert_containerd_configuration /etc/containerd/config.toml /etc/crictl.yaml "$SANDBOX_IMAGE"
assert_kubelet_defaults "$node_ip"
assert_package_version "$CONTAINERD_PACKAGE_NAME" "$CONTAINERD_PACKAGE_VERSION"
assert_package_version kubelet "$KUBERNETES_PACKAGE_VERSION"
assert_package_version kubeadm "$KUBERNETES_PACKAGE_VERSION"
assert_package_version kubectl "$KUBERNETES_PACKAGE_VERSION"
assert_package_version cri-tools "$CRI_TOOLS_PACKAGE_VERSION"
assert_output_contains containerd "$CONTAINERD_RUNTIME_VERSION" containerd --version
assert_output_contains kubeadm "$KUBERNETES_VERSION" kubeadm version --output short
crictl --runtime-endpoint "$cri_socket" info >/dev/null || die "containerd CRI probe failed"
log "Kubernetes node common convergence complete"
