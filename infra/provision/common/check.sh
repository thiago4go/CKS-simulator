#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

[[ $# -eq 9 ]] || die "usage: check.sh MANIFEST ROLE LAB_ID HANDLE NODE_NAME NODE_IP POD_CIDR SERVICE_CIDR REQUIRED_PORTS"
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
    die "candidate check does not accept cluster CIDRs or ports"
  printf 'common-check: candidate passed\n'
  exit 0
fi

validate_cluster_inputs "$role" "$node_ip" "$pod_cidr" "$service_cidr" "$required_ports"
ownership_file=/etc/kubernetes/kubelet.conf
[[ "$role" != control-plane ]] || ownership_file=/etc/kubernetes/admin.conf
if [[ ! -e "$ownership_file" ]]; then
  assert_ports_available "$required_ports"
fi
assert_swap_disabled /proc/swaps /etc/fstab /etc/systemd/zram-generator.conf
assert_required_modules
assert_forwarding_sysctls
assert_containerd_configuration /etc/containerd/config.toml /etc/crictl.yaml "$SANDBOX_IMAGE"
assert_kubelet_defaults "$node_ip"
systemctl is-active --quiet containerd || die "containerd is not active"
assert_package_version "$CONTAINERD_PACKAGE_NAME" "$CONTAINERD_PACKAGE_VERSION"
assert_package_version kubelet "$KUBERNETES_PACKAGE_VERSION"
assert_package_version kubeadm "$KUBERNETES_PACKAGE_VERSION"
assert_package_version kubectl "$KUBERNETES_PACKAGE_VERSION"
assert_package_version cri-tools "$CRI_TOOLS_PACKAGE_VERSION"
assert_output_contains containerd "$CONTAINERD_RUNTIME_VERSION" containerd --version
assert_output_contains kubeadm "$KUBERNETES_VERSION" kubeadm version --output short
crictl --runtime-endpoint "$cri_socket" info >/dev/null || die "containerd CRI probe failed"
printf 'common-check: kubernetes-node passed\n'
