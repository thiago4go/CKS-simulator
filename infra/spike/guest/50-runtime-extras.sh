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
  CKS_NODE_ROLE \
  FALCO_VERSION FALCO_DEB_URL FALCO_DEB_SHA256 \
  TRIVY_VERSION TRIVY_URL TRIVY_SHA256 TRIVY_ARCHIVE_MEMBER \
  KUBE_BENCH_VERSION KUBE_BENCH_URL KUBE_BENCH_SHA256 KUBE_BENCH_ARCHIVE_MEMBER
[[ "$CKS_NODE_ROLE" == worker1 || "$CKS_NODE_ROLE" == worker2 ]] || die "CKS_NODE_ROLE must be worker1 or worker2"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes ca-certificates curl tar gzip jq

install_tar_binary trivy "$TRIVY_URL" "$TRIVY_SHA256" "$TRIVY_ARCHIVE_MEMBER" /usr/local/bin/trivy
install_tar_binary kube-bench "$KUBE_BENCH_URL" "$KUBE_BENCH_SHA256" "$KUBE_BENCH_ARCHIVE_MEMBER" /usr/local/bin/kube-bench
assert_output_contains trivy "$TRIVY_VERSION" trivy --version
assert_output_contains kube-bench "$KUBE_BENCH_VERSION" kube-bench version
trivy image --download-db-only || die "Trivy database download failed"

install_verified_deb falco "$FALCO_DEB_URL" "$FALCO_DEB_SHA256"
assert_output_contains falco "$FALCO_VERSION" falco --version
mkdir -p /etc/falco/config.d /etc/systemd/system/cks-falco.service.d
cat > /etc/falco/config.d/cks-modern-ebpf.yaml <<'EOF'
engine:
  kind: modern_ebpf
EOF
cat > /etc/systemd/system/cks-falco.service <<'EOF'
[Unit]
Description=CKS Falco modern eBPF probe service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml -o engine.kind=modern_ebpf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cks-falco.service
systemctl is-active --quiet cks-falco.service || die "Falco modern eBPF service did not become active"

if [[ "$CKS_NODE_ROLE" == worker1 ]]; then
  require_env RUNSC_VERSION RUNSC_URL RUNSC_SHA256 CONTAINERD_SHIM_RUNSC_URL CONTAINERD_SHIM_RUNSC_SHA256
  command -v dockerd >/dev/null 2>&1 && die "Docker must not be installed on worker1"
  install_downloaded_binary runsc "$RUNSC_URL" "$RUNSC_SHA256" /usr/local/bin/runsc
  install_downloaded_binary containerd-shim-runsc-v1 "$CONTAINERD_SHIM_RUNSC_URL" "$CONTAINERD_SHIM_RUNSC_SHA256" /usr/local/bin/containerd-shim-runsc-v1
  assert_output_contains runsc "$RUNSC_VERSION" runsc --version
  cat > /etc/containerd/runsc.toml <<'EOF'
[runsc_config]
  platform = "systrap"
EOF
  systemctl restart containerd
  systemctl is-active --quiet containerd || die "containerd failed after gVisor configuration"
fi

if [[ "$CKS_NODE_ROLE" == worker2 ]]; then
  require_env \
    DOCKER_APT_KEY_URL DOCKER_APT_KEY_SHA256 DOCKER_APT_REPOSITORY \
    DOCKER_CE_VERSION DOCKER_CLI_VERSION DOCKER_CONTAINERD_IO_VERSION \
    DOCKER_BUILDX_VERSION DOCKER_COMPOSE_VERSION
  docker_key=$(mktemp)
  docker_keyring=$(mktemp)
  download_verified docker-apt-key "$DOCKER_APT_KEY_URL" "$DOCKER_APT_KEY_SHA256" "$docker_key"
  gpg --batch --yes --dearmor --output "$docker_keyring" "$docker_key"
  install -D -m 0644 "$docker_keyring" /etc/apt/keyrings/docker.gpg
  rm -f -- "$docker_key" "$docker_keyring"
  printf 'deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.gpg] %s\n' "$DOCKER_APT_REPOSITORY" > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install --yes \
    "docker-ce=${DOCKER_CE_VERSION}" \
    "docker-ce-cli=${DOCKER_CLI_VERSION}" \
    "containerd.io=${DOCKER_CONTAINERD_IO_VERSION}" \
    "docker-buildx-plugin=${DOCKER_BUILDX_VERSION}" \
    "docker-compose-plugin=${DOCKER_COMPOSE_VERSION}"
  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "ip-forward-no-drop": true
}
EOF
  systemctl enable --now docker
  systemctl restart containerd
  systemctl is-active --quiet docker || die "Docker did not become active on worker2"
  systemctl is-active --quiet containerd || die "system containerd CRI was disrupted by Docker installation"
  crictl --runtime-endpoint unix:///run/containerd/containerd.sock info >/dev/null || die "Kubernetes CRI no longer points to system containerd"
fi

log "runtime extras complete for ${CKS_NODE_ROLE}"
