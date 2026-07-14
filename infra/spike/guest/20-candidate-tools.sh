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
  KUBECTL_VERSION KUBECTL_URL KUBECTL_SHA256 \
  HELM_VERSION HELM_URL HELM_SHA256 HELM_ARCHIVE_MEMBER \
  CILIUM_CLI_VERSION CILIUM_CLI_URL CILIUM_CLI_SHA256 CILIUM_CLI_ARCHIVE_MEMBER \
  TRIVY_VERSION TRIVY_URL TRIVY_SHA256 TRIVY_ARCHIVE_MEMBER \
  KUBE_BENCH_VERSION KUBE_BENCH_URL KUBE_BENCH_SHA256 KUBE_BENCH_ARCHIVE_MEMBER

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes ca-certificates curl openssl jq git vim-tiny less bash-completion openssh-client tar gzip

install_downloaded_binary kubectl "$KUBECTL_URL" "$KUBECTL_SHA256" /usr/local/bin/kubectl
install_tar_binary helm "$HELM_URL" "$HELM_SHA256" "$HELM_ARCHIVE_MEMBER" /usr/local/bin/helm
install_tar_binary cilium "$CILIUM_CLI_URL" "$CILIUM_CLI_SHA256" "$CILIUM_CLI_ARCHIVE_MEMBER" /usr/local/bin/cilium
install_tar_binary trivy "$TRIVY_URL" "$TRIVY_SHA256" "$TRIVY_ARCHIVE_MEMBER" /usr/local/bin/trivy
install_tar_binary kube-bench "$KUBE_BENCH_URL" "$KUBE_BENCH_SHA256" "$KUBE_BENCH_ARCHIVE_MEMBER" /usr/local/bin/kube-bench

assert_output_contains kubectl "$KUBECTL_VERSION" kubectl version --client
assert_output_contains helm "$HELM_VERSION" helm version --short
assert_output_contains cilium "$CILIUM_CLI_VERSION" cilium version --client
assert_output_contains trivy "$TRIVY_VERSION" trivy --version
assert_output_contains kube-bench "$KUBE_BENCH_VERSION" kube-bench version

log "downloading the Trivy vulnerability database"
if ! trivy image --download-db-only; then
  die "Trivy database download failed"
fi
log "candidate tool provisioning complete"
