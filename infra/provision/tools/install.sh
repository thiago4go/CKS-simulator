#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

readonly ROLE=${1:-}
readonly REQUIRED_HELM_VERSION='3.21.3'
readonly REQUIRED_CILIUM_CLI_VERSION='0.19.5'
readonly REQUIRED_ETCDCTL_VERSION='3.6.6'
readonly REQUIRED_KUBE_BENCH_VERSION='0.15.6'
readonly REQUIRED_GVISOR_VERSION='release-20260706.0'
readonly REQUIRED_DOCKER_VERSION='29.6.1'

require_root
load_tools_inputs
for command in curl sha256sum sha512sum tar python3 install cmp; do
  require_command "$command"
done

install_tar_binary() {
  local name=$1 url=$2 digest=$3 installed_digest=$4 member=$5 destination=$6
  local work archive extracted
  if artifact_is_current "$installed_digest" "$destination"; then
    return 0
  fi
  work=$(mktemp -d)
  archive="${work}/${name}.tgz"
  download_sha256 "$name" "$url" "$digest" "$archive"
  extracted="${work}/extract"
  extract_safe_tar "$archive" "$extracted"
  [[ -f "${extracted}/${member}" && ! -L "${extracted}/${member}" ]] || {
    rm -rf -- "$work"
    die "verified ${name} archive has no expected binary"
    return 1
  }
  install_text_if_changed "${extracted}/${member}" "$destination" 0755
  artifact_is_current "$installed_digest" "$destination" || die "installed ${name} fingerprint mismatch"
  rm -rf -- "$work"
}

install_kube_bench() {
  require_vars KUBE_BENCH_VERSION KUBE_BENCH_MODE KUBE_BENCH_URL KUBE_BENCH_SHA256 \
    KUBE_BENCH_BINARY_INSTALLED_SHA256 KUBE_BENCH_CONFIG_INSTALLED_SHA256
  [[ "$KUBE_BENCH_VERSION" == "$REQUIRED_KUBE_BENCH_VERSION" ]] || die "kube-bench must be ${REQUIRED_KUBE_BENCH_VERSION}"
  [[ "$KUBE_BENCH_MODE" == training-only ]] || die "kube-bench must remain training-only"
  if ! artifact_is_current "$KUBE_BENCH_BINARY_INSTALLED_SHA256" /usr/local/bin/kube-bench ||
     ! artifact_is_current "$KUBE_BENCH_CONFIG_INSTALLED_SHA256" /usr/local/share/kube-bench; then
    local work archive extracted new_cfg
    work=$(mktemp -d)
    archive="${work}/kube-bench.tgz"
    extracted="${work}/extract"
    download_sha256 kube-bench "$KUBE_BENCH_URL" "$KUBE_BENCH_SHA256" "$archive"
    extract_safe_tar "$archive" "$extracted"
    [[ -f "${extracted}/kube-bench" && ! -L "${extracted}/kube-bench" && -d "${extracted}/cfg" ]] || {
      rm -rf -- "$work"
      die "verified kube-bench archive is incomplete"
      return 1
    }
    install_text_if_changed "${extracted}/kube-bench" /usr/local/bin/kube-bench 0755
    new_cfg="${CKS_TOOLS_STATE_DIR}/kube-bench-cfg.new"
    rm -rf -- "$new_cfg"
    mkdir -p -- "$(dirname -- "$new_cfg")"
    cp -R -- "${extracted}/cfg" "$new_cfg"
    find "$new_cfg" -type d -exec chmod 0755 -- {} +
    find "$new_cfg" -type f -exec chmod 0644 -- {} +
    [[ ! -L /usr/local/share/kube-bench ]] || { rm -rf -- "$work" "$new_cfg"; die "unsafe kube-bench config destination"; return 1; }
    rm -rf -- /usr/local/share/kube-bench
    mkdir -p -- /usr/local/share
    mv -- "$new_cfg" /usr/local/share/kube-bench
    artifact_is_current "$KUBE_BENCH_BINARY_INSTALLED_SHA256" /usr/local/bin/kube-bench \
      || die "installed kube-bench binary fingerprint mismatch"
    artifact_is_current "$KUBE_BENCH_CONFIG_INSTALLED_SHA256" /usr/local/share/kube-bench \
      || die "installed kube-bench config fingerprint mismatch"
    rm -rf -- "$work"
  fi
  assert_output_contains kube-bench "$KUBE_BENCH_VERSION" env \
    -u KUBE_BENCH_VERSION -u KUBE_BENCH_MODE -u KUBE_BENCH_URL -u KUBE_BENCH_SHA256 \
    kube-bench version
}

install_control_plane_tools() {
  require_vars \
    HELM_VERSION HELM_URL HELM_SHA256 HELM_INSTALLED_SHA256 \
    CILIUM_CLI_VERSION CILIUM_CLI_URL CILIUM_CLI_SHA256 CILIUM_CLI_INSTALLED_SHA256 \
    ETCDCTL_VERSION ETCDCTL_URL ETCDCTL_SHA256 ETCDCTL_INSTALLED_SHA256
  [[ "$HELM_VERSION" == "$REQUIRED_HELM_VERSION" ]] || die "Helm must be ${REQUIRED_HELM_VERSION}"
  [[ "${CILIUM_CLI_VERSION#v}" == "$REQUIRED_CILIUM_CLI_VERSION" ]] || die "Cilium CLI must be ${REQUIRED_CILIUM_CLI_VERSION}"
  [[ "$ETCDCTL_VERSION" == "$REQUIRED_ETCDCTL_VERSION" ]] || die "etcdctl must be ${REQUIRED_ETCDCTL_VERSION}"
  install_tar_binary helm "$HELM_URL" "$HELM_SHA256" "$HELM_INSTALLED_SHA256" linux-arm64/helm /usr/local/bin/helm
  install_tar_binary cilium-cli "$CILIUM_CLI_URL" "$CILIUM_CLI_SHA256" "$CILIUM_CLI_INSTALLED_SHA256" cilium /usr/local/bin/cilium
  install_tar_binary etcdctl "$ETCDCTL_URL" "$ETCDCTL_SHA256" "$ETCDCTL_INSTALLED_SHA256" \
    "etcd-v${ETCDCTL_VERSION}-linux-arm64/etcdctl" /usr/local/bin/etcdctl
  install_kube_bench
  assert_output_contains helm "v${HELM_VERSION}" helm version --short
  assert_output_contains cilium "${CILIUM_CLI_VERSION}" cilium version --client
  assert_output_contains etcdctl "$ETCDCTL_VERSION" env \
    -u ETCDCTL_VERSION -u ETCDCTL_URL -u ETCDCTL_SHA256 etcdctl version
}

render_containerd_runsc_config() {
  local source=$1 destination=$2
  python3 - "$source" "$destination" <<'PY'
import pathlib
import sys

source, destination = map(pathlib.Path, sys.argv[1:])
if not source.is_file() or source.is_symlink():
    raise SystemExit("containerd config is missing or unsafe")
text = source.read_text(encoding="utf-8")
required = ('default_runtime_name = "runc"', 'runtime_type = "io.containerd.runc.v2"', "SystemdCgroup = true")
if any(value not in text for value in required):
    raise SystemExit("system containerd runc configuration is not intact")
begin = "# BEGIN CKS-SIMULATOR RUNSC RUNTIME"
end = "# END CKS-SIMULATOR RUNSC RUNTIME"
if text.count(begin) != text.count(end) or text.count(begin) > 1:
    raise SystemExit("managed runsc block is malformed")
if begin in text:
    prefix, remainder = text.split(begin, 1)
    _managed, suffix = remainder.split(end, 1)
    text = prefix.rstrip() + "\n" + suffix.lstrip("\n")
block = '''
# BEGIN CKS-SIMULATOR RUNSC RUNTIME
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
# END CKS-SIMULATOR RUNSC RUNTIME
'''
destination.write_text(text.rstrip() + "\n" + block, encoding="utf-8")
PY
}

install_gvisor_systrap() {
  require_vars \
    GVISOR_VERSION GVISOR_PLATFORM GVISOR_RUNSC_URL GVISOR_RUNSC_SHA512 \
    GVISOR_RUNSC_INSTALLED_SHA256 GVISOR_SHIM_URL GVISOR_SHIM_SHA512 \
    GVISOR_SHIM_INSTALLED_SHA256
  [[ "$GVISOR_VERSION" == "$REQUIRED_GVISOR_VERSION" ]] || die "gVisor must be ${REQUIRED_GVISOR_VERSION}"
  [[ "$GVISOR_PLATFORM" == systrap ]] || die "gVisor must use systrap"
  local work runsc_download shim_download runsc_config containerd_config
  local applied_marker desired_digest restart_required=0
  local runsc_changed=0 shim_changed=0 runsc_config_changed=0 containerd_config_changed=0
  work=$(mktemp -d)
  if ! artifact_is_current "$GVISOR_RUNSC_INSTALLED_SHA256" /usr/local/bin/runsc; then
    runsc_download="${work}/runsc"
    download_sha512 runsc "$GVISOR_RUNSC_URL" "$GVISOR_RUNSC_SHA512" "$runsc_download"
    install_text_if_changed "$runsc_download" /usr/local/bin/runsc 0755
    runsc_changed=$CKS_INSTALL_TEXT_CHANGED
    artifact_is_current "$GVISOR_RUNSC_INSTALLED_SHA256" /usr/local/bin/runsc \
      || die "installed runsc fingerprint mismatch"
  fi
  if ! artifact_is_current "$GVISOR_SHIM_INSTALLED_SHA256" /usr/local/bin/containerd-shim-runsc-v1; then
    shim_download="${work}/containerd-shim-runsc-v1"
    download_sha512 containerd-shim-runsc-v1 "$GVISOR_SHIM_URL" "$GVISOR_SHIM_SHA512" "$shim_download"
    install_text_if_changed "$shim_download" /usr/local/bin/containerd-shim-runsc-v1 0755
    shim_changed=$CKS_INSTALL_TEXT_CHANGED
    artifact_is_current "$GVISOR_SHIM_INSTALLED_SHA256" /usr/local/bin/containerd-shim-runsc-v1 \
      || die "installed gVisor shim fingerprint mismatch"
  fi
  runsc_config="${work}/runsc.toml"
  cat > "$runsc_config" <<EOF
[runsc_config]
  platform = "systrap"
  network = "sandbox"
EOF
  install_text_if_changed "$runsc_config" /etc/containerd/runsc.toml 0644
  runsc_config_changed=$CKS_INSTALL_TEXT_CHANGED
  containerd_config="${work}/containerd.toml"
  render_containerd_runsc_config /etc/containerd/config.toml "$containerd_config"
  install_text_if_changed "$containerd_config" /etc/containerd/config.toml 0644
  containerd_config_changed=$CKS_INSTALL_TEXT_CHANGED
  rm -rf -- "$work"
  applied_marker="${CKS_TOOLS_STATE_DIR}/gvisor-applied.sha256"
  [[ ! -L "$applied_marker" ]] || die "unsafe gVisor applied marker"
  desired_digest=$(
    {
      sha256sum \
        /usr/local/bin/runsc \
        /usr/local/bin/containerd-shim-runsc-v1 \
        /etc/containerd/runsc.toml \
        /etc/containerd/config.toml
      printf '%s\n' "$GVISOR_VERSION" "$GVISOR_PLATFORM"
    } | sha256sum | awk '{print $1}'
  )
  if (( runsc_changed || shim_changed || runsc_config_changed || containerd_config_changed )); then
    restart_required=1
  elif [[ ! -f "$applied_marker" || $(<"$applied_marker") != "$desired_digest" ]]; then
    restart_required=1
  elif ! systemctl is-active --quiet containerd; then
    restart_required=1
  elif ! containerd config dump | grep -F 'io.containerd.runsc.v1' >/dev/null; then
    restart_required=1
  fi
  if (( restart_required )); then
    systemctl restart containerd
  fi
  systemctl is-active --quiet containerd || die "system containerd is not active after gVisor convergence"
  systemctl is-active --quiet kubelet || die "kubelet is not active after gVisor convergence"
  containerd config dump | grep -F 'io.containerd.runsc.v1' >/dev/null || die "containerd did not load the runsc runtime"
  assert_output_contains runsc "$GVISOR_VERSION" runsc --version
  printf '%s\n' "$desired_digest" >"${applied_marker}.new"
  chmod 0600 "${applied_marker}.new"
  mv -fT -- "${applied_marker}.new" "$applied_marker"
}

install_apparmor_smoke_profile() {
  for command in apparmor_parser aa-status aa-exec; do
    require_command "$command"
  done
  local profile
  profile=$(mktemp)
  cat > "$profile" <<'EOF'
#include <tunables/global>

profile cks-simulator-capability-smoke flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  file,
  deny /var/lib/cks-simulator/probes/apparmor-denied w,
}
EOF
  install_text_if_changed "$profile" /etc/apparmor.d/cks-simulator-capability-smoke 0644
  rm -f -- "$profile"
  apparmor_parser -r /etc/apparmor.d/cks-simulator-capability-smoke
  aa-status --enabled
}

install_isolated_docker() {
  require_vars DOCKER_VERSION DOCKER_URL DOCKER_SHA256 DOCKER_INSTALLED_SHA256 NGINX_ALPINE_IMAGE
  [[ "$DOCKER_VERSION" == "$REQUIRED_DOCKER_VERSION" ]] || die "Docker Engine must be ${REQUIRED_DOCKER_VERSION}"
  local install_root="/opt/cks-simulator/docker/${DOCKER_VERSION}/bin"
  local work archive extracted staged daemon_config unit docker_changed=0 daemon_changed=0 unit_changed=0
  systemctl is-active --quiet containerd || die "system containerd must be active before Docker convergence"
  systemctl is-active --quiet kubelet || die "kubelet must be active before Docker convergence"
  if ! artifact_is_current "$DOCKER_INSTALLED_SHA256" "$install_root"; then
    work=$(mktemp -d)
    archive="${work}/docker.tgz"
    extracted="${work}/extract"
    staged="${work}/bin"
    download_sha256 docker-engine "$DOCKER_URL" "$DOCKER_SHA256" "$archive"
    extract_safe_tar "$archive" "$extracted"
    [[ -f "${extracted}/docker/dockerd" && -f "${extracted}/docker/docker" && -f "${extracted}/docker/containerd" ]] || {
      rm -rf -- "$work"
      die "verified Docker archive is incomplete"
      return 1
    }
    mkdir -p -- "$staged"
    find "${extracted}/docker" -maxdepth 1 -type f -exec install -m 0755 -- {} "$staged/" \;
    chmod 0755 -- "$staged"
    [[ ! -L "$install_root" ]] || { rm -rf -- "$work"; die "unsafe Docker install destination"; return 1; }
    rm -rf -- "$install_root"
    mkdir -p -- "$(dirname -- "$install_root")"
    mv -- "$staged" "$install_root"
    artifact_is_current "$DOCKER_INSTALLED_SHA256" "$install_root" \
      || die "installed Docker bundle fingerprint mismatch"
    rm -rf -- "$work"
    docker_changed=1
  fi
  # Expose only the client globally. The service's private PATH resolves its
  # bundled dockerd/containerd/runc without shadowing Kubernetes' system tools.
  ln -sfn -- "${install_root}/docker" /usr/local/bin/docker
  daemon_config=$(mktemp)
  cat > "$daemon_config" <<'EOF'
{
  "data-root": "/var/lib/cks-docker",
  "exec-root": "/run/cks-docker",
  "pidfile": "/run/cks-docker.pid",
  "hosts": ["unix:///run/docker.sock"],
  "ip-forward-no-drop": true
}
EOF
  install_text_if_changed "$daemon_config" /etc/docker/daemon.json 0644
  daemon_changed=$CKS_INSTALL_TEXT_CHANGED
  rm -f -- "$daemon_config"
  unit=$(mktemp)
  cat > "$unit" <<EOF
[Unit]
Description=CKS Simulator isolated Docker Engine ${DOCKER_VERSION}
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
Environment=PATH=${install_root}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=${install_root}/dockerd --config-file=/etc/docker/daemon.json
Restart=on-failure
RestartSec=2
TimeoutStartSec=120
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF
  install_text_if_changed "$unit" /etc/systemd/system/cks-docker.service 0644
  unit_changed=$CKS_INSTALL_TEXT_CHANGED
  rm -f -- "$unit"
  if (( unit_changed )); then
    systemctl daemon-reload
  fi
  systemctl enable cks-docker.service >/dev/null
  if (( docker_changed || daemon_changed || unit_changed )) || ! systemctl is-active --quiet cks-docker.service; then
    systemctl restart cks-docker.service
  fi
  wait_until 120 2 docker --host unix:///run/docker.sock info >/dev/null || die "isolated Docker Engine did not become ready"
  [[ $(docker --host unix:///run/docker.sock version --format '{{.Server.Version}}') == "$DOCKER_VERSION" ]] || die "Docker server version mismatch"
  assert_digest_pinned_image "$NGINX_ALPINE_IMAGE"
  docker --host unix:///run/docker.sock pull "$NGINX_ALPINE_IMAGE" >/dev/null
  docker --host unix:///run/docker.sock tag "$NGINX_ALPINE_IMAGE" nginx:1-alpine
  systemctl is-active --quiet containerd || die "system containerd was disrupted by Docker convergence"
  systemctl is-active --quiet kubelet || die "kubelet was disrupted by Docker convergence"
}

case "$ROLE" in
  control-plane)
    install_control_plane_tools
    ;;
  worker1)
    install_kube_bench
    install_apparmor_smoke_profile
    install_gvisor_systrap
    ;;
  worker2)
    install_kube_bench
    install_isolated_docker
    ;;
  *)
    die "usage: $0 {control-plane|worker1|worker2}"
    exit 2
    ;;
esac

log "${ROLE} tool convergence complete"
