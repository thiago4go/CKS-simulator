#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly TARGET=${1:?target is required}
readonly VERSIONS=/tmp/cks-spike-versions.json
readonly DOWNLOADS=/var/lib/cks-simulator/downloads

[[ ${EUID} -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -r "$VERSIONS" ]] || { echo "version manifest is missing" >&2; exit 1; }
mkdir -p "$DOWNLOADS"

json() { jq -er "$1" "$VERSIONS"; }

download_sha256() {
  local url=$1 expected=$2 output=$3
  [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || return 1
  curl --fail --location --silent --show-error --retry 3 "$url" -o "$output"
  printf '%s  %s\n' "$expected" "$output" | sha256sum --check --status
}

download_sha512() {
  local url=$1 expected=$2 output=$3
  [[ "$expected" =~ ^[a-f0-9]{128}$ ]] || return 1
  curl --fail --location --silent --show-error --retry 3 "$url" -o "$output"
  printf '%s  %s\n' "$expected" "$output" | sha512sum --check --status
}

install_control_plane_tools() {
  local archive
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install --yes curl jq tar gzip openssl

  archive=$DOWNLOADS/helm.tar.gz
  download_sha256 "$(json '.helm.url')" "$(json '.helm.sha256')" "$archive"
  rm -rf "$DOWNLOADS/helm"
  mkdir -p "$DOWNLOADS/helm"
  tar -xzf "$archive" -C "$DOWNLOADS/helm" --no-same-owner
  install -m 0755 "$DOWNLOADS/helm/linux-arm64/helm" /usr/local/bin/helm

  archive=$DOWNLOADS/cilium.tar.gz
  download_sha256 "$(json '.cilium.cli_url')" "$(json '.cilium.cli_sha256')" "$archive"
  tar -xzf "$archive" -C /usr/local/bin --no-same-owner cilium
  chmod 0755 /usr/local/bin/cilium

  archive=$DOWNLOADS/trivy.tar.gz
  download_sha256 "$(json '.trivy.url')" "$(json '.trivy.sha256')" "$archive"
  tar -xzf "$archive" -C /usr/local/bin --no-same-owner trivy
  chmod 0755 /usr/local/bin/trivy

  archive=$DOWNLOADS/kube-bench.tar.gz
  download_sha256 "$(json '.kube_bench.url')" "$(json '.kube_bench.sha256')" "$archive"
  rm -rf "$DOWNLOADS/kube-bench" /usr/local/share/kube-bench
  mkdir -p "$DOWNLOADS/kube-bench" /usr/local/share/kube-bench
  tar -xzf "$archive" -C "$DOWNLOADS/kube-bench" --no-same-owner
  install -m 0755 "$DOWNLOADS/kube-bench/kube-bench" /usr/local/bin/kube-bench
  cp -R "$DOWNLOADS/kube-bench/cfg" /usr/local/share/kube-bench/

  download_sha256 "$(json '.falco.chart_url')" "$(json '.falco.chart_sha256')" "$DOWNLOADS/falco.tgz"
  download_sha256 "$(json '.ingress_nginx.chart_url')" "$(json '.ingress_nginx.chart_sha256')" "$DOWNLOADS/ingress-nginx.tgz"

  helm version --short | grep -F "v$(json '.helm.version')" >/dev/null
  cilium version --client | grep -F "v$(json '.cilium.cli_version')" >/dev/null
  trivy --version | grep -F "Version: $(json '.trivy.version')" >/dev/null
  kube-bench version | grep -F "$(json '.kube_bench.version')" >/dev/null
}

install_gvisor() {
  download_sha512 "$(json '.gvisor.runsc_url')" "$(json '.gvisor.runsc_sha512')" "$DOWNLOADS/runsc"
  download_sha512 "$(json '.gvisor.shim_url')" "$(json '.gvisor.shim_sha512')" "$DOWNLOADS/containerd-shim-runsc-v1"
  install -m 0755 "$DOWNLOADS/runsc" /usr/local/bin/runsc
  install -m 0755 "$DOWNLOADS/containerd-shim-runsc-v1" /usr/local/bin/containerd-shim-runsc-v1
  cat > /etc/containerd/runsc.toml <<EOF
[runsc_config]
  platform = "$(json '.gvisor.platform')"
  network = "sandbox"
EOF
  systemctl restart containerd
  systemctl is-active --quiet containerd
  containerd config dump | grep -F 'io.containerd.runsc.v1' >/dev/null
  runsc --version | grep -F "$(json '.gvisor.version')" >/dev/null
}

install_docker() {
  local archive=$DOWNLOADS/docker.tgz
  download_sha256 "$(json '.docker.url')" "$(json '.docker.sha256')" "$archive"
  rm -rf "$DOWNLOADS/docker" /opt/cks-docker
  mkdir -p "$DOWNLOADS/docker" /opt/cks-docker/bin
  tar -xzf "$archive" -C "$DOWNLOADS/docker" --no-same-owner
  install -m 0755 "$DOWNLOADS/docker"/docker/* /opt/cks-docker/bin/
  ln -sfn /opt/cks-docker/bin/docker /usr/local/bin/docker
  install -d -m 0755 /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "data-root": "/var/lib/cks-docker",
  "exec-root": "/run/cks-docker",
  "pidfile": "/run/cks-docker.pid",
  "ip-forward-no-drop": true
}
EOF
  cat > /etc/systemd/system/cks-docker.service <<'EOF'
[Unit]
Description=CKS isolated Docker daemon
After=network-online.target containerd.service
Wants=network-online.target

[Service]
Type=notify
Environment=PATH=/opt/cks-docker/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/cks-docker/bin/dockerd --config-file=/etc/docker/daemon.json --host=unix:///run/cks-docker.sock
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl disable --now docker.service docker.socket 2>/dev/null || true
  systemctl disable --now cks-docker.service 2>/dev/null || true
}

install_apparmor_profile() {
  cat > /etc/apparmor.d/cks-deny-write <<'EOF'
#include <tunables/global>

profile cks-deny-write flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  file,
  deny /tmp/cks-denied w,
}
EOF
  apparmor_parser -r /etc/apparmor.d/cks-deny-write
  aa-status --enabled
}

start_and_probe_docker() {
  local image
  image=$(json '.workload_images.busybox')
  systemctl start cks-docker.service
  timeout 90 bash -c 'until docker --host unix:///run/cks-docker.sock info >/dev/null 2>&1; do sleep 2; done'
  jq -e '."ip-forward-no-drop" == true' /etc/docker/daemon.json >/dev/null
  test -S /run/containerd/containerd.sock
  test -S /run/cks-docker.sock
  systemctl is-active --quiet containerd
  systemctl is-active --quiet cks-docker.service
  test "$(docker --host unix:///run/cks-docker.sock version --format '{{.Server.Version}}')" = "$(json '.docker.version')"
  test "$(crictl --runtime-endpoint unix:///run/containerd/containerd.sock info | jq -r '.status.conditions[] | select(.type == "RuntimeReady") | .status')" = true
  test "$(docker --host unix:///run/cks-docker.sock run --rm "$image" sh -c 'printf CKS_DOCKER_OK')" = CKS_DOCKER_OK
}

case "$TARGET" in
  control-plane) install_control_plane_tools ;;
  gvisor) install_gvisor ;;
  docker) install_docker ;;
  apparmor) install_apparmor_profile ;;
  start-docker) start_and_probe_docker ;;
  *) echo "unknown target: $TARGET" >&2; exit 2 ;;
esac
