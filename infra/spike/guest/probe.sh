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

probe_common() {
  [[ $(swapon --noheadings | wc -l) -eq 0 ]] || die "swap is enabled"
  [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || die "IPv4 forwarding is disabled"
  [[ $(sysctl -n net.bridge.bridge-nf-call-iptables) == 1 ]] || die "bridge netfilter is disabled"
  [[ -d /sys/fs/cgroup/system.slice ]] || die "systemd cgroup hierarchy is unavailable"
  grep -Fq 'SystemdCgroup = true' /etc/containerd/config.toml || die "containerd systemd cgroups are not explicit"
  grep -Fq "runtime-endpoint: unix:///run/containerd/containerd.sock" /etc/crictl.yaml || die "explicit CRI endpoint is missing"
  crictl --runtime-endpoint unix:///run/containerd/containerd.sock info >/dev/null || die "containerd CRI is unhealthy"
}

probe_candidate() {
  require_env KUBECTL_VERSION HELM_VERSION CILIUM_CLI_VERSION TRIVY_VERSION KUBE_BENCH_VERSION
  assert_output_contains kubectl "$KUBECTL_VERSION" kubectl version --client
  assert_output_contains helm "$HELM_VERSION" helm version --short
  assert_output_contains cilium "$CILIUM_CLI_VERSION" cilium version --client
  assert_output_contains trivy "$TRIVY_VERSION" trivy --version
  assert_output_contains kube-bench "$KUBE_BENCH_VERSION" kube-bench version
}

probe_control_plane() {
  KUBECONFIG=/etc/kubernetes/admin.conf kubectl get --raw=/readyz >/dev/null || die "control-plane readyz failed"
  KUBECONFIG=/etc/kubernetes/admin.conf kubectl get nodes -o name | grep -Fq 'node/' || die "cluster has no registered nodes"
}

probe_worker() {
  systemctl is-active --quiet kubelet || die "kubelet is not active"
  [[ -s /etc/kubernetes/kubelet.conf ]] || die "worker kubelet.conf is missing"
}

probe_gvisor() {
  require_env GVISOR_PROBE_IMAGE
  local container_id="cks-gvisor-probe-$$"
  local output
  grep -Fq 'platform = "systrap"' /etc/containerd/runsc.toml || die "gVisor is not configured for systrap"
  ctr --namespace cks-probe images pull --platform linux/arm64 "$GVISOR_PROBE_IMAGE" || die "gVisor probe image pull failed"
  output=$(ctr --namespace cks-probe run --rm --runtime io.containerd.runsc.v1 "$GVISOR_PROBE_IMAGE" "$container_id" /bin/sh -c 'printf CKS_GVISOR_OK') \
    || die "gVisor systrap container failed"
  [[ "$output" == CKS_GVISOR_OK ]] || die "gVisor probe returned unexpected output"
}

probe_falco() {
  local work rules output falco_pid
  work=$(mktemp -d)
  rules="${work}/rules.yaml"
  output="${work}/falco.log"
  cat > "$rules" <<'EOF'
- rule: CKS modern eBPF capability
  desc: Detect the deterministic CKS probe file
  condition: evt.type = openat and fd.name = /etc/cks-falco-probe
  output: CKS_FALCO_MODERN_EBPF_OK
  priority: INFO
  source: syscall
EOF
  : > /etc/cks-falco-probe
  timeout --signal=TERM 20s falco -c /etc/falco/falco.yaml -r "$rules" -o engine.kind=modern_ebpf >"$output" 2>&1 &
  falco_pid=$!
  sleep 4
  /usr/bin/head -c 1 /etc/cks-falco-probe >/dev/null
  sleep 2
  kill -TERM "$falco_pid" 2>/dev/null || true
  wait "$falco_pid" 2>/dev/null || true
  rm -f /etc/cks-falco-probe
  grep -Fq CKS_FALCO_MODERN_EBPF_OK "$output" || {
    sed -n '1,80p' "$output" >&2
    rm -rf -- "$work"
    die "Falco modern eBPF did not capture the positive event"
  }
  rm -rf -- "$work"
}

probe_docker() {
  require_env DOCKER_PROBE_IMAGE
  systemctl is-active --quiet docker || die "Docker is not active"
  python3 -c 'import json; assert json.load(open("/etc/docker/daemon.json"))["ip-forward-no-drop"] is True' \
    || die "Docker ip-forward-no-drop is not true"
  output=$(docker run --rm "$DOCKER_PROBE_IMAGE" /bin/sh -c 'printf CKS_DOCKER_OK') || die "Docker behavioral probe failed"
  [[ "$output" == CKS_DOCKER_OK ]] || die "Docker probe returned unexpected output"
  crictl --runtime-endpoint unix:///run/containerd/containerd.sock info >/dev/null || die "system containerd CRI is unhealthy after Docker probe"
}

probe_trivy() {
  require_env TRIVY_PROBE_IMAGE
  local result
  result=$(mktemp)
  if ! trivy image --format json --output "$result" "$TRIVY_PROBE_IMAGE"; then
    rm -f -- "$result"
    die "Trivy image scan failed"
  fi
  [[ -s "$result" ]] || die "Trivy produced no scan evidence"
  jq -e '.ArtifactName and .SchemaVersion' "$result" >/dev/null || die "Trivy scan evidence is invalid"
  rm -f -- "$result"
}

probe_kube_bench() {
  local target=${KUBE_BENCH_TARGET:-node}
  local result
  result=$(mktemp)
  if ! kube-bench run --targets "$target" --json > "$result"; then
    rm -f -- "$result"
    die "kube-bench execution failed for target ${target}"
  fi
  [[ -s "$result" ]] || die "kube-bench produced no evidence"
  jq -e '.Totals or .Controls' "$result" >/dev/null || die "kube-bench evidence is invalid"
  rm -f -- "$result"
}

run_all() {
  case ${CKS_NODE_ROLE:-} in
    candidate)
      probe_candidate
      ;;
    control-plane)
      probe_common
      probe_control_plane
      probe_trivy
      KUBE_BENCH_TARGET=master probe_kube_bench
      ;;
    worker1)
      probe_common
      probe_worker
      probe_gvisor
      probe_falco
      probe_trivy
      probe_kube_bench
      ;;
    worker2)
      probe_common
      probe_worker
      probe_falco
      probe_docker
      probe_trivy
      probe_kube_bench
      ;;
    *)
      die "CKS_NODE_ROLE must be candidate, control-plane, worker1, or worker2"
      ;;
  esac
}

case ${1:-all} in
  all) run_all ;;
  common) probe_common ;;
  candidate) probe_candidate ;;
  control-plane) probe_control_plane ;;
  worker) probe_worker ;;
  gvisor) probe_gvisor ;;
  falco) probe_falco ;;
  docker) probe_docker ;;
  trivy) probe_trivy ;;
  kube-bench) probe_kube_bench ;;
  *) die "usage: $0 {all|common|candidate|control-plane|worker|gvisor|falco|docker|trivy|kube-bench}" ;;
esac

log "probe ${1:-all} passed"
