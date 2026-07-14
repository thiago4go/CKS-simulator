#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

readonly TARGET=${1:-}
readonly KUBECONFIG=${KUBECONFIG:-/etc/kubernetes/admin.conf}
readonly KUBE_BENCH_TIMEOUT_SECONDS=${CKS_KUBE_BENCH_TIMEOUT_SECONDS:-180}
readonly CLUSTER_CHECK_TIMEOUT_SECONDS=${CKS_CLUSTER_CHECK_TIMEOUT_SECONDS:-720}
readonly FALCO_EVENT_TIMEOUT_SECONDS=${CKS_FALCO_EVENT_TIMEOUT_SECONDS:-180}
export KUBECONFIG

require_root
load_tools_inputs
validate_positive_timeout CKS_KUBE_BENCH_TIMEOUT_SECONDS "$KUBE_BENCH_TIMEOUT_SECONDS" 600
validate_positive_timeout CKS_CLUSTER_CHECK_TIMEOUT_SECONDS "$CLUSTER_CHECK_TIMEOUT_SECONDS" 1800
validate_positive_timeout CKS_FALCO_EVENT_TIMEOUT_SECONDS "$FALCO_EVENT_TIMEOUT_SECONDS" 600

kube_bench_training_check() {
  local role=$1 target=$2 result stderr rc=0
  require_vars KUBE_BENCH_VERSION KUBE_BENCH_MODE
  [[ "$KUBE_BENCH_VERSION" == 0.15.6 && "$KUBE_BENCH_MODE" == training-only ]] || die "kube-bench pin or training label is invalid"
  require_command timeout
  require_command jq
  assert_output_contains kube-bench "$KUBE_BENCH_VERSION" env \
    -u KUBE_BENCH_VERSION -u KUBE_BENCH_MODE -u KUBE_BENCH_URL -u KUBE_BENCH_SHA256 \
    kube-bench version
  mkdir -p -- /var/lib/cks-simulator/probes
  result="/var/lib/cks-simulator/probes/kube-bench-${role}-training-only.json"
  stderr="${result%.json}.stderr"
  set +e
  timeout "$KUBE_BENCH_TIMEOUT_SECONDS" env \
    -u KUBE_BENCH_VERSION -u KUBE_BENCH_MODE -u KUBE_BENCH_URL -u KUBE_BENCH_SHA256 \
    kube-bench run \
    --targets "$target" --config-dir /usr/local/share/kube-bench --json \
    > "$result" 2> "$stderr"
  rc=$?
  set -e
  case "$rc" in
    0|1)
      ;;
    *)
      die "kube-bench execution failed for ${role} with rc=${rc}"
      return 1
      ;;
  esac
  jq -e '
    type == "object" and
    (.Controls | type == "array" and length > 0) and
    any(.Controls[]?; any(.tests[]?; (.results | type == "array" and length > 0)))
  ' "$result" >/dev/null || { die "kube-bench produced no structured benchmark evidence"; return 1; }
  printf 'KUBE_BENCH_TRAINING_ONLY role=%s version=%s rc=%s evidence=%s\n' \
    "$role" "$KUBE_BENCH_VERSION" "$rc" "$result"
}

etcdctl_endpoint_health() {
  require_vars ETCDCTL_VERSION
  [[ "$ETCDCTL_VERSION" == 3.6.6 ]] || die "etcdctl must be 3.6.6"
  assert_output_contains etcdctl "$ETCDCTL_VERSION" env \
    -u ETCDCTL_VERSION -u ETCDCTL_URL -u ETCDCTL_SHA256 etcdctl version
  local -a tls=(
    --endpoints=https://127.0.0.1:2379
    --cacert=/etc/kubernetes/pki/etcd/ca.crt
    --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt
    --key=/etc/kubernetes/pki/etcd/healthcheck-client.key
  )
  env -u ETCDCTL_API -u ETCDCTL_VERSION -u ETCDCTL_URL -u ETCDCTL_SHA256 \
    etcdctl "${tls[@]}" endpoint health >/dev/null
  env -u ETCDCTL_API -u ETCDCTL_VERSION -u ETCDCTL_URL -u ETCDCTL_SHA256 \
    etcdctl "${tls[@]}" endpoint status --write-out=json \
    | jq -e 'type == "array" and length == 1 and .[0].Status.header.revision > 0' >/dev/null
}

apparmor_allow_deny_smoke() {
  for command in aa-status aa-exec apparmor_parser; do
    require_command "$command"
  done
  aa-status --enabled
  apparmor_parser -r /etc/apparmor.d/cks-simulator-capability-smoke
  mkdir -p -- /var/lib/cks-simulator/probes
  rm -f -- \
    /var/lib/cks-simulator/probes/apparmor-allowed \
    /var/lib/cks-simulator/probes/apparmor-denied
  aa-exec -p cks-simulator-capability-smoke -- /bin/bash -c '
    printf APPARMOR_ALLOW_OK > /var/lib/cks-simulator/probes/apparmor-allowed
    if printf should-fail > /var/lib/cks-simulator/probes/apparmor-denied; then
      exit 42
    fi
  '
  grep -Fxq APPARMOR_ALLOW_OK /var/lib/cks-simulator/probes/apparmor-allowed
  [[ ! -s /var/lib/cks-simulator/probes/apparmor-denied ]] || die "AppArmor denied write unexpectedly succeeded"
}

gvisor_local_smoke() {
  require_vars GVISOR_VERSION GVISOR_PLATFORM
  [[ "$GVISOR_VERSION" == release-20260706.0 && "$GVISOR_PLATFORM" == systrap ]] || die "gVisor pin or platform is invalid"
  assert_output_contains runsc "$GVISOR_VERSION" runsc --version
  grep -Fq 'platform = "systrap"' /etc/containerd/runsc.toml || die "runsc is not configured for systrap"
  grep -Fq 'default_runtime_name = "runc"' /etc/containerd/config.toml || die "system containerd no longer defaults to runc"
  grep -Fq 'runtime_type = "io.containerd.runsc.v1"' /etc/containerd/config.toml || die "runsc handler is missing"
  systemctl is-active --quiet containerd || die "system containerd is not active"
  systemctl is-active --quiet kubelet || die "kubelet is not active"
  crictl --runtime-endpoint unix:///run/containerd/containerd.sock info \
    | jq -e '.status.conditions[] | select(.type == "RuntimeReady") | .status == true' >/dev/null
}

docker_and_kubernetes_smoke() {
  require_vars DOCKER_VERSION BUSYBOX_IMAGE
  [[ "$DOCKER_VERSION" == 29.6.1 ]] || die "Docker Engine must be 29.6.1"
  assert_digest_pinned_image "$BUSYBOX_IMAGE"
  systemctl is-active --quiet cks-docker.service || die "isolated Docker Engine is not active"
  systemctl is-active --quiet containerd || die "Kubernetes system containerd is not active"
  systemctl is-active --quiet kubelet || die "kubelet is not active"
  grep -Fxq 'runtime-endpoint: unix:///run/containerd/containerd.sock' /etc/crictl.yaml || die "crictl no longer targets system containerd"
  grep -Fq -- '--container-runtime-endpoint=unix:///run/containerd/containerd.sock' /etc/default/kubelet || die "kubelet no longer targets system containerd"
  [[ $(docker --host unix:///run/docker.sock version --format '{{.Server.Version}}') == "$DOCKER_VERSION" ]] || die "Docker server version mismatch"
  [[ $(docker --host unix:///run/docker.sock info --format '{{.DockerRootDir}}') == /var/lib/cks-docker ]] || die "Docker data root is not isolated"
  [[ $(docker --host unix:///run/docker.sock run --rm "$BUSYBOX_IMAGE" sh -c 'printf CKS_DOCKER_OK') == CKS_DOCKER_OK ]] || die "Docker container smoke failed"
  crictl --runtime-endpoint unix:///run/containerd/containerd.sock info \
    | jq -e '.status.conditions[] | select(.type == "RuntimeReady") | .status == true' >/dev/null
}

kubernetes_cilium_health() {
  require_vars KUBERNETES_VERSION CILIUM_VERSION CILIUM_CLI_VERSION CKS_CONTROL_PLANE_NODE CKS_WORKER1_NODE CKS_WORKER2_NODE
  local nodes_json
  [[ -f "$KUBECONFIG" && ! -L "$KUBECONFIG" ]] || die "control-plane kubeconfig is missing or unsafe"
  kubectl get --raw=/readyz >/dev/null
  kubectl wait --for=condition=Ready \
    "node/${CKS_CONTROL_PLANE_NODE}" "node/${CKS_WORKER1_NODE}" "node/${CKS_WORKER2_NODE}" \
    --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  nodes_json=$(mktemp)
  kubectl get nodes -o json > "$nodes_json"
  python3 - "$nodes_json" "$CKS_CONTROL_PLANE_NODE" "$CKS_WORKER1_NODE" "$CKS_WORKER2_NODE" <<'PY'
import json
import sys

path = sys.argv[1]
expected = set(sys.argv[2:])
with open(path, "r", encoding="utf-8") as stream:
    document = json.load(stream)
items = document.get("items", [])
observed = {item.get("metadata", {}).get("name") for item in items}
if observed != expected:
    raise SystemExit("cluster does not contain exactly the three expected nodes")
for item in items:
    conditions = item.get("status", {}).get("conditions", [])
    if not any(value.get("type") == "Ready" and value.get("status") == "True" for value in conditions):
        raise SystemExit("cluster has a non-Ready node")
PY
  rm -f -- "$nodes_json"
  [[ $(kubectl version -o json | jq -r '.serverVersion.gitVersion') == "v${KUBERNETES_VERSION#v}" ]] || die "Kubernetes server version mismatch"
  assert_output_contains cilium "$CILIUM_CLI_VERSION" cilium version --client
  cilium status --wait --wait-duration "${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  kubectl rollout status daemonset/cilium --namespace kube-system --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  kubectl rollout status deployment/coredns --namespace kube-system --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
}

cilium_network_policy_smoke() (
  require_vars BUSYBOX_IMAGE CKS_WORKER1_NODE CKS_WORKER2_NODE
  assert_digest_pinned_image "$BUSYBOX_IMAGE"
  local namespace="cks-netprobe-$$" server=server client=client
  kubectl get namespace "$namespace" >/dev/null 2>&1 && die "network probe namespace already exists"
  trap 'kubectl delete namespace "$namespace" --ignore-not-found --wait=false >/dev/null 2>&1 || true' EXIT
  kubectl create namespace "$namespace" >/dev/null
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: ${server}, namespace: ${namespace}, labels: {app: server}}
spec:
  nodeName: ${CKS_WORKER2_NODE}
  containers:
    - {name: server, image: ${BUSYBOX_IMAGE}, command: ["sh", "-c", "mkdir -p /www; echo CKS_NETWORK_OK >/www/index.html; httpd -f -p 8080 -h /www"]}
---
apiVersion: v1
kind: Pod
metadata: {name: ${client}, namespace: ${namespace}, labels: {access: allowed}}
spec:
  nodeName: ${CKS_WORKER1_NODE}
  containers:
    - {name: client, image: ${BUSYBOX_IMAGE}, command: ["sh", "-c", "sleep 1800"]}
---
apiVersion: v1
kind: Service
metadata: {name: server, namespace: ${namespace}}
spec: {selector: {app: server}, ports: [{port: 8080, targetPort: 8080}]}
EOF
  kubectl wait --namespace "$namespace" --for=condition=Ready pod/server pod/client --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  kubectl exec --namespace "$namespace" "$client" -- wget -qO- -T 10 http://server:8080 | grep -Fxq CKS_NETWORK_OK
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-server, namespace: ${namespace}}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress]
  ingress: []
EOF
  sleep 3
  if kubectl exec --namespace "$namespace" "$client" -- wget -qO- -T 5 http://server:8080 >/dev/null 2>&1; then
    die "Cilium did not enforce default-deny ingress"
  fi
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-client, namespace: ${namespace}}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {access: allowed}}}]
      ports: [{protocol: TCP, port: 8080}]
EOF
  wait_until "$CLUSTER_CHECK_TIMEOUT_SECONDS" 2 kubectl exec --namespace "$namespace" "$client" -- wget -qO- -T 10 http://server:8080 >/dev/null
)

apparmor_kubernetes_smoke() (
  require_vars BUSYBOX_IMAGE CKS_WORKER1_NODE
  assert_digest_pinned_image "$BUSYBOX_IMAGE"
  local pod="cks-smoke-apparmor-$$"
  trap 'kubectl delete pod "$pod" --ignore-not-found --wait=true >/dev/null 2>&1 || true' EXIT
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
spec:
  nodeName: ${CKS_WORKER1_NODE}
  restartPolicy: Never
  containers:
    - name: smoke
      image: ${BUSYBOX_IMAGE}
      securityContext:
        appArmorProfile:
          type: Localhost
          localhostProfile: cks-simulator-capability-smoke
      command: ["sh", "-c"]
      args:
        - >-
          mkdir -p /var/lib/cks-simulator/probes;
          printf APPARMOR_ALLOW_OK >/var/lib/cks-simulator/probes/apparmor-allowed;
          if printf should-fail >/var/lib/cks-simulator/probes/apparmor-denied;
          then exit 42; else printf 'APPARMOR_ALLOW_OK APPARMOR_DENY_OK'; fi
EOF
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${pod}" --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  kubectl logs "$pod" | grep -Fq 'APPARMOR_ALLOW_OK APPARMOR_DENY_OK'
)

gvisor_pod_smoke() (
  require_vars BUSYBOX_IMAGE CKS_WORKER1_NODE
  assert_digest_pinned_image "$BUSYBOX_IMAGE"
  local pod="cks-smoke-gvisor-$$" runtime="cks-smoke-runsc-$$"
  trap 'kubectl delete pod "$pod" --ignore-not-found --wait=true >/dev/null 2>&1 || true; kubectl delete runtimeclass "$runtime" --ignore-not-found >/dev/null 2>&1 || true' EXIT
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: ${runtime}
handler: runsc
EOF
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
spec:
  nodeName: ${CKS_WORKER1_NODE}
  runtimeClassName: ${runtime}
  restartPolicy: Never
  containers:
    - name: smoke
      image: ${BUSYBOX_IMAGE}
      command: ["sh", "-c", "dmesg | grep -i gvisor"]
EOF
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${pod}" --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  [[ $(kubectl get pod "$pod" -o jsonpath='{.spec.runtimeClassName}') == "$runtime" ]] || die "gVisor pod lost its RuntimeClass"
  [[ $(kubectl get pod "$pod" -o jsonpath='{.spec.nodeName}') == "$CKS_WORKER1_NODE" ]] || die "gVisor pod ran on the wrong node"
  kubectl logs "$pod" | grep -iq gvisor || die "gVisor pod produced no runtime evidence"
)

falco_fresh_event_smoke() (
  require_vars BUSYBOX_IMAGE CKS_WORKER1_NODE
  assert_digest_pinned_image "$BUSYBOX_IMAGE"
  local nonce pod probe_file start_time output deadline
  nonce="$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
  pod="cks-smoke-falco-$$"
  probe_file="/tmp/cks-simulator-falco-smoke-${nonce}"
  trap 'kubectl delete pod "$pod" --ignore-not-found --wait=true >/dev/null 2>&1 || true' EXIT
  start_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  kubectl run "$pod" --image="$BUSYBOX_IMAGE" --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"${CKS_WORKER1_NODE}\"}}" -- \
    sh -c "printf CKS_FALCO_FRESH_EVENT > '${probe_file}'; cat '${probe_file}' >/dev/null; sleep 3"
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${pod}" --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  deadline=$((SECONDS + FALCO_EVENT_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    output=$(kubectl logs --namespace falco --selector app.kubernetes.io/name=falco \
      --container falco --since-time="$start_time" --tail=2000 --prefix=true 2>/dev/null || true)
    if [[ "$output" == *CKS_SIMULATOR_FALCO_SMOKE* && "$output" == *"$probe_file"* ]]; then
      return 0
    fi
    sleep 2
  done
  die "Falco modern eBPF produced no fresh positive event"
)

ingress_generated_tls_smoke() (
  require_vars AGNHOST_IMAGE CKS_WORKER1_IP
  assert_digest_pinned_image "$AGNHOST_IMAGE"
  local namespace="cks-capability-ingress-$$" host=cks-capability.local work http_port https_port
  work=$(mktemp -d)
  trap 'kubectl delete namespace "$namespace" --ignore-not-found --wait=false >/dev/null 2>&1 || true; rm -rf -- "$work"' EXIT
  kubectl get namespace "$namespace" >/dev/null 2>&1 && die "ingress probe namespace already exists"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=${host}" -keyout "${work}/tls.key" -out "${work}/tls.crt" >/dev/null 2>&1
  kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl --namespace "$namespace" create secret tls cks-smoke-tls \
    --cert="${work}/tls.crt" --key="${work}/tls.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: echo, namespace: ${namespace}}
spec:
  replicas: 1
  selector: {matchLabels: {app: echo}}
  template:
    metadata: {labels: {app: echo}}
    spec:
      containers:
        - {name: echo, image: ${AGNHOST_IMAGE}, args: ["netexec", "--http-port=8080"]}
---
apiVersion: v1
kind: Service
metadata: {name: echo, namespace: ${namespace}}
spec:
  selector: {app: echo}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: echo
  namespace: ${namespace}
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
spec:
  ingressClassName: nginx
  tls: [{hosts: [${host}], secretName: cks-smoke-tls}]
  rules:
    - host: ${host}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: echo, port: {number: 80}}}
EOF
  kubectl rollout status deployment/echo --namespace "$namespace" --timeout="${CLUSTER_CHECK_TIMEOUT_SECONDS}s"
  http_port=$(kubectl get service ingress-nginx-controller --namespace ingress-nginx -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}')
  https_port=$(kubectl get service ingress-nginx-controller --namespace ingress-nginx -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
  [[ "$http_port" =~ ^[0-9]+$ && "$https_port" =~ ^[0-9]+$ ]] || die "ingress NodePorts are missing"
  wait_until "$CLUSTER_CHECK_TIMEOUT_SECONDS" 3 curl --fail --silent --show-error --max-time 15 \
    --resolve "${host}:${http_port}:${CKS_WORKER1_IP}" "http://${host}:${http_port}/hostname" >/dev/null || die "ingress HTTP probe failed"
  wait_until "$CLUSTER_CHECK_TIMEOUT_SECONDS" 3 curl --fail --silent --show-error --insecure --max-time 15 \
    --resolve "${host}:${https_port}:${CKS_WORKER1_IP}" "https://${host}:${https_port}/hostname" >/dev/null || die "ingress HTTPS probe failed"
  openssl s_client -connect "${CKS_WORKER1_IP}:${https_port}" -servername "$host" </dev/null 2>/dev/null \
    | openssl x509 -noout -subject | grep -Fq "CN = ${host}"
)

control_plane_check() {
  require_vars HELM_VERSION CILIUM_CLI_VERSION
  [[ "$HELM_VERSION" == 3.21.3 ]] || die "Helm must be 3.21.3"
  assert_output_contains helm "v${HELM_VERSION}" helm version --short
  assert_output_contains cilium "$CILIUM_CLI_VERSION" cilium version --client
  etcdctl_endpoint_health
  kube_bench_training_check control-plane master
}

cluster_check() {
  kubernetes_cilium_health
  cilium_network_policy_smoke
  apparmor_kubernetes_smoke
  gvisor_pod_smoke
  falco_fresh_event_smoke
  ingress_generated_tls_smoke
  kubernetes_cilium_health
}

case "$TARGET" in
  control-plane) control_plane_check ;;
  worker1)
    apparmor_allow_deny_smoke
    gvisor_local_smoke
    kube_bench_training_check worker1 node
    ;;
  worker2)
    docker_and_kubernetes_smoke
    kube_bench_training_check worker2 node
    ;;
  cluster) cluster_check ;;
  network) cilium_network_policy_smoke ;;
  health) kubernetes_cilium_health ;;
  apparmor-pod) apparmor_kubernetes_smoke ;;
  gvisor-pod) gvisor_pod_smoke ;;
  falco) falco_fresh_event_smoke ;;
  ingress) ingress_generated_tls_smoke ;;
  *)
    die "usage: $0 {control-plane|worker1|worker2|network|cluster}"
    exit 2
    ;;
esac

log "${TARGET} behavioral checks passed"
