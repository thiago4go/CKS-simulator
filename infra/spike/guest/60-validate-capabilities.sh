#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly PHASE=${1:?phase is required}
readonly WORKER1_NODE=${2:?worker1 node is required}
readonly WORKER2_NODE=${3:?worker2 node is required}
readonly WORKER1_IP=${4:?worker1 IP is required}
readonly VERSIONS=/tmp/cks-spike-versions.json
readonly PROBES=/var/lib/cks-simulator/probes
# Keep the repeatable regression local and deterministic. These two exact
# upstream tests provide service-loopback and packet-drop validation; the
# dedicated NetworkPolicy probe below owns explicit allow/deny enforcement.
# Cilium filters qualified "test/scenario" names, so both halves are explicit.
readonly CILIUM_LOCAL_TESTS='(pod-to-itself-via-service/pod-to-itself-via-service|no-unexpected-packet-drops/no-unexpected-packet-drops)$'
export KUBECONFIG=/etc/kubernetes/admin.conf
mkdir -p "$PROBES"

json() { jq -er "$1" "$VERSIONS"; }

probe() {
  local name=$1 rc
  shift
  printf 'PROBE_START %s\n' "$name"
  set +e
  (
    set -Eeuo pipefail
    "$@"
  )
  rc=$?
  set -e
  if ((rc == 0)); then
    printf 'PROBE_PASS %s\n' "$name"
    printf 'PROBE_RESULT %s PASS\n' "$name"
  else
    printf 'PROBE_FAIL %s rc=%s\n' "$name" "$rc" >&2
    printf 'PROBE_RESULT %s FAIL\n' "$name"
    return "$rc"
  fi
}

cilium_version_probe() {
  cilium version --client | grep -F "v$(json '.cilium.cli_version')" >/dev/null
  kubectl -n kube-system rollout status daemonset/cilium --timeout=5m
  kubectl -n kube-system rollout status daemonset/cilium-envoy --timeout=5m
  cilium status --wait --wait-duration 5m
  kubectl -n kube-system get daemonset cilium -o json | jq -e '
    .status.desiredNumberScheduled == 3 and
    .status.numberReady == 3 and
    .status.numberAvailable == 3
  ' >/dev/null
  kubectl -n kube-system get daemonset cilium-envoy -o json | jq -e '
    .status.desiredNumberScheduled == 3 and
    .status.numberReady == 3 and
    .status.numberAvailable == 3
  ' >/dev/null
}

cilium_connectivity_probe() {
  local output rc
  set +e
  output=$(timeout 12m cilium connectivity test --test "$CILIUM_LOCAL_TESTS" --test-concurrency 1 2>&1)
  rc=$?
  set -e
  printf '%s\n' "$output"
  ((rc == 0)) || return "$rc"
  grep -F 'Test [pod-to-itself-via-service]' <<< "$output" >/dev/null
  grep -F 'Test [no-unexpected-packet-drops]' <<< "$output" >/dev/null
  grep -F 'All 2 tests (4 actions) successful' <<< "$output" >/dev/null
}

post_docker_cilium_probe() {
  cilium_version_probe
  cilium_connectivity_probe
}

network_policy_probe() {
  local agnhost busybox
  agnhost=$(json '.workload_images.agnhost')
  busybox=$(json '.workload_images.busybox')
  cat > "$PROBES/network-policy.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata: {name: cks-cap-net}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: server, namespace: cks-cap-net}
spec:
  replicas: 1
  selector: {matchLabels: {app: server}}
  template:
    metadata: {labels: {app: server}}
    spec:
      containers:
        - name: server
          image: $agnhost
          args: ["netexec", "--http-port=8080"]
---
apiVersion: v1
kind: Service
metadata: {name: server, namespace: cks-cap-net}
spec:
  selector: {app: server}
  ports: [{port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata: {name: allowed, namespace: cks-cap-net, labels: {access: allowed}}
spec:
  containers:
    - {name: client, image: $busybox, command: ["sh", "-c", "sleep 3600"]}
---
apiVersion: v1
kind: Pod
metadata: {name: denied, namespace: cks-cap-net, labels: {access: denied}}
spec:
  containers:
    - {name: client, image: $busybox, command: ["sh", "-c", "sleep 3600"]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: server-ingress, namespace: cks-cap-net}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {access: allowed}}
      ports: [{protocol: TCP, port: 8080}]
EOF
  kubectl apply -f "$PROBES/network-policy.yaml" >/dev/null
  kubectl rollout status -n cks-cap-net deployment/server --timeout=5m
  kubectl wait -n cks-cap-net --for=condition=Ready pod/allowed pod/denied --timeout=5m
  kubectl exec -n cks-cap-net allowed -- wget -qO- --timeout=5 http://server:8080/hostname >/dev/null
  if kubectl exec -n cks-cap-net denied -- wget -qO- --timeout=5 http://server:8080/hostname >/dev/null 2>&1; then
    echo "denied client unexpectedly reached the server" >&2
    return 1
  fi
}

apparmor_probe() {
  local busybox
  busybox=$(json '.workload_images.busybox')
  cat > "$PROBES/apparmor.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: apparmor-denial}
spec:
  nodeName: $WORKER1_NODE
  restartPolicy: Never
  containers:
    - name: denial
      image: $busybox
      securityContext:
        appArmorProfile:
          type: Localhost
          localhostProfile: cks-deny-write
      command: ["sh", "-c", "if echo should-fail >/tmp/cks-denied; then exit 42; else echo APPARMOR_DENIED; fi"]
EOF
  kubectl delete pod apparmor-denial --ignore-not-found --wait=true >/dev/null
  kubectl apply -f "$PROBES/apparmor.yaml" >/dev/null
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/apparmor-denial --timeout=5m
  kubectl logs apparmor-denial | grep -Fx APPARMOR_DENIED
}

gvisor_probe() {
  local busybox
  busybox=$(json '.workload_images.busybox')
  cat > "$PROBES/gvisor.yaml" <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: runsc-systrap}
handler: runsc
---
apiVersion: v1
kind: Pod
metadata: {name: gvisor-systrap}
spec:
  nodeName: $WORKER1_NODE
  runtimeClassName: runsc-systrap
  restartPolicy: Never
  containers:
    - name: probe
      image: $busybox
      command: ["sh", "-c", "dmesg | grep -i gvisor"]
EOF
  kubectl delete pod gvisor-systrap --ignore-not-found --wait=true >/dev/null
  kubectl apply -f "$PROBES/gvisor.yaml" >/dev/null
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/gvisor-systrap --timeout=5m
  kubectl logs gvisor-systrap | grep -i gvisor
}

falco_probe() {
  local busybox falco_image falco_image_tag nonce output pod_name probe_file rendered_image rendered_images start_time
  busybox=$(json '.workload_images.busybox')
  falco_image=$(json '.falco.image')
  test "$falco_image" = 'docker.io/falcosecurity/falco:0.44.1@sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b'
  falco_image_tag=${falco_image#docker.io/falcosecurity/falco:}
  nonce="$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
  probe_file="cks-falco-$nonce"
  cat > "$PROBES/falco-values.yaml" <<EOF
image:
  registry: docker.io
  repository: falcosecurity/falco
  tag: "$falco_image_tag"
driver:
  kind: modern_ebpf
  loader:
    enabled: false
collectors:
  enabled: false
falcoctl:
  artifact:
    install:
      enabled: false
    follow:
      enabled: false
falco:
  # The pinned image ships config.d/falco.container_plugin.yaml. Excluding the
  # image-level config directory and bundled rules keeps this probe syscall-only
  # and prevents an undeclared, mutable container-plugin dependency.
  config_files: []
  rules_files:
    - /etc/falco/rules.d
customRules:
  cks-sensitive-file.yaml: |-
    - rule: CKS unique runtime file read
      desc: Detect the unique syscall generated by the CKS capability probe
      condition: evt.type in (open, openat, openat2) and fd.name = /tmp/$probe_file
      output: "CKS_RUNTIME_EVENT nonce=$nonce file=%fd.name proc=%proc.name"
      priority: WARNING
      tags: [filesystem, cks]
EOF
  helm template falco /var/lib/cks-simulator/downloads/falco.tgz \
    --namespace falco --skip-tests --values "$PROBES/falco-values.yaml" \
    > "$PROBES/falco-rendered.yaml"
  rendered_images=$(awk '$1 == "image:" {gsub(/"/, "", $2); print $2}' "$PROBES/falco-rendered.yaml")
  test -n "$rendered_images"
  while IFS= read -r rendered_image; do
    if [[ $rendered_image != *@sha256:* || $rendered_image != "$falco_image" ]]; then
      printf 'unpinned or unexpected Falco pod image: %s\n' "$rendered_image" >&2
      return 1
    fi
  done <<< "$rendered_images"
  helm upgrade --install falco /var/lib/cks-simulator/downloads/falco.tgz \
    --namespace falco --create-namespace \
    --values "$PROBES/falco-values.yaml" \
    --wait --timeout 12m
  helm get values falco -n falco -o json | jq -e --arg tag "$falco_image_tag" '
    .image.registry == "docker.io" and
    .image.repository == "falcosecurity/falco" and
    .image.tag == $tag and
    .driver.kind == "modern_ebpf" and
    .driver.loader.enabled == false and
    .collectors.enabled == false and
    .falcoctl.artifact.install.enabled == false and
    .falcoctl.artifact.follow.enabled == false and
    .falco.config_files == [] and
    .falco.rules_files == ["/etc/falco/rules.d"]
  ' >/dev/null
  kubectl -n falco exec daemonset/falco -c falco -- falco --version | grep -F "$(json '.falco.version')" >/dev/null
  pod_name="falco-event-$nonce"
  start_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  kubectl run "$pod_name" --image="$busybox" --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$WORKER1_NODE\"}}" \
    -- sh -c "printf cks-runtime-event > /tmp/$probe_file; cat /tmp/$probe_file >/dev/null; sleep 3"
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$pod_name" --timeout=5m
  for _ in $(seq 1 60); do
    output=$(kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco \
      --since-time="$start_time" --tail=2000 --prefix=true 2>/dev/null || true)
    while IFS= read -r line; do
      if [[ $line == *"$nonce"* && $line == *CKS_RUNTIME_EVENT* && $line == *"/tmp/$probe_file"* ]]; then
        kubectl delete pod "$pod_name" --wait=true >/dev/null
        return 0
      fi
    done <<< "$output"
    sleep 2
  done
  kubectl delete pod "$pod_name" --ignore-not-found --wait=true >/dev/null
  return 1
}

trivy_probe() {
  local busybox
  busybox=$(json '.workload_images.busybox')
  cat > "$PROBES/trivy.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: {name: deliberately-privileged}
spec:
  containers:
    - name: shell
      image: $busybox
      securityContext: {privileged: true}
EOF
  trivy --version | grep -F "Version: $(json '.trivy.version')" >/dev/null
  trivy config --quiet --format json "$PROBES/trivy.yaml" > "$PROBES/trivy-result.json"
  jq -e '
    def finding_text:
      [
        .ID?, .AVDID?, .Title?, .Description?, .Message?, .Resolution?,
        (.CauseMetadata? | .. | select(type == "string")),
        (.IacMetadata? | .. | select(type == "string"))
      ]
      | map(select(type == "string"))
      | join(" ")
      | ascii_downcase;
    [
      .Results[]?.Misconfigurations[]?
      | select(((.Status? // "FAIL") | ascii_upcase) == "FAIL")
      | . as $finding
      | finding_text as $text
      | select(
          (($finding.Title? // "") | ascii_downcase | test("privileged[[:space:]-]+container")) or
          ($text | test("securitycontext[[:space:]./_-]*privileged"))
        )
    ]
    | length > 0
  ' "$PROBES/trivy-result.json" >/dev/null
}

kube_bench_training_probe() {
  local rc=0
  kube-bench version | grep -F "$(json '.kube_bench.version')" >/dev/null
  set +e
  timeout 180 kube-bench run --targets master,node --config-dir /usr/local/share/kube-bench/cfg --json \
    > "$PROBES/kube-bench-training.json" 2> "$PROBES/kube-bench-training.stderr"
  rc=$?
  set -e
  printf 'KUBE_BENCH_TRAINING_ONLY rc=%s\n' "$rc"
  case "$rc" in
    0|1) ;;
    *)
      printf 'kube-bench exited unexpectedly; see %s\n' "$PROBES/kube-bench-training.stderr" >&2
      return "$rc"
      ;;
  esac
  jq -e '
    type == "object" and
    (.Controls | type == "array" and length > 0) and
    any(.Controls[]?; any(.tests[]?; (.results | type == "array" and length > 0)))
  ' "$PROBES/kube-bench-training.json" >/dev/null
}

ingress_tls_probe() {
  local agnhost https_port
  agnhost=$(json '.workload_images.agnhost')
  helm upgrade --install ingress-nginx /var/lib/cks-simulator/downloads/ingress-nginx.tgz \
    --namespace ingress-nginx --create-namespace \
    --set controller.service.type=NodePort \
    --wait --timeout 12m
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=cks-cap.local' \
    -keyout "$PROBES/tls.key" -out "$PROBES/tls.crt" >/dev/null 2>&1
  kubectl create namespace cks-cap-ingress --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n cks-cap-ingress create secret tls cks-cap-tls --cert="$PROBES/tls.crt" --key="$PROBES/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  cat > "$PROBES/ingress.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: echo, namespace: cks-cap-ingress}
spec:
  replicas: 1
  selector: {matchLabels: {app: echo}}
  template:
    metadata: {labels: {app: echo}}
    spec:
      containers:
        - {name: echo, image: $agnhost, args: ["netexec", "--http-port=8080"]}
---
apiVersion: v1
kind: Service
metadata: {name: echo, namespace: cks-cap-ingress}
spec:
  selector: {app: echo}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: echo, namespace: cks-cap-ingress}
spec:
  ingressClassName: nginx
  tls: [{hosts: [cks-cap.local], secretName: cks-cap-tls}]
  rules:
    - host: cks-cap.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: echo, port: {number: 80}}}
EOF
  kubectl apply -f "$PROBES/ingress.yaml" >/dev/null
  kubectl rollout status -n cks-cap-ingress deployment/echo --timeout=5m
  https_port=$(kubectl -n ingress-nginx get service ingress-nginx-controller -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
  timeout 180 bash -c "until curl --fail --silent --insecure --resolve cks-cap.local:${https_port}:${WORKER1_IP} https://cks-cap.local:${https_port}/hostname >/dev/null; do sleep 3; done"
  openssl s_client -connect "$WORKER1_IP:$https_port" -servername cks-cap.local </dev/null 2>/dev/null \
    | openssl x509 -noout -subject | grep -F 'CN = cks-cap.local'
}

case "$PHASE" in
  baseline)
    probe kubernetes-version test "$(kubectl version -o json | jq -r '.serverVersion.gitVersion')" = "v$(json '.kubernetes.version')"
    probe nodes-ready kubectl wait --for=condition=Ready nodes --all --timeout=5m
    probe cilium-version cilium_version_probe
    probe cilium-connectivity-before-docker cilium_connectivity_probe
    probe cilium-network-policy network_policy_probe
    probe apparmor-denial apparmor_probe
    probe gvisor-systrap gvisor_probe
    probe falco-modern-ebpf-event falco_probe
    probe trivy-config trivy_probe
    probe kube-bench-training-only kube_bench_training_probe
    probe ingress-tls ingress_tls_probe
    ;;
  post-docker)
    probe nodes-ready-after-docker kubectl wait --for=condition=Ready nodes --all --timeout=5m
    probe cilium-connectivity-after-docker post_docker_cilium_probe
    ;;
  *) echo "unknown phase: $PHASE" >&2; exit 2 ;;
esac
