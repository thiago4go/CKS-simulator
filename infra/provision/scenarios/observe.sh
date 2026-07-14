#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly FIXTURE_ROOT=/opt/cks-simulator/scenarios/fixtures
readonly STATE_ROOT=/var/lib/cks-simulator/scenarios
readonly IDENTITY=/etc/cks-simulator/identity.json
readonly GRADER_CONFIG=/etc/cks-simulator/cks-grader.kubeconfig
readonly DOCKER_SOCKET=unix:///run/docker.sock
readonly MAX_JSON_BYTES=8192

exec 3>&1
exec >/dev/null 2>&1

invalid_request() {
  printf '{"error":"invalid_request","ok":false,"schema":1}\n' >&3
  exit 2
}

observation_failed() {
  trap - ERR
  printf '{"error":"observation_failed","ok":false,"schema":1}\n' >&3
  exit 1
}
trap observation_failed ERR

[[ $# -eq 1 ]] || invalid_request
case "$1" in
  01|02|03|04|05|06|07|08) readonly SCENARIO_ID=$1 ;;
  *) invalid_request ;;
esac
[[ ${EUID} -eq 0 ]]
[[ -f "$IDENTITY" && ! -L "$IDENTITY" ]]
[[ $(stat -c '%u' "$IDENTITY") == 0 ]]
[[ $(stat -c '%s' "$IDENTITY") -le 4096 ]]
ROLE=$(jq -er '.role | select(. == "candidate" or . == "control-plane" or . == "worker1" or . == "worker2")' "$IDENTITY")
readonly ROLE
case "${SCENARIO_ID}:${ROLE}" in
  01:candidate|02:candidate|03:control-plane|04:control-plane|05:control-plane|05:worker1|06:control-plane|07:control-plane|07:worker1|08:worker2) ;;
  *) invalid_request ;;
esac

case "$SCENARIO_ID" in
  01) readonly LIFECYCLE_FILE="$STATE_ROOT/01/lifecycle" ;;
  02) readonly LIFECYCLE_FILE="$STATE_ROOT/02/lifecycle" ;;
  03) readonly LIFECYCLE_FILE="$STATE_ROOT/03/lifecycle" ;;
  04) readonly LIFECYCLE_FILE="$STATE_ROOT/04/lifecycle" ;;
  05) readonly LIFECYCLE_FILE="$STATE_ROOT/05/lifecycle" ;;
  06) readonly LIFECYCLE_FILE="$STATE_ROOT/06/lifecycle" ;;
  07) readonly LIFECYCLE_FILE="$STATE_ROOT/07/lifecycle" ;;
  08) readonly LIFECYCLE_FILE="$STATE_ROOT/08/lifecycle" ;;
esac
[[ -f "$LIFECYCLE_FILE" && ! -L "$LIFECYCLE_FILE" ]]
[[ $(stat -c '%u' "$LIFECYCLE_FILE") == 0 ]]
[[ $(stat -c '%s' "$LIFECYCLE_FILE") -le 16 ]]
LIFECYCLE=$(<"$LIFECYCLE_FILE")
readonly LIFECYCLE
case "$LIFECYCLE" in prepared|reference|restored) ;; *) observation_failed ;; esac

gate() {
  local actual=$1
  [[ "$actual" == true ]] && printf true || printf false
}

fixture_is_trusted() {
  local path=$1
  case "$path" in "$FIXTURE_ROOT"/0[1-8]/*) ;; *) return 1 ;; esac
  [[ -f "$path" && ! -L "$path" ]]
  [[ $(stat -c '%u' "$path") == 0 ]]
  [[ $(( 8#$(stat -c '%a' "$path") & 8#022 )) -eq 0 ]]
  [[ $(stat -c '%s' "$path") -le 2097152 ]]
}

o01() {
  local contexts=false pem=false match=false
  fixture_is_trusted "$FIXTURE_ROOT/01/contexts.txt"
  fixture_is_trusted "$FIXTURE_ROOT/01/restricted.crt"
  if [[ -f /opt/course/1/contexts && ! -L /opt/course/1/contexts ]] \
    && [[ $(stat -c '%s' /opt/course/1/contexts) -le 4096 ]] \
    && cmp -s -- "$FIXTURE_ROOT/01/contexts.txt" /opt/course/1/contexts; then
    contexts=true
  fi
  if [[ -f /opt/course/1/cert && ! -L /opt/course/1/cert ]] \
    && [[ $(stat -c '%s' /opt/course/1/cert) -le 16384 ]] \
    && openssl x509 -in /opt/course/1/cert -noout; then
    pem=true
  fi
  if [[ "$pem" == true ]] && cmp -s -- "$FIXTURE_ROOT/01/restricted.crt" /opt/course/1/cert; then
    match=true
  fi
  jq -cn --argjson contexts "$(gate "$contexts")" --argjson pem "$(gate "$pem")" \
    --argjson match "$(gate "$match")" \
    '{"contexts-exact":$contexts,"certificate-pem":$pem,"certificate-match":$match}'
}

o02() {
  local output=false inputs=false database=false absent=false
  fixture_is_trusted "$FIXTURE_ROOT/02/scan-results.json"
  fixture_is_trusted "$FIXTURE_ROOT/02/good-images.txt"
  if [[ -f /opt/course/2/good-images && ! -L /opt/course/2/good-images ]] \
    && [[ $(stat -c '%s' /opt/course/2/good-images) -le 4096 ]] \
    && cmp -s -- "$FIXTURE_ROOT/02/good-images.txt" /opt/course/2/good-images; then
    output=true
  fi
  if jq -e '
    .schema == 1 and
    ([.images[].name] == [
      "nginx:1.16.1-alpine",
      "k8s.gcr.io/kube-apiserver:v1.18.0",
      "k8s.gcr.io/kube-controller-manager:v1.18.0",
      "docker.io/weaveworks/weave-kube:2.7.0"
    ])
  ' "$FIXTURE_ROOT/02/scan-results.json" >/dev/null; then
    inputs=true
  fi
  if jq -e '.database == "cks-simulator-u7-2026-07-14"' "$FIXTURE_ROOT/02/scan-results.json" >/dev/null; then
    database=true
  fi
  if [[ "$output" == true ]] && jq -e '
    ([.images[] | select(.name == "docker.io/weaveworks/weave-kube:2.7.0") | .vulnerabilities] == [[]]) and
    ([.images[] | select(.vulnerabilities | index("CVE-2020-10878") or index("CVE-2020-1967")) | .name] | length == 3)
  ' "$FIXTURE_ROOT/02/scan-results.json" >/dev/null; then
    absent=true
  fi
  jq -cn --argjson output "$(gate "$output")" --argjson absent "$(gate "$absent")" \
    '{"scan-output-exact":$output,"forbidden-cves-absent":$absent}'
}

o03() {
  local object service=false nodeport=false ready=false
  [[ -f "$GRADER_CONFIG" && ! -L "$GRADER_CONFIG" ]]
  if object=$(timeout 30 kubectl --kubeconfig="$GRADER_CONFIG" --namespace default \
    get service kubernetes -o json); then
    ready=true
    if jq -e '.spec.type == "ClusterIP"' <<<"$object" >/dev/null; then service=true; fi
    if jq -e '(.spec.ports | all((.nodePort // null) == null))' <<<"$object" >/dev/null; then nodeport=true; fi
  fi
  jq -cn --argjson service "$(gate "$service")" --argjson nodeport "$(gate "$nodeport")" \
    '{"service-clusterip":$service,"nodeport-absent":$nodeport}'
}

o04() {
  local object pods service_account=false automount=false projected=false expiration=false mount=false ready=false
  [[ -f "$GRADER_CONFIG" && ! -L "$GRADER_CONFIG" ]]
  if object=$(timeout 30 kubectl --kubeconfig="$GRADER_CONFIG" --namespace team-coral \
    get deployment stream-multiplex -o json); then
    jq -e '.spec.template.spec.serviceAccountName == "stream-multiplex"' <<<"$object" >/dev/null && service_account=true
    jq -e '.spec.template.spec.automountServiceAccountToken == false' <<<"$object" >/dev/null && automount=true
    jq -e '[.spec.template.spec.volumes[]? | select(.projected.sources[]?.serviceAccountToken.path == "token")] | length == 1' <<<"$object" >/dev/null && projected=true
    jq -e '[.spec.template.spec.volumes[]?.projected.sources[]?.serviceAccountToken.expirationSeconds] | index(1200) != null' <<<"$object" >/dev/null && expiration=true
    jq -e '[.spec.template.spec.containers[].volumeMounts[]? | select((.mountPath == "/var/run/secrets/custom" or .mountPath == "/var/run/secrets/custom/") and .readOnly == true)] | length == 1' <<<"$object" >/dev/null && mount=true
  fi
  if pods=$(timeout 30 kubectl --kubeconfig="$GRADER_CONFIG" --namespace team-coral \
    get pods -l app=stream-multiplex -o json); then
    jq -e '[.items[] | select(.status.phase == "Running" and ((.status.containerStatuses // []) | length > 0 and all(.ready == true)) and (.spec.nodeName | endswith("-worker1")))] | length >= 1' <<<"$pods" >/dev/null && ready=true
  fi
  jq -cn --argjson service_account "$(gate "$service_account")" --argjson automount "$(gate "$automount")" \
    --argjson projected "$(gate "$projected")" --argjson expiration "$(gate "$expiration")" \
    --argjson mount "$(gate "$mount")" \
    '{"service-account":$service_account,"automount-disabled":$automount,"projected-token":$projected,"expiration-1200":$expiration,"readonly-mount":$mount}'
}

o05_control() {
  local profiling=false owner=false
  if [[ -f /etc/kubernetes/manifests/kube-controller-manager.yaml \
    && ! -L /etc/kubernetes/manifests/kube-controller-manager.yaml ]] \
    && grep -Eq '^[[:space:]]*-[[:space:]]*--profiling=false[[:space:]]*$' \
      /etc/kubernetes/manifests/kube-controller-manager.yaml; then
    profiling=true
  fi
  if [[ -d /var/lib/etcd && ! -L /var/lib/etcd ]] \
    && [[ $(stat -c '%U:%G' /var/lib/etcd) == etcd:etcd ]]; then
    owner=true
  fi
  jq -cn --argjson profiling "$(gate "$profiling")" --argjson owner "$(gate "$owner")" \
    '{"profiling-disabled":$profiling,"etcd-owner":$owner}'
}

o05_worker() {
  local mode=false ca=false
  if [[ -f /var/lib/kubelet/config.yaml && ! -L /var/lib/kubelet/config.yaml ]] \
    && [[ $(stat -c '%a' /var/lib/kubelet/config.yaml) == 600 ]]; then
    mode=true
  fi
  if grep -Eq '^[[:space:]]*clientCAFile:[[:space:]]*/etc/kubernetes/pki/ca.crt[[:space:]]*$' \
    /var/lib/kubelet/config.yaml; then
    ca=true
  fi
  jq -cn --argjson mode "$(gate "$mode")" --argjson ca "$(gate "$ca")" \
    '{"kubelet-mode":$mode,"client-ca":$ca}'
}

o06() {
  local object pods root=false tmp=false ready=false
  [[ -f "$GRADER_CONFIG" && ! -L "$GRADER_CONFIG" ]]
  if object=$(timeout 30 kubectl --kubeconfig="$GRADER_CONFIG" --namespace team-purple \
    get deployment immutable-deployment -o json); then
    jq -e '.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem == true' <<<"$object" >/dev/null && root=true
    jq -e '
      ([.spec.template.spec.volumes[]? | select(.emptyDir != null)] | length == 1) and
      ([.spec.template.spec.containers[].volumeMounts[]? | select(.mountPath == "/tmp")] | length == 1)
    ' <<<"$object" >/dev/null && tmp=true
  fi
  if pods=$(timeout 30 kubectl --kubeconfig="$GRADER_CONFIG" --namespace team-purple \
    get pods -l app=immutable-deployment -o json); then
    jq -e '[.items[] | select(.status.phase == "Running" and ((.status.containerStatuses // []) | length > 0 and all(.ready == true)) and (.spec.nodeName | endswith("-worker2")))] | length >= 1' <<<"$pods" >/dev/null && ready=true
  fi
  jq -cn --argjson root "$(gate "$root")" --argjson tmp "$(gate "$tmp")" \
    '{"readonly-root":$root,"tmp-emptydir":$tmp}'
}

o07() {
  local namespace pod audit=false warn=false admitted=false warning=false
  if [[ "$ROLE" == worker1 ]]; then
    fixture_is_trusted "$FIXTURE_ROOT/07/reference-warning.txt"
    if [[ -f /opt/course/7/bad-pod.log && ! -L /opt/course/7/bad-pod.log ]] \
      && [[ $(stat -c '%s' /opt/course/7/bad-pod.log) -le 8192 ]] \
      && cmp -s -- "$FIXTURE_ROOT/07/reference-warning.txt" /opt/course/7/bad-pod.log; then
      warning=true
    fi
    jq -cn --argjson warning "$(gate "$warning")" '{"warning-recorded":$warning}'
    return
  fi
  [[ "$ROLE" == control-plane ]]
  [[ -f "$GRADER_CONFIG" && ! -L "$GRADER_CONFIG" ]]
  if namespace=$(timeout 30 kubectl --kubeconfig="$GRADER_CONFIG" get namespace team-sepia -o json); then
    jq -e '.metadata.labels["pod-security.kubernetes.io/audit"] == "baseline"' <<<"$namespace" >/dev/null && audit=true
    jq -e '.metadata.labels["pod-security.kubernetes.io/warn"] == "restricted"' <<<"$namespace" >/dev/null && warn=true
  fi
  if pod=$(timeout 30 kubectl --kubeconfig="$GRADER_CONFIG" --namespace team-sepia get pod bad-pod -o json); then
    jq -e '.spec.containers[0].securityContext.privileged == true' <<<"$pod" >/dev/null && admitted=true
  fi
  jq -cn --argjson audit "$(gate "$audit")" --argjson warn "$(gate "$warn")" \
    --argjson admitted "$(gate "$admitted")" \
    '{"audit-baseline":$audit,"warn-restricted":$warn,"bad-pod-admitted":$admitted}'
}

o08() {
  local icc=false one=false two=false isolated=false pinned_id=''
  if [[ -f /etc/docker/daemon.json && ! -L /etc/docker/daemon.json ]] \
    && jq -e '.icc == false' /etc/docker/daemon.json >/dev/null; then
    icc=true
  fi
  pinned_id=$(timeout 15 docker --host "$DOCKER_SOCKET" image inspect nginx:1-alpine \
    --format '{{.Id}}' 2>/dev/null || true)
  if timeout 15 docker --host "$DOCKER_SOCKET" inspect container1 \
    | jq -e --arg image_id "$pinned_id" '.[0].State.Running == true and .[0].HostConfig.RestartPolicy.Name == "always" and .[0].Config.Image == "nginx:1-alpine" and .[0].Image == $image_id' >/dev/null; then
    one=true
  fi
  if timeout 15 docker --host "$DOCKER_SOCKET" inspect container2 \
    | jq -e --arg image_id "$pinned_id" '.[0].State.Running == true and .[0].HostConfig.RestartPolicy.Name == "always" and .[0].Config.Image == "nginx:1-alpine" and .[0].Image == $image_id' >/dev/null; then
    two=true
  fi
  if timeout 15 docker --host "$DOCKER_SOCKET" network inspect bridge \
    | jq -e '.[0].Options["com.docker.network.bridge.enable_icc"] == "false"' >/dev/null; then
    isolated=true
  fi
  jq -cn --argjson icc "$(gate "$icc")" \
    --argjson one "$(gate "$one")" --argjson two "$(gate "$two")" \
    --argjson isolated "$(gate "$isolated")" \
    '{"icc-disabled":$icc,"container1":$one,"container2":$two,"containers-isolated":$isolated}'
}

case "${SCENARIO_ID}:${ROLE}" in
  01:candidate) checks=$(o01) ;;
  02:candidate) checks=$(o02) ;;
  03:control-plane) checks=$(o03) ;;
  04:control-plane) checks=$(o04) ;;
  05:control-plane) checks=$(o05_control) ;;
  05:worker1) checks=$(o05_worker) ;;
  06:control-plane) checks=$(o06) ;;
  07:control-plane) checks=$(o07) ;;
  07:worker1) checks=$(o07) ;;
  08:worker2) checks=$(o08) ;;
  *) invalid_request ;;
esac
readonly checks
state_sha256=$(jq -cn --arg scenario_id "$SCENARIO_ID" --arg role "$ROLE" \
  --arg lifecycle "$LIFECYCLE" --argjson checks "$checks" \
  '{checks:$checks,lifecycle:$lifecycle,role:$role,scenario_id:$scenario_id}' \
  | sha256sum | awk '{print $1}')
readonly state_sha256
record=$(jq -cn --arg scenario_id "$SCENARIO_ID" --arg role "$ROLE" \
  --arg lifecycle "$LIFECYCLE" --argjson checks "$checks" --arg state_sha256 "$state_sha256" \
  '{checks:$checks,lifecycle:$lifecycle,role:$role,scenario_id:$scenario_id,schema:1,state_sha256:$state_sha256}')
readonly record
[[ ${#record} -le MAX_JSON_BYTES ]]
printf '%s\n' "$record" >&3
