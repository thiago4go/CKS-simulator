#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly FIXTURE_ROOT=/opt/cks-simulator/scenarios/fixtures
readonly STATE_ROOT=/var/lib/cks-simulator/scenarios
readonly IDENTITY=/etc/cks-simulator/identity.json
readonly GRADER_CONFIG=/etc/cks-simulator/cks-grader.kubeconfig
readonly TOOLS_ENV=/etc/cks-simulator/scenario.env
readonly APISERVER_MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml
readonly MAX_JSON_BYTES=16384

exec 3>&1
exec >/dev/null 2>&1

invalid() { printf '{"error":"invalid_request","ok":false,"schema":1}\n' >&3; exit 2; }
failed() { trap - ERR; printf '{"error":"observation_failed","ok":false,"schema":1}\n' >&3; exit 1; }
trap failed ERR

[[ $# -eq 1 ]] || invalid
case "$1" in 09|10|11|12|13|14|15|16|17) readonly SCENARIO_ID=$1 ;; *) invalid ;; esac
[[ ${EUID} -eq 0 ]]
ROLE=$(jq -er '.role | select(. == "candidate" or . == "control-plane" or . == "worker1" or . == "worker2")' "$IDENTITY")
readonly ROLE
case "${SCENARIO_ID}:${ROLE}" in
  09:candidate|09:control-plane|09:worker1|10:candidate|10:control-plane|10:worker1|\
  11:control-plane|12:control-plane|13:control-plane|13:worker2|14:control-plane|\
  15:control-plane|16:candidate|16:control-plane|17:control-plane) ;;
  *) invalid ;;
esac

readonly LIFECYCLE_FILE=${STATE_ROOT}/${SCENARIO_ID}/lifecycle
[[ -f "$LIFECYCLE_FILE" && ! -L "$LIFECYCLE_FILE" ]]
[[ $(stat -c '%u' "$LIFECYCLE_FILE") == 0 ]]
LIFECYCLE=$(<"$LIFECYCLE_FILE")
readonly LIFECYCLE
case "$LIFECYCLE" in prepared|reference|restored) ;; *) failed ;; esac

gate() { [[ "$1" == true ]] && printf true || printf false; }
gkube() { timeout 60 kubectl --kubeconfig="$GRADER_CONFIG" "$@"; }
manifest_json() { kubectl patch --local --type=merge -f "$APISERVER_MANIFEST" --patch='{}' -o json; }

o09_candidate() {
  local logs=false
  [[ -s /opt/course/9/logs && ! -L /opt/course/9/logs ]] && logs=true
  jq -cn --argjson logs "$(gate "$logs")" '{"logs-recorded":$logs}'
}

o09_worker() {
  local loaded=false
  aa-status --enabled
  aa-status --json | jq -e '.profiles["k8s-apparmor-deny-write"] != null' >/dev/null && loaded=true
  jq -cn --argjson loaded "$(gate "$loaded")" '{"profile-loaded":$loaded}'
}

o09_control() {
  local node deployment pods label=false profile=false denied=false
  node=$(gkube get nodes -o json)
  jq -e '[.items[] | select(.metadata.name | endswith("-worker1")) | select(.metadata.labels.security == "apparmor")] | length == 1' <<<"$node" >/dev/null && label=true
  if deployment=$(gkube --namespace default get deployment apparmor -o json); then
    jq -e '.spec.template.spec.nodeSelector.security == "apparmor" and
      (.spec.template.spec.containers | length == 1) and
      .spec.template.spec.containers[0].name == "c1" and
      .spec.template.spec.containers[0].securityContext.appArmorProfile == {type:"Localhost",localhostProfile:"k8s-apparmor-deny-write"}' <<<"$deployment" >/dev/null && profile=true
  fi
  if pods=$(gkube --namespace default get pods -l app=apparmor -o json); then
    jq -e '[.items[].status.containerStatuses[]? | select((.restartCount > 0) or (.state.waiting.reason == "CrashLoopBackOff") or (.lastState.terminated.exitCode > 0))] | length > 0' <<<"$pods" >/dev/null && denied=true
  fi
  jq -cn --argjson label "$(gate "$label")" --argjson profile "$(gate "$profile")" --argjson denied "$(gate "$denied")" \
    '{"node-label":$label,"deployment-profile":$profile,"pod-denied":$denied}'
}

o10_candidate() {
  local evidence=false
  [[ -s /opt/course/10/gvisor-test-dmesg && ! -L /opt/course/10/gvisor-test-dmesg ]] \
    && grep -qi gvisor /opt/course/10/gvisor-test-dmesg && evidence=true
  jq -cn --argjson evidence "$(gate "$evidence")" '{"dmesg-evidence":$evidence}'
}

o10_control() {
  local runtime pod handler=false class=false node=false
  if runtime=$(gkube get runtimeclass gvisor -o json); then
    jq -e '.handler == "runsc"' <<<"$runtime" >/dev/null && handler=true
  fi
  if pod=$(gkube --namespace team-purple get pod gvisor-test -o json); then
    jq -e '.spec.runtimeClassName == "gvisor" and .status.phase == "Running"' <<<"$pod" >/dev/null && class=true
    jq -e '.spec.nodeName | endswith("-worker1")' <<<"$pod" >/dev/null && node=true
  fi
  jq -cn --argjson handler "$(gate "$handler")" --argjson class "$(gate "$class")" --argjson node "$(gate "$node")" \
    '{"runtimeclass-handler":$handler,"pod-runtime":$class,"pod-worker1":$node}'
}

o10_worker() {
  local process=false
  ps -eo args= | grep -F '/usr/local/bin/containerd-shim-runsc-v1' | grep -v -F 'grep -F' | grep -q . && process=true
  jq -cn --argjson process "$(gate "$process")" '{"runtime-process":$process}'
}

o11() {
  local db user app cm deployments pods active=false password=false moved=false converted=false removed=false consumers=false ready=false
  if db=$(gkube --namespace team-khaki-us-east-ad1 get secret db-con -o json); then
    active=true
    [[ $(jq -r '.data.password // ""' <<<"$db" | base64 -d) == '4c!29f_Ee2e' ]] && password=true
  fi
  if user=$(gkube --namespace team-khaki-us-east-ad2 get secret user-data -o json); then
    [[ $(jq -r '.data.username // ""' <<<"$user" | base64 -d) == system ]] && moved=true
  fi
  if app=$(gkube --namespace team-khaki-us-east-ad1 get secret app-data -o json); then
    [[ $(jq -r '.data.host // ""' <<<"$app" | base64 -d) == db.team-khaki ]] \
      && [[ $(jq -r '.data.user // ""' <<<"$app" | base64 -d) == system ]] && converted=true
  fi
  if [[ "$active" == true ]]; then
    if ! gkube --namespace team-khaki-us-east-ad1 get configmap app-data >/dev/null 2>&1; then removed=true; fi
    if deployments=$(gkube --namespace team-khaki-us-east-ad1 get deployment app-db app-green-sky -o json); then
      jq -e '([.items[] | select(.metadata.name == "app-db") | .spec.template.spec.containers[0].envFrom[0].secretRef.name] == ["db-con"]) and ([.items[] | select(.metadata.name == "app-green-sky") | .spec.template.spec.containers[0].envFrom[0].secretRef.name] == ["app-data"])' <<<"$deployments" >/dev/null && consumers=true
    fi
    if pods=$(gkube --namespace team-khaki-us-east-ad1 get pods -o json); then
      jq -e '[.items[] | select(.status.phase == "Running" and ((.status.containerStatuses // []) | length > 0 and all(.ready == true)) and (.spec.nodeName | endswith("-worker2")))] | length >= 2' <<<"$pods" >/dev/null \
        && [[ "$consumers" == true ]] && ready=true
    fi
  fi
  jq -cn --argjson password "$(gate "$password")" --argjson moved "$(gate "$moved")" \
    --argjson converted "$(gate "$converted")" --argjson removed "$(gate "$removed")" \
    --argjson consumers "$(gate "$consumers")" --argjson ready "$(gate "$ready")" \
    '{"password-updated":$password,"user-data-moved":$moved,"app-data-secret":$converted,"configmap-removed":$removed,"consumers-updated":$consumers,"consumers-ready":$ready}'
}

o12() {
  local manifest ip review config=false enabled=false backend_raw=false allowed_raw=false backend=false denied=false allowed=false
  manifest=$(manifest_json)
  jq -e '[.spec.containers[0].command[] | select(. == "--admission-control-config-file=/etc/kubernetes/webhook/admission-config.yaml")] | length == 1' <<<"$manifest" >/dev/null \
    && jq -e '[.spec.containers[0].volumeMounts[] | select(.mountPath == "/etc/kubernetes/webhook")] | length == 1' <<<"$manifest" >/dev/null && config=true
  jq -e '[.spec.containers[0].command[] | select(startswith("--enable-admission-plugins=") and contains("ImagePolicyWebhook"))] | length == 1' <<<"$manifest" >/dev/null && enabled=true
  if systemctl is-active --quiet cks-image-policy-webhook.service \
    && gkube --namespace team-white get service webhook-backend >/dev/null; then
    backend_raw=true
    ip=$(hostname -I | awk '{print $1}')
    review=$(curl --silent --show-error --fail --cacert "$STATE_ROOT/12/tls.crt" -H 'Content-Type: application/json' \
      --data '{"spec":{"containers":[{"image":"safe:1"}]}}' "https://${ip}:9443")
    jq -e '.status.allowed == true' <<<"$review" >/dev/null && allowed_raw=true
    review=$(curl --silent --show-error --fail --cacert "$STATE_ROOT/12/tls.crt" -H 'Content-Type: application/json' \
      --data '{"spec":{"containers":[{"image":"danger-danger.invalid/test:1"}]}}' "https://${ip}:9443")
    jq -e '.status.allowed == false' <<<"$review" >/dev/null \
      && [[ -s "$STATE_ROOT/12/denial-evidence" ]] && denied=true
  fi
  [[ "$backend_raw" == true && "$config" == true && "$enabled" == true ]] && backend=true
  [[ "$allowed_raw" == true && "$enabled" == true ]] && allowed=true
  jq -cn --argjson config "$(gate "$config")" --argjson enabled "$(gate "$enabled")" \
    --argjson backend "$(gate "$backend")" --argjson denied "$(gate "$denied")" --argjson allowed "$(gate "$allowed")" \
    '{"admission-config":$config,"apiserver-enabled":$enabled,"webhook-backend":$backend,"dangerous-denied":$denied,"safe-allowed":$allowed}'
}

o13_control() {
  local policy logs cidr=false same=false system=false deny=false live_deny=false live_allow=false
  if policy=$(gkube --namespace metadata-access get ciliumnetworkpolicy default -o json); then
    jq -e '.spec.egress | any(.toCIDR == ["0.0.0.0/0"])' <<<"$policy" >/dev/null && cidr=true
    jq -e '.spec.egress | any((.toEndpoints // []) | any(.matchLabels["k8s:io.kubernetes.pod.namespace"] == "metadata-access"))' <<<"$policy" >/dev/null && same=true
    jq -e '.spec.egress | any((.toEndpoints // []) | any(.matchLabels["k8s:io.kubernetes.pod.namespace"] == "kube-system"))' <<<"$policy" >/dev/null && system=true
    jq -e '.spec.egressDeny | any(.toCIDR == ["192.168.100.21/32"] and (.toPorts | any(.ports | any(.port == "9055" and .protocol == "TCP"))))' <<<"$policy" >/dev/null && deny=true
  fi
  if logs=$(gkube --namespace metadata-access logs metadata-client --tail=30); then
    grep -q 'metadata=deny' <<<"$logs" && [[ "$deny" == true ]] && live_deny=true
    grep -q 'peer=allow' <<<"$logs" && grep -q 'dns=allow' <<<"$logs" \
      && [[ "$same" == true && "$system" == true ]] && live_allow=true
  fi
  jq -cn --argjson cidr "$(gate "$cidr")" --argjson same "$(gate "$same")" --argjson system "$(gate "$system")" \
    --argjson deny "$(gate "$deny")" --argjson live_deny "$(gate "$live_deny")" --argjson live_allow "$(gate "$live_allow")" \
    '{"policy-cidr-allow":$cidr,"same-namespace-allow":$same,"kube-system-allow":$system,"metadata-deny-rule":$deny,"metadata-denied-live":$live_deny,"peers-allowed-live":$live_allow}'
}

o13_worker() {
  local live=false
  if [[ "$LIFECYCLE" == reference ]] \
    && curl -fsS --max-time 5 http://192.168.100.21:9055 | grep -q METADATA_SENSITIVE; then live=true; fi
  jq -cn --argjson live "$(gate "$live")" '{"metadata-endpoint-live":$live}'
}

o14() {
  local manifest secret raw password=false configured=false readable=false prefix=false absent=false
  [[ -f /opt/course/14/password.txt && $(< /opt/course/14/password.txt) == 'CKS-simulator-aesgcm-key-00001!!' ]] && password=true
  manifest=$(manifest_json)
  jq -e '[.spec.containers[0].command[] | select(. == "--encryption-provider-config=/etc/kubernetes/etcd/ec.yaml")] | length == 1' <<<"$manifest" >/dev/null \
    && jq -e '[.spec.containers[0].volumeMounts[] | select(.mountPath == "/etc/kubernetes/etcd")] | length == 1' <<<"$manifest" >/dev/null && configured=true
  if secret=$(gkube --namespace team-magenta get secret audit-secret -o json); then
    [[ $(jq -r '.data.password' <<<"$secret" | base64 -d) == magenta-plaintext-proof ]] \
      && [[ "$configured" == true ]] && readable=true
  fi
  raw=$(env -u ETCDCTL_API etcdctl --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
    --key=/etc/kubernetes/pki/etcd/healthcheck-client.key get /registry/secrets/team-magenta/audit-secret --print-value-only)
  if [[ -n "$raw" ]]; then
    grep -aFq 'k8s:enc:aesgcm:v1:key1:' <<<"$raw" && prefix=true
    ! grep -aFq 'magenta-plaintext-proof' <<<"$raw" && absent=true
  fi
  jq -cn --argjson password "$(gate "$password")" --argjson configured "$(gate "$configured")" \
    --argjson readable "$(gate "$readable")" --argjson prefix "$(gate "$prefix")" --argjson absent "$(gate "$absent")" \
    '{"password-decoded":$password,"apiserver-configured":$configured,"secret-api-readable":$readable,"etcd-encrypted-prefix":$prefix,"plaintext-absent":$absent}'
}

o15() {
  local ingress secret service app_body api_body cert tls=false match=false app=false api=false routing=false
  local https_port worker_ip
  worker_ip=$(awk -F= '$1 == "CKS_WORKER1_IP" {print $2}' "$TOOLS_ENV")
  [[ "$worker_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
  if ingress=$(gkube --namespace team-pink get ingress secure -o json); then
    jq -e '.spec.tls == [{hosts:["secure-ingress.test"],secretName:"secure-tls"}]' <<<"$ingress" >/dev/null && tls=true
    jq -e '([.spec.rules[0].http.paths[] | {path,service:.backend.service.name}] | sort_by(.path)) == [{path:"/api",service:"api"},{path:"/app",service:"app"}]' <<<"$ingress" >/dev/null && routing=true
    service=$(gkube --namespace ingress-nginx get service ingress-nginx-controller -o json)
    https_port=$(jq -r '.spec.ports[] | select(.name == "https") | .nodePort' <<<"$service")
    if app_body=$(curl -kfsS --max-time 15 --resolve "secure-ingress.test:${https_port}:${worker_ip}" "https://secure-ingress.test:${https_port}/app") && [[ -n "$app_body" ]]; then app=true; fi
    if api_body=$(curl -kfsS --max-time 15 --resolve "secure-ingress.test:${https_port}:${worker_ip}" "https://secure-ingress.test:${https_port}/api") && [[ -n "$api_body" ]]; then api=true; fi
  fi
  if secret=$(gkube --namespace team-pink get secret secure-tls -o json); then
    cert=$(mktemp)
    jq -r '.data["tls.crt"]' <<<"$secret" | base64 -d >"$cert"
    openssl x509 -in "$cert" -noout -subject | grep -Fq 'CN = secure-ingress.test' && match=true
    rm -f -- "$cert"
  fi
  if [[ "$tls" != true || "$match" != true ]]; then
    app=false
    api=false
    routing=false
  fi
  jq -cn --argjson tls "$(gate "$tls")" --argjson match "$(gate "$match")" --argjson app "$(gate "$app")" \
    --argjson api "$(gate "$api")" --argjson routing "$(gate "$routing")" \
    '{"ingress-tls":$tls,"certificate-match":$match,"https-app":$app,"https-api":$api,"backend-routing":$routing}'
}

o16_candidate() {
  local logs=false
  [[ -s /opt/course/16/logs && ! -L /opt/course/16/logs ]] \
    && grep -q custom_rule_1 /opt/course/16/logs && grep -q custom_rule_2 /opt/course/16/logs && logs=true
  jq -cn --argjson logs "$(gate "$logs")" '{"logs-recorded":$logs}'
}

o16_control() {
  local cm logs one=false two=false loaded=false event1=false event2=false
  cm=$(gkube --namespace falco get configmap falco-rules -o json)
  jq -e '.data["cks-simulator-custom.yaml"] | contains("rule: Custom Rule 1") and contains("priority: WARNING")' <<<"$cm" >/dev/null && one=true
  jq -e '.data["cks-simulator-custom.yaml"] | contains("rule: Custom Rule 2") and contains("priority: INFO")' <<<"$cm" >/dev/null && two=true
  gkube --namespace falco get pods -l app.kubernetes.io/name=falco -o json \
    | jq -e '.items | length == 3 and all(.status.phase == "Running" and (.status.containerStatuses | all(.ready == true)))' >/dev/null \
    && [[ "$one" == true && "$two" == true ]] && loaded=true
  logs=$(gkube --namespace falco logs --selector app.kubernetes.io/name=falco --container falco --tail=5000 --prefix=true)
  grep -q custom_rule_1 <<<"$logs" && event1=true
  grep -q custom_rule_2 <<<"$logs" && event2=true
  jq -cn --argjson one "$(gate "$one")" --argjson two "$(gate "$two")" --argjson loaded "$(gate "$loaded")" \
    --argjson event1 "$(gate "$event1")" --argjson event2 "$(gate "$event2")" \
    '{"custom-rule1":$one,"custom-rule2":$two,"falco-rules-loaded":$loaded,"rule1-event":$event1,"rule2-event":$event2}'
}

o17() {
  local manifest policy log backups=false secret=false nodes=false none=false secret_event=false node_event=false exclusive=false
  manifest=$(manifest_json)
  jq -e '[.spec.containers[0].command[] | select(. == "--audit-log-maxbackup=1")] | length == 1' <<<"$manifest" >/dev/null && backups=true
  if [[ -f /etc/kubernetes/audit/policy.yaml ]]; then
    policy=$(kubectl patch --local --type=merge -f /etc/kubernetes/audit/policy.yaml --patch='{}' -o json)
    jq -e '.rules[0].level == "Metadata" and .rules[0].resources == [{group:"",resources:["secrets"]}]' <<<"$policy" >/dev/null && secret=true
    jq -e '.rules[1].level == "RequestResponse" and .rules[1].userGroups == ["system:nodes"]' <<<"$policy" >/dev/null && nodes=true
    jq -e '.rules[-1].level == "None"' <<<"$policy" >/dev/null && none=true
  fi
  log=/etc/kubernetes/audit/logs/audit.log
  if [[ -s "$log" ]]; then
    jq -s -e 'any(.[]; .level == "Metadata" and .objectRef.resource == "secrets")' "$log" >/dev/null && secret_event=true
    jq -s -e 'any(.[]; .level == "RequestResponse" and (.user.groups | index("system:nodes") != null))' "$log" >/dev/null && node_event=true
    jq -s -e 'all(.[]; (.level == "Metadata" and .objectRef.resource == "secrets") or (.level == "RequestResponse" and (.user.groups | index("system:nodes") != null)))' "$log" >/dev/null && exclusive=true
  fi
  [[ "$backups" == true && "$secret" == true ]] || secret_event=false
  [[ "$backups" == true && "$nodes" == true ]] || node_event=false
  [[ "$backups" == true && "$secret" == true && "$nodes" == true && "$none" == true ]] || exclusive=false
  jq -cn --argjson backups "$(gate "$backups")" --argjson secret "$(gate "$secret")" --argjson nodes "$(gate "$nodes")" \
    --argjson none "$(gate "$none")" --argjson secret_event "$(gate "$secret_event")" \
    --argjson node_event "$(gate "$node_event")" --argjson exclusive "$(gate "$exclusive")" \
    '{"maxbackup-one":$backups,"policy-secret-metadata":$secret,"policy-nodes-requestresponse":$nodes,"policy-default-none":$none,"secret-audit-event":$secret_event,"node-audit-event":$node_event,"audit-exclusive":$exclusive}'
}

case "${SCENARIO_ID}:${ROLE}" in
  09:candidate) checks=$(o09_candidate) ;; 09:worker1) checks=$(o09_worker) ;; 09:control-plane) checks=$(o09_control) ;;
  10:candidate) checks=$(o10_candidate) ;; 10:control-plane) checks=$(o10_control) ;; 10:worker1) checks=$(o10_worker) ;;
  11:control-plane) checks=$(o11) ;; 12:control-plane) checks=$(o12) ;;
  13:control-plane) checks=$(o13_control) ;; 13:worker2) checks=$(o13_worker) ;;
  14:control-plane) checks=$(o14) ;; 15:control-plane) checks=$(o15) ;;
  16:candidate) checks=$(o16_candidate) ;; 16:control-plane) checks=$(o16_control) ;;
  17:control-plane) checks=$(o17) ;; *) invalid ;;
esac
readonly checks
state_sha256=$(jq -cn --arg scenario_id "$SCENARIO_ID" --arg role "$ROLE" --arg lifecycle "$LIFECYCLE" \
  --argjson checks "$checks" '{checks:$checks,lifecycle:$lifecycle,role:$role,scenario_id:$scenario_id}' \
  | sha256sum | awk '{print $1}')
record=$(jq -cn --arg scenario_id "$SCENARIO_ID" --arg role "$ROLE" --arg lifecycle "$LIFECYCLE" \
  --argjson checks "$checks" --arg state_sha256 "$state_sha256" \
  '{checks:$checks,lifecycle:$lifecycle,role:$role,scenario_id:$scenario_id,schema:1,state_sha256:$state_sha256}')
[[ ${#record} -le MAX_JSON_BYTES ]]
printf '%s\n' "$record" >&3
