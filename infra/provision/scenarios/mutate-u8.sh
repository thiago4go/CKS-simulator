#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly INSTALL_ROOT=/opt/cks-simulator
readonly FIXTURE_ROOT=${INSTALL_ROOT}/scenarios/fixtures
readonly STATE_ROOT=/var/lib/cks-simulator/scenarios
readonly IDENTITY=/etc/cks-simulator/identity.json
readonly OPERATOR_CONFIG=/etc/kubernetes/admin.conf
readonly CANDIDATE_CONFIG=/home/candidate/.kube/config
readonly TOOLS_ENV=/etc/cks-simulator/scenario.env
readonly APISERVER_MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml

exec 3>&1
exec >/dev/null 2>&1

fail() {
  trap - ERR
  printf '{"error":"mutation_failed","ok":false,"schema":1}\n' >&3
  exit 1
}
trap fail ERR

[[ $# -eq 2 ]]
readonly SCENARIO_ID=$1 ACTION=$2
case "$SCENARIO_ID" in 09|10|11|12|13|14|15|16|17) ;; *) fail ;; esac
case "$ACTION" in prepare|reference|restore) ;; *) fail ;; esac
[[ ${EUID} -eq 0 ]]

ROLE=$(python3 - "$IDENTITY" <<'PY'
import json, os, stat, sys
path = sys.argv[1]
value = os.lstat(path)
if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022 or value.st_size > 4096:
    raise SystemExit(1)
with open(path, encoding="utf-8") as stream:
    role = json.load(stream).get("role")
if role not in {"candidate", "control-plane", "worker1", "worker2"}:
    raise SystemExit(1)
print(role)
PY
)
readonly ROLE
case "${SCENARIO_ID}:${ROLE}" in
  09:candidate|09:control-plane|09:worker1|10:candidate|10:control-plane|10:worker1|11:control-plane|\
  12:control-plane|13:control-plane|13:worker1|13:worker2|14:control-plane|\
  15:candidate|15:control-plane|16:candidate|16:control-plane|17:control-plane|17:worker1) ;;
  *) fail ;;
esac

readonly SCENARIO_STATE=${STATE_ROOT}/${SCENARIO_ID}
install -d -m 0700 -o root -g root -- "$STATE_ROOT" "$SCENARIO_STATE"

fixture() {
  local path=${FIXTURE_ROOT}/${SCENARIO_ID}/$1 value
  case "$path" in "$FIXTURE_ROOT"/0[9]/*|"$FIXTURE_ROOT"/1[0-7]/*) ;; *) return 1 ;; esac
  [[ -f "$path" && ! -L "$path" ]]
  value=$(stat -c '%u:%a:%s' -- "$path")
  python3 - "$value" <<'PY'
import sys
uid, mode, size = sys.argv[1].split(":")
if uid != "0" or int(mode, 8) & 0o022 or int(size) > 2 * 1024 * 1024:
    raise SystemExit(1)
PY
  printf '%s' "$path"
}

kube() {
  [[ "$ROLE" == control-plane ]]
  timeout 180 kubectl --kubeconfig="$OPERATOR_CONFIG" "$@"
}

candidate_kube() {
  [[ "$ROLE" == candidate ]]
  timeout 180 kubectl --kubeconfig="$CANDIDATE_CONFIG" "$@"
}

load_tools() {
  [[ -f "$TOOLS_ENV" && ! -L "$TOOLS_ENV" ]]
  [[ $(stat -c '%u:%a:%s' "$TOOLS_ENV") =~ ^0:600:[1-9][0-9]{0,3}$ ]]
  CKS_WORKER1_NODE=$(awk -F= '$1 == "CKS_WORKER1_NODE" {print $2}' "$TOOLS_ENV")
  CKS_WORKER2_NODE=$(awk -F= '$1 == "CKS_WORKER2_NODE" {print $2}' "$TOOLS_ENV")
  CKS_WORKER2_IP=$(awk -F= '$1 == "CKS_WORKER2_IP" {print $2}' "$TOOLS_ENV")
  [[ ${CKS_WORKER1_NODE:-} =~ ^cks-[0-9a-f]{16}-worker1$ ]]
  [[ ${CKS_WORKER2_NODE:-} =~ ^cks-[0-9a-f]{16}-worker2$ ]]
  [[ ${CKS_WORKER2_IP:-} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

reset_course() {
  local number=$1
  local path=/opt/course/${number}
  [[ "$ROLE" == candidate ]]
  [[ ! -L /opt/course ]]
  rm -rf -- "$path"
  install -d -m 0755 -o root -g root /opt/course
  install -d -m 0775 -o candidate -g candidate -- "$path"
}

remove_course() {
  [[ "$ROLE" == candidate ]]
  case "$1" in 9|10|15|16) rm -rf -- "/opt/course/$1" ;; *) return 1 ;; esac
}

write_lifecycle() {
  local lifecycle temporary
  case "$ACTION" in prepare) lifecycle=prepared ;; reference) lifecycle=reference ;; restore) lifecycle=restored ;; esac
  temporary=$(mktemp "$SCENARIO_STATE/.lifecycle.XXXXXX")
  printf '%s\n' "$lifecycle" >"$temporary"
  install -m 0600 -o root -g root -- "$temporary" "$SCENARIO_STATE/lifecycle.new"
  mv -fT -- "$SCENARIO_STATE/lifecycle.new" "$SCENARIO_STATE/lifecycle"
  rm -f -- "$temporary"
}

delete_object() {
  local namespace=$1 kind=$2 name=$3
  kube --namespace "$namespace" delete "$kind" "$name" --ignore-not-found --wait=true --timeout=90s >/dev/null
}

backup_apiserver() {
  [[ "$ROLE" == control-plane ]]
  [[ -f "$APISERVER_MANIFEST" && ! -L "$APISERVER_MANIFEST" ]]
  if [[ ! -f "$SCENARIO_STATE/apiserver.original" ]]; then
    install -m 0600 -o root -g root -- "$APISERVER_MANIFEST" "$SCENARIO_STATE/apiserver.original"
  fi
}

install_apiserver_patch() {
  local patch=$1 temporary
  backup_apiserver
  temporary=$(mktemp "$SCENARIO_STATE/.apiserver.XXXXXX")
  kubectl patch --local --type=json -f "$SCENARIO_STATE/apiserver.original" \
    --patch "$patch" -o yaml >"$temporary"
  install -m 0600 -o root -g root -- "$temporary" "${APISERVER_MANIFEST}.cks-new"
  mv -fT -- "${APISERVER_MANIFEST}.cks-new" "$APISERVER_MANIFEST"
  rm -f -- "$temporary"
  sleep 8
  local deadline=$((SECONDS + 180))
  until kubectl --kubeconfig="$OPERATOR_CONFIG" get --raw=/readyz >/dev/null 2>&1; do
    (( SECONDS < deadline ))
    sleep 2
  done
}

restore_apiserver() {
  [[ -f "$SCENARIO_STATE/apiserver.original" && ! -L "$SCENARIO_STATE/apiserver.original" ]]
  install -m 0600 -o root -g root -- "$SCENARIO_STATE/apiserver.original" "${APISERVER_MANIFEST}.cks-new"
  mv -fT -- "${APISERVER_MANIFEST}.cks-new" "$APISERVER_MANIFEST"
  sleep 8
  local deadline=$((SECONDS + 180))
  until kubectl --kubeconfig="$OPERATOR_CONFIG" get --raw=/readyz >/dev/null 2>&1; do
    (( SECONDS < deadline ))
    sleep 2
  done
}

patch_with_mount() {
  local argument=$1 volume_name=$2 host_path=$3 mount_path=$4 extra_argument=${5:-} patch
  patch=$(jq -cn \
    --arg argument "$argument" --arg volume "$volume_name" --arg host "$host_path" \
    --arg mount "$mount_path" --arg extra "$extra_argument" '
      [
        {op:"add",path:"/spec/containers/0/command/-",value:$argument},
        {op:"add",path:"/spec/containers/0/volumeMounts/-",value:{name:$volume,mountPath:$mount,readOnly:true}},
        {op:"add",path:"/spec/volumes/-",value:{name:$volume,hostPath:{path:$host,type:"Directory"}}}
      ] + (if $extra == "" then [] else [{op:"add",path:"/spec/containers/0/command/-",value:$extra}] end)')
  install_apiserver_patch "$patch"
}

s09_control() {
  load_tools
  delete_object default deployment apparmor
  kube label node "$CKS_WORKER1_NODE" security- --overwrite >/dev/null 2>&1 || true
  if [[ "$ACTION" == reference ]]; then
    kube label node "$CKS_WORKER1_NODE" security=apparmor --overwrite >/dev/null
    kube apply -f "$(fixture reference.json)" >/dev/null
  fi
}

s09_worker() {
  local profile=/etc/apparmor.d/k8s-apparmor-deny-write
  if [[ "$ACTION" == reference ]]; then
    install -m 0644 -o root -g root -- "$(fixture profile)" "$profile"
    apparmor_parser -r "$profile"
  elif [[ -f "$profile" ]]; then
    apparmor_parser -R "$profile" >/dev/null 2>&1 || true
    rm -f -- "$profile"
  fi
}

s09_candidate() {
  if [[ "$ACTION" == restore ]]; then remove_course 9; return; fi
  reset_course 9
  install -m 0644 -o candidate -g candidate -- "$(fixture profile)" /opt/course/9/profile
  : >/opt/course/9/logs
  chown candidate:candidate /opt/course/9/logs
  if [[ "$ACTION" == reference ]]; then
    local deadline=$((SECONDS + 180)) logs=''
    until logs=$(candidate_kube logs --namespace default deployment/apparmor --container c1 2>&1) && [[ -n "$logs" ]]; do
      (( SECONDS < deadline ))
      sleep 3
    done
    printf '%s\n' "$logs" >/opt/course/9/logs
    chown candidate:candidate /opt/course/9/logs
  fi
}

s10_control() {
  load_tools
  kube --namespace team-purple delete pod gvisor-test --ignore-not-found --wait=true --timeout=90s >/dev/null
  kube delete runtimeclass gvisor --ignore-not-found >/dev/null
  if [[ "$ACTION" == reference ]]; then
    local rendered
    rendered=$(mktemp "$SCENARIO_STATE/.gvisor.XXXXXX")
    jq --arg node "$CKS_WORKER1_NODE" '(.items[] | select(.kind == "Pod") | .spec.nodeName) = $node' \
      "$(fixture reference.json)" >"$rendered"
    kube apply -f "$rendered" >/dev/null
    rm -f -- "$rendered"
    kube --namespace team-purple wait --for=condition=Ready pod/gvisor-test --timeout=180s >/dev/null
  fi
}

s10_candidate() {
  if [[ "$ACTION" == restore ]]; then remove_course 10; return; fi
  reset_course 10
  : >/opt/course/10/gvisor-test-dmesg
  chown candidate:candidate /opt/course/10/gvisor-test-dmesg
  if [[ "$ACTION" == reference ]]; then
    candidate_kube --namespace team-purple logs gvisor-test > /opt/course/10/gvisor-test-dmesg
    grep -qi gvisor /opt/course/10/gvisor-test-dmesg
    chown candidate:candidate /opt/course/10/gvisor-test-dmesg
  fi
}

s10_worker() { :; }

s11_control() {
  load_tools
  kube --namespace team-khaki-us-east-ad1 delete deployment app-db app-green-sky --ignore-not-found --wait=true --timeout=120s >/dev/null
  kube --namespace team-khaki-us-east-ad1 delete secret db-con user-data app-data --ignore-not-found >/dev/null
  kube --namespace team-khaki-us-east-ad1 delete configmap app-data --ignore-not-found >/dev/null
  kube --namespace team-khaki-us-east-ad2 delete secret user-data --ignore-not-found >/dev/null
  if [[ "$ACTION" == restore ]]; then return; fi
  kube apply -f "$(fixture full-resources.json)" >/dev/null
  for name in app-db app-green-sky; do
    kube --namespace team-khaki-us-east-ad1 patch deployment "$name" --type=merge \
      --patch "{\"spec\":{\"template\":{\"spec\":{\"nodeName\":\"${CKS_WORKER2_NODE}\"}}}}" >/dev/null
  done
  if [[ "$ACTION" == reference ]]; then
    kube --namespace team-khaki-us-east-ad1 create secret generic db-con \
      --from-literal='password=4c!29f_Ee2e' --dry-run=client -o yaml | kube apply -f - >/dev/null
    kube --namespace team-khaki-us-east-ad2 create secret generic user-data \
      --from-literal='username=system' --dry-run=client -o yaml | kube apply -f - >/dev/null
    kube --namespace team-khaki-us-east-ad1 delete secret user-data >/dev/null
    kube --namespace team-khaki-us-east-ad1 create secret generic app-data \
      --from-literal='host=db.team-khaki' --from-literal='user=system' --dry-run=client -o yaml | kube apply -f - >/dev/null
    kube --namespace team-khaki-us-east-ad1 patch deployment app-green-sky --type=json \
      --patch='[{"op":"replace","path":"/spec/template/spec/containers/0/envFrom/0","value":{"secretRef":{"name":"app-data"}}}]' >/dev/null
    kube --namespace team-khaki-us-east-ad1 delete configmap app-data >/dev/null
    kube --namespace team-khaki-us-east-ad1 rollout restart deployment/app-db >/dev/null
  fi
  kube --namespace team-khaki-us-east-ad1 rollout status deployment/app-db --timeout=180s >/dev/null
  kube --namespace team-khaki-us-east-ad1 rollout status deployment/app-green-sky --timeout=180s >/dev/null
}

s12_prepare_backend() {
  local ip cert key unit
  ip=$(hostname -I | awk '{print $1}')
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
  cert=$SCENARIO_STATE/tls.crt
  key=$SCENARIO_STATE/tls.key
  if [[ ! -f "$cert" || ! -f "$key" ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
      -subj '/CN=cks-image-policy-webhook' -addext "subjectAltName=IP:${ip}" \
      -keyout "$key" -out "$cert" >/dev/null 2>&1
    chmod 0600 "$key" "$cert"
  fi
  install -m 0700 -o root -g root -- "$(fixture backend.py)" "$SCENARIO_STATE/backend.py"
  unit=/etc/systemd/system/cks-image-policy-webhook.service
  cat >"$SCENARIO_STATE/backend.service" <<EOF
[Unit]
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 ${SCENARIO_STATE}/backend.py
Restart=always
RestartSec=1
[Install]
WantedBy=multi-user.target
EOF
  install -m 0644 -o root -g root -- "$SCENARIO_STATE/backend.service" "$unit"
  systemctl daemon-reload
  systemctl enable --now cks-image-policy-webhook.service >/dev/null
  local deadline=$((SECONDS + 60))
  until curl --silent --show-error --fail --cacert "$cert" \
    -H 'Content-Type: application/json' --data '{"spec":{"containers":[{"image":"safe:1"}]}}' \
    "https://${ip}:9443" | jq -e '.status.allowed == true' >/dev/null; do
    (( SECONDS < deadline ))
    sleep 2
  done
  kube create namespace team-white --dry-run=client -o yaml | kube apply -f - >/dev/null
  cat <<EOF | kube apply -f - >/dev/null
apiVersion: v1
kind: Service
metadata: {name: webhook-backend, namespace: team-white}
spec: {ports: [{port: 443, targetPort: 9443}]}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: webhook-backend
  namespace: team-white
  labels: {kubernetes.io/service-name: webhook-backend}
addressType: IPv4
ports: [{name: https, protocol: TCP, port: 9443}]
endpoints: [{addresses: ["${ip}"]}]
EOF
  install -d -m 0755 -o candidate -g candidate /opt/course/12 /opt/course/12/webhook
  install -m 0644 -o candidate -g candidate -- "$(fixture admission-config.yaml)" /opt/course/12/webhook/admission-config.yaml
  install -m 0644 -o candidate -g candidate -- "$cert" /opt/course/12/webhook/tls.crt
  cat >"$SCENARIO_STATE/webhook.yaml" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: webhook
  cluster:
    certificate-authority: /etc/kubernetes/webhook/tls.crt
    server: https://${ip}:9443
users:
- name: apiserver
  user: {}
contexts:
- name: webhook
  context: {cluster: webhook, user: apiserver}
current-context: webhook
EOF
  install -m 0644 -o candidate -g candidate -- "$SCENARIO_STATE/webhook.yaml" /opt/course/12/webhook/webhook.yaml
}

s12_control() {
  if [[ "$ACTION" == restore ]]; then
    restore_apiserver
    systemctl disable --now cks-image-policy-webhook.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/cks-image-policy-webhook.service
    systemctl daemon-reload
    kube --namespace team-white delete service webhook-backend --ignore-not-found >/dev/null
    kube --namespace team-white delete endpointslice webhook-backend --ignore-not-found >/dev/null
    rm -rf /opt/course/12
    return
  fi
  backup_apiserver
  s12_prepare_backend
  rm -f "$SCENARIO_STATE/denial-evidence"
  if [[ "$ACTION" == reference ]]; then
    local base idx enabled patch
    base=$(kubectl patch --local --type=merge -f "$SCENARIO_STATE/apiserver.original" --patch='{}' -o json)
    idx=$(jq '[.spec.containers[0].command | to_entries[] | select(.value | startswith("--enable-admission-plugins=")) | .key][0]' <<<"$base")
    [[ "$idx" =~ ^[0-9]+$ ]]
    enabled=$(jq -r ".spec.containers[0].command[$idx]" <<<"$base")
    [[ "$enabled" == *ImagePolicyWebhook* ]] || enabled="${enabled},ImagePolicyWebhook"
    patch=$(jq -cn --argjson idx "$idx" --arg enabled "$enabled" '[
      {op:"replace",path:("/spec/containers/0/command/"+($idx|tostring)),value:$enabled},
      {op:"add",path:"/spec/containers/0/command/-",value:"--admission-control-config-file=/etc/kubernetes/webhook/admission-config.yaml"},
      {op:"add",path:"/spec/containers/0/volumeMounts/-",value:{name:"image-policy-webhook",mountPath:"/etc/kubernetes/webhook",readOnly:true}},
      {op:"add",path:"/spec/volumes/-",value:{name:"image-policy-webhook",hostPath:{path:"/opt/course/12/webhook",type:"Directory"}}}
    ]')
    install_apiserver_patch "$patch"
    if kube run danger-test --image=danger-danger.invalid/example:1 --restart=Never 2>"$SCENARIO_STATE/denial-evidence"; then
      kube delete pod danger-test --ignore-not-found >/dev/null
      return 1
    fi
    grep -qi 'danger-danger\|denied' "$SCENARIO_STATE/denial-evidence"
  fi
}

s13_route() {
  load_tools
  if [[ "$ROLE" == worker2 ]]; then
    if [[ "$ACTION" == restore ]]; then
      [[ ! -f "$SCENARIO_STATE/http.pid" ]] || kill "$(<"$SCENARIO_STATE/http.pid")" >/dev/null 2>&1 || true
      rm -f "$SCENARIO_STATE/http.pid"
      ip address del 192.168.100.21/32 dev lo >/dev/null 2>&1 || true
    else
      ip address replace 192.168.100.21/32 dev lo
      if [[ ! -f "$SCENARIO_STATE/http.pid" ]] || ! kill -0 "$(<"$SCENARIO_STATE/http.pid")" 2>/dev/null; then
        install -d -m 0700 "$SCENARIO_STATE/www"
        printf 'METADATA_SENSITIVE\n' >"$SCENARIO_STATE/www/index.html"
        nohup python3 -m http.server 9055 --bind 192.168.100.21 --directory "$SCENARIO_STATE/www" \
          </dev/null >"$SCENARIO_STATE/http.log" 2>&1 3>&- &
        printf '%s\n' "$!" >"$SCENARIO_STATE/http.pid"
      fi
      timeout 30 bash -c 'until curl -fsS http://192.168.100.21:9055 | grep -q METADATA_SENSITIVE; do sleep 1; done'
    fi
  else
    if [[ "$ACTION" == restore ]]; then
      ip route del 192.168.100.21/32 >/dev/null 2>&1 || true
    else
      ip route replace 192.168.100.21/32 via "$CKS_WORKER2_IP"
    fi
  fi
}

s13_control() {
  load_tools
  kube --namespace metadata-access delete ciliumnetworkpolicy default --ignore-not-found >/dev/null
  kube --namespace metadata-access delete pod metadata-client --ignore-not-found --wait=true --timeout=90s >/dev/null
  kube --namespace metadata-access delete deployment metadata-peer --ignore-not-found --wait=true --timeout=90s >/dev/null
  kube --namespace metadata-access delete service metadata-peer --ignore-not-found >/dev/null
  if [[ "$ACTION" == restore ]]; then return; fi
  local rendered
  rendered=$(mktemp "$SCENARIO_STATE/.resources.XXXXXX")
  jq --arg node "$CKS_WORKER1_NODE" '
    (.items[] | select(.kind == "Deployment") | .spec.template.spec.nodeName) = $node |
    (.items[] | select(.kind == "Pod") | .spec.nodeName) = $node
  ' "$(fixture full-resources.json)" >"$rendered"
  kube apply -f "$rendered" >/dev/null
  rm -f "$rendered"
  kube --namespace metadata-access rollout status deployment/metadata-peer --timeout=180s >/dev/null
  kube --namespace metadata-access wait --for=condition=Ready pod/metadata-client --timeout=180s >/dev/null
  if [[ "$ACTION" == reference ]]; then
    kube apply -f "$(fixture reference.json)" >/dev/null
  fi
}

s14_control() {
  if [[ "$ACTION" == restore ]]; then
    kube --namespace team-magenta delete secret audit-secret --ignore-not-found >/dev/null
    restore_apiserver
    rm -rf /etc/kubernetes/etcd /opt/course/14
    return
  fi
  backup_apiserver
  install -d -m 0700 -o root -g root /etc/kubernetes/etcd
  install -m 0600 -o root -g root -- "$(fixture full-ec.yaml)" /etc/kubernetes/etcd/ec.yaml
  install -d -m 0775 -o candidate -g candidate /opt/course/14
  : >/opt/course/14/password.txt
  chown candidate:candidate /opt/course/14/password.txt
  kube --namespace team-magenta delete secret audit-secret --ignore-not-found >/dev/null
  kube apply -f "$(fixture resources.json)" >/dev/null
  if [[ "$ACTION" == reference ]]; then
    printf 'CKS-simulator-aesgcm-key-00001!!\n' >/opt/course/14/password.txt
    chown candidate:candidate /opt/course/14/password.txt
    patch_with_mount '--encryption-provider-config=/etc/kubernetes/etcd/ec.yaml' \
      etcd-encryption /etc/kubernetes/etcd /etc/kubernetes/etcd
    kube --namespace team-magenta get secret audit-secret -o json | kube replace -f - >/dev/null
  fi
}

s15_control() {
  kube --namespace team-pink delete ingress secure --ignore-not-found >/dev/null
  kube --namespace team-pink delete deployment app api --ignore-not-found --wait=true --timeout=120s >/dev/null
  kube --namespace team-pink delete service app api --ignore-not-found >/dev/null
  kube --namespace team-pink delete secret secure-tls --ignore-not-found >/dev/null
  if [[ "$ACTION" == restore ]]; then return; fi
  kube apply -f "$(fixture full-resources.json)" >/dev/null
  kube --namespace team-pink rollout status deployment/app --timeout=180s >/dev/null
  kube --namespace team-pink rollout status deployment/api --timeout=180s >/dev/null
}

s15_candidate() {
  if [[ "$ACTION" == restore ]]; then remove_course 15; return; fi
  reset_course 15
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
    -subj '/CN=secure-ingress.test' -addext 'subjectAltName=DNS:secure-ingress.test' \
    -keyout /opt/course/15/tls.key -out /opt/course/15/tls.crt >/dev/null 2>&1
  chown candidate:candidate /opt/course/15/tls.key /opt/course/15/tls.crt
  chmod 0600 /opt/course/15/tls.key
  chmod 0644 /opt/course/15/tls.crt
  if [[ "$ACTION" == reference ]]; then
    candidate_kube --namespace team-pink create secret tls secure-tls \
      --cert=/opt/course/15/tls.crt --key=/opt/course/15/tls.key \
      --dry-run=client -o yaml | candidate_kube apply -f - >/dev/null
    candidate_kube --namespace team-pink patch ingress secure --type=merge \
      --patch='{"spec":{"tls":[{"hosts":["secure-ingress.test"],"secretName":"secure-tls"}]}}' >/dev/null
    local worker_ip https_port deadline
    worker_ip=$(awk -F= '$1 == "CKS_WORKER1_IP" {print $2}' "$TOOLS_ENV")
    [[ "$worker_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
    https_port=$(candidate_kube --namespace ingress-nginx get service ingress-nginx-controller \
      -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
    [[ "$https_port" =~ ^[0-9]{5}$ ]]
    deadline=$((SECONDS + 120))
    until curl -kfsS --max-time 10 --resolve "secure-ingress.test:${https_port}:${worker_ip}" \
      "https://secure-ingress.test:${https_port}/app" >/dev/null \
      && curl -kfsS --max-time 10 --resolve "secure-ingress.test:${https_port}:${worker_ip}" \
        "https://secure-ingress.test:${https_port}/api" >/dev/null; do
      (( SECONDS < deadline ))
      sleep 2
    done
  fi
}

falco_baseline() {
  kube --namespace falco patch configmap falco-rules --type=json \
    --patch='[{"op":"remove","path":"/data/cks-simulator-custom.yaml"}]' >/dev/null 2>&1 || true
  kube --namespace falco rollout restart daemonset/falco >/dev/null
  kube --namespace falco rollout status daemonset/falco --timeout=180s >/dev/null
}

s16_control() {
  kube delete pod cks-falco-trigger --ignore-not-found --wait=false >/dev/null
  falco_baseline
  rm -f "$SCENARIO_STATE/events.log"
  if [[ "$ACTION" != reference ]]; then return; fi
  local rules patch start deadline output
  rules=$(<"$(fixture reference.yaml)")
  patch=$(jq -cn --arg rules "$rules" '{data:{"cks-simulator-custom.yaml":$rules}}')
  kube --namespace falco patch configmap falco-rules --type=merge --patch "$patch" >/dev/null
  kube --namespace falco rollout restart daemonset/falco >/dev/null
  kube --namespace falco rollout status daemonset/falco --timeout=180s >/dev/null
  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  cat <<'EOF' | kube apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: cks-falco-trigger, namespace: default}
spec:
  restartPolicy: Never
  containers:
  - name: trigger
    image: docker.io/library/busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028
    securityContext: {privileged: true}
    command: ["sh", "-c", "chroot /host cat /etc/kubernetes/kubelet.conf >/dev/null 2>&1 || true; kill -TERM $$"]
    volumeMounts: [{name: host, mountPath: /host, readOnly: true}]
  volumes: [{name: host, hostPath: {path: /, type: Directory}}]
EOF
  kube wait --for=jsonpath='{.status.phase}'=Failed pod/cks-falco-trigger --timeout=120s >/dev/null 2>&1 || true
  deadline=$((SECONDS + 120))
  until output=$(kube --namespace falco logs --selector app.kubernetes.io/name=falco \
      --container falco --since-time="$start" --tail=5000 --prefix=true 2>/dev/null || true) \
      && [[ "$output" == *custom_rule_1* && "$output" == *custom_rule_2* ]]; do
    (( SECONDS < deadline ))
    sleep 3
  done
  printf '%s\n' "$output" >"$SCENARIO_STATE/events.log"
}

s16_candidate() {
  if [[ "$ACTION" == restore ]]; then remove_course 16; return; fi
  reset_course 16
  install -m 0644 -o candidate -g candidate -- "$(fixture reference.yaml)" /opt/course/16/falco_rules.local.yaml
  : >/opt/course/16/logs
  chown candidate:candidate /opt/course/16/logs
  if [[ "$ACTION" == reference ]]; then
    candidate_kube --namespace falco logs --selector app.kubernetes.io/name=falco \
      --container falco --tail=5000 --prefix=true > /opt/course/16/logs
    grep -q custom_rule_1 /opt/course/16/logs
    grep -q custom_rule_2 /opt/course/16/logs
    chown candidate:candidate /opt/course/16/logs
  fi
}

s17_control() {
  if [[ "$ACTION" == restore ]]; then
    restore_apiserver
    rm -rf /etc/kubernetes/audit
    return
  fi
  backup_apiserver
  install -d -m 0700 -o root -g root /etc/kubernetes/audit/logs
  local policy
  policy=$(fixture baseline-policy.yaml)
  [[ "$ACTION" == reference ]] && policy=$(fixture reference-policy.yaml)
  install -m 0600 -o root -g root -- "$policy" /etc/kubernetes/audit/policy.yaml
  : >/etc/kubernetes/audit/logs/audit.log
  chmod 0600 /etc/kubernetes/audit/logs/audit.log
  local patch
  patch=$(jq -cn --arg backups "$([[ "$ACTION" == reference ]] && printf 1 || printf 10)" '[
    {op:"add",path:"/spec/containers/0/command/-",value:"--audit-policy-file=/etc/kubernetes/audit/policy.yaml"},
    {op:"add",path:"/spec/containers/0/command/-",value:"--audit-log-path=/etc/kubernetes/audit/logs/audit.log"},
    {op:"add",path:"/spec/containers/0/command/-",value:("--audit-log-maxbackup="+$backups)},
    {op:"add",path:"/spec/containers/0/command/-",value:"--audit-log-maxage=30"},
    {op:"add",path:"/spec/containers/0/command/-",value:"--audit-log-maxsize=100"},
    {op:"add",path:"/spec/containers/0/volumeMounts/-",value:{name:"audit",mountPath:"/etc/kubernetes/audit",readOnly:false}},
    {op:"add",path:"/spec/volumes/-",value:{name:"audit",hostPath:{path:"/etc/kubernetes/audit",type:"Directory"}}}
  ]')
  install_apiserver_patch "$patch"
  if [[ "$ACTION" == reference ]]; then
    : >/etc/kubernetes/audit/logs/audit.log
    kube --namespace team-magenta get secret audit-secret >/dev/null 2>&1 || kube --namespace kube-system get secret >/dev/null
  fi
}

s17_worker() {
  [[ "$ACTION" == reference ]] || return 0
  load_tools
  timeout 30 kubectl --kubeconfig=/etc/kubernetes/kubelet.conf get node "$CKS_WORKER1_NODE" >/dev/null
}

case "${SCENARIO_ID}:${ROLE}" in
  09:control-plane) s09_control ;; 09:worker1) s09_worker ;; 09:candidate) s09_candidate ;;
  10:control-plane) s10_control ;; 10:worker1) s10_worker ;; 10:candidate) s10_candidate ;;
  11:control-plane) s11_control ;;
  12:control-plane) s12_control ;;
  13:control-plane) s13_control ;; 13:worker1|13:worker2) s13_route ;;
  14:control-plane) s14_control ;;
  15:control-plane) s15_control ;; 15:candidate) s15_candidate ;;
  16:control-plane) s16_control ;; 16:candidate) s16_candidate ;;
  17:control-plane) s17_control ;; 17:worker1) s17_worker ;;
  *) fail ;;
esac

write_lifecycle
printf '{"action":"%s","ok":true,"role":"%s","scenario_id":"%s","schema":1}\n' \
  "$ACTION" "$ROLE" "$SCENARIO_ID" >&3
