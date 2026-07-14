#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly INSTALL_ROOT=/opt/cks-simulator
readonly FIXTURE_ROOT=${INSTALL_ROOT}/scenarios/fixtures
readonly STATE_ROOT=/var/lib/cks-simulator/scenarios
readonly IDENTITY=/etc/cks-simulator/identity.json
readonly OPERATOR_CONFIG=/etc/kubernetes/admin.conf
readonly DOCKER_SOCKET=unix:///run/docker.sock

exec 3>&1
exec >/dev/null 2>&1

die() {
  printf '{"error":"mutation_failed","ok":false,"schema":1}\n' >&3
  exit 1
}

mutation_failed() {
  trap - ERR
  printf '{"error":"mutation_failed","ok":false,"schema":1}\n' >&3
  exit 1
}
trap mutation_failed ERR

[[ $# -eq 2 ]] || die "usage: mutate.sh SCENARIO_ID prepare|reference|restore"
readonly SCENARIO_ID=$1 ACTION=$2
case "$SCENARIO_ID" in 01|02|03|04|05|06|07|08) ;; *) die "unsupported scenario ID" ;; esac
case "$ACTION" in prepare|reference|restore) ;; *) die "unsupported scenario action" ;; esac
[[ ${EUID} -eq 0 ]] || die "must run as root"

for command in python3 install stat mktemp timeout; do
  command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
done

ROLE=$(python3 - "$IDENTITY" <<'PY'
import json
import os
import stat
import sys

path = sys.argv[1]
value = os.lstat(path)
if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
    raise SystemExit("guest identity is not a secure root-owned file")
if value.st_size > 4096:
    raise SystemExit("guest identity exceeds size limit")
with open(path, "r", encoding="utf-8") as stream:
    payload = json.load(stream)
role = payload.get("role")
if role not in {"candidate", "control-plane", "worker1", "worker2"}:
    raise SystemExit("guest identity role is invalid")
print(role)
PY
)
readonly ROLE

case "${SCENARIO_ID}:${ROLE}" in
  01:candidate|02:candidate|03:control-plane|04:control-plane|04:worker1|05:control-plane|05:worker1|06:control-plane|06:worker2|07:control-plane|07:worker1|08:worker2) ;;
  *) die "scenario is not assigned to this guest role" ;;
esac

state_dir() {
  case "$SCENARIO_ID" in
    01) printf '%s' "$STATE_ROOT/01" ;;
    02) printf '%s' "$STATE_ROOT/02" ;;
    03) printf '%s' "$STATE_ROOT/03" ;;
    04) printf '%s' "$STATE_ROOT/04" ;;
    05) printf '%s' "$STATE_ROOT/05" ;;
    06) printf '%s' "$STATE_ROOT/06" ;;
    07) printf '%s' "$STATE_ROOT/07" ;;
    08) printf '%s' "$STATE_ROOT/08" ;;
  esac
}

readonly SCENARIO_STATE=$(state_dir)
install -d -m 0700 -o root -g root -- "$STATE_ROOT" "$SCENARIO_STATE"

assert_fixture() {
  local path=$1 value
  case "$path" in "$FIXTURE_ROOT"/0[1-8]/*) ;; *) die "fixture path is not allowlisted" ;; esac
  [[ -f "$path" && ! -L "$path" ]] || die "fixture is missing or unsafe: ${path}"
  value=$(stat -c '%u:%a:%s' -- "$path")
  python3 - "$value" <<'PY' || die "fixture ownership, mode, or size is unsafe"
import sys

uid, mode, size = sys.argv[1].split(":")
if uid != "0" or int(mode, 8) & 0o022 or int(size) > 2 * 1024 * 1024:
    raise SystemExit(1)
PY
}

course_dir() {
  case "$SCENARIO_ID" in
    01) printf '/opt/course/1' ;;
    02) printf '/opt/course/2' ;;
    04) printf '/opt/course/4' ;;
    06) printf '/opt/course/6' ;;
    07) printf '/opt/course/7' ;;
    *) die "scenario has no learner file directory" ;;
  esac
}

reset_course_dir() {
  local path
  path=$(course_dir)
  case "$path" in /opt/course/1|/opt/course/2|/opt/course/4|/opt/course/6|/opt/course/7) ;; *) die "course path is not allowlisted" ;; esac
  [[ ! -L /opt/course ]] || die "course root must not be a symlink"
  rm -rf -- "$path"
  install -d -m 0755 -o root -g root -- /opt/course
  install -d -m 0775 -o candidate -g candidate -- "$path"
}

remove_course_dir() {
  local path
  path=$(course_dir)
  case "$path" in /opt/course/1|/opt/course/2|/opt/course/4|/opt/course/6|/opt/course/7) ;; *) die "course path is not allowlisted" ;; esac
  [[ ! -L /opt/course ]] || die "course root must not be a symlink"
  rm -rf -- "$path"
}

copy_course_file() {
  local source=$1 destination=$2
  assert_fixture "$source"
  case "$destination" in
    /opt/course/1/kubeconfig|/opt/course/1/contexts|/opt/course/1/cert|\
    /opt/course/2/scan-results.json|/opt/course/2/images|/opt/course/2/good-images|\
    /opt/course/4/stream-multiplex.yaml|/opt/course/6/immutable-deployment.yaml|\
    /opt/course/6/immutable-deployment-new.yaml|/opt/course/7/bad-pod.yaml|\
    /opt/course/7/namespace.yaml|/opt/course/7/bad-pod.log) ;;
    *) die "course destination is not allowlisted" ;;
  esac
  install -m 0644 -o candidate -g candidate -- "$source" "$destination"
}

empty_course_file() {
  local destination=$1 temporary
  case "$destination" in /opt/course/1/contexts|/opt/course/2/good-images|/opt/course/7/bad-pod.log) ;; *) die "empty course destination is not allowlisted" ;; esac
  temporary=$(mktemp "$SCENARIO_STATE/.empty.XXXXXX")
  install -m 0644 -o candidate -g candidate -- "$temporary" "$destination"
  rm -f -- "$temporary"
}

kube() {
  [[ "$ROLE" == control-plane ]] || die "Kubernetes mutation requires control-plane"
  [[ -f "$OPERATOR_CONFIG" && ! -L "$OPERATOR_CONFIG" ]] || die "operator kubeconfig is missing or unsafe"
  timeout 120 kubectl --kubeconfig="$OPERATOR_CONFIG" "$@"
}

remove_workload() {
  local namespace=$1 kind=$2 name=$3
  case "${namespace}:${kind}:${name}" in
    team-coral:deployment:stream-multiplex|team-coral:serviceaccount:stream-multiplex|\
    team-purple:deployment:immutable-deployment|team-sepia:pod:bad-pod) ;;
    *) die "Kubernetes object is not allowlisted" ;;
  esac
  kube --namespace "$namespace" delete "$kind" "$name" --ignore-not-found --wait=true --timeout=60s >/dev/null
}

apply_fixture() {
  local path=$1
  assert_fixture "$path"
  kube apply -f "$path" >/dev/null
}

scenario_node() {
  local role=$1 node nodes
  case "$role" in worker1|worker2) ;; *) die "scenario node role is invalid" ;; esac
  nodes=$(kube get nodes -o name)
  node=$(grep -E "^node/cks-[0-9a-f]{16}-${role}$" <<<"$nodes" || true)
  [[ "$node" =~ ^node/cks-[0-9a-f]{16}-worker[12]$ ]]
  [[ $(grep -c . <<<"$node") -eq 1 ]]
  printf '%s' "${node#node/}"
}

pin_deployment() {
  local namespace=$1 name=$2 role=$3 node patch
  case "${namespace}:${name}:${role}" in
    team-coral:stream-multiplex:worker1|team-purple:immutable-deployment:worker2) ;;
    *) die "deployment pin is not allowlisted" ;;
  esac
  node=$(scenario_node "$role")
  patch=$(printf '{"spec":{"template":{"spec":{"nodeName":"%s"}}}}' "$node")
  kube --namespace "$namespace" patch deployment "$name" --type=merge --patch "$patch" >/dev/null
}

write_lifecycle() {
  local lifecycle temporary
  case "$ACTION" in
    prepare) lifecycle=prepared ;;
    reference) lifecycle=reference ;;
    restore) lifecycle=restored ;;
  esac
  temporary=$(mktemp "$SCENARIO_STATE/.lifecycle.XXXXXX")
  printf '%s\n' "$lifecycle" >"$temporary"
  install -m 0600 -o root -g root -- "$temporary" "$SCENARIO_STATE/lifecycle.new"
  mv -fT -- "$SCENARIO_STATE/lifecycle.new" "$SCENARIO_STATE/lifecycle"
  rm -f -- "$temporary"
}

s01_prepare() {
  local contexts certificate destination
  contexts="$FIXTURE_ROOT/01/contexts.txt"
  certificate="$FIXTURE_ROOT/01/restricted.crt"
  assert_fixture "$contexts"
  assert_fixture "$certificate"
  reset_course_dir
  destination=/opt/course/1/kubeconfig
  python3 - "$contexts" "$certificate" "$destination" <<'PY'
import base64
import json
import sys

contexts_path, certificate_path, destination = sys.argv[1:]
with open(contexts_path, "r", encoding="utf-8") as stream:
    contexts = [line.rstrip("\n") for line in stream if line.rstrip("\n")]
with open(certificate_path, "rb") as stream:
    certificate = base64.b64encode(stream.read()).decode("ascii")
payload = {
    "apiVersion": "v1",
    "kind": "Config",
    "clusters": [
        {"name": "infra-prod", "cluster": {"server": "https://infra-prod.invalid:6443"}},
        {"name": "kubernetes", "cluster": {"server": "https://kubernetes.invalid:6443"}},
    ],
    "users": [
        {"name": "gianna@infra-prod", "user": {}},
        {"name": "kubernetes-admin@kubernetes", "user": {}},
        {"name": "restricted@infra-prod", "user": {"client-certificate-data": certificate}},
    ],
    "contexts": [
        {"name": contexts[0], "context": {"cluster": "infra-prod", "user": contexts[0]}},
        {"name": contexts[1], "context": {"cluster": "kubernetes", "user": contexts[1]}},
        {"name": contexts[2], "context": {"cluster": "infra-prod", "user": contexts[2]}},
    ],
    "current-context": contexts[1],
}
with open(destination, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
    stream.write("\n")
PY
  chown candidate:candidate -- "$destination"
  chmod 0644 -- "$destination"
  empty_course_file /opt/course/1/contexts
}

s01_reference() {
  s01_prepare
  copy_course_file "$FIXTURE_ROOT/01/contexts.txt" /opt/course/1/contexts
  copy_course_file "$FIXTURE_ROOT/01/restricted.crt" /opt/course/1/cert
}

s02_prepare() {
  local source
  source="$FIXTURE_ROOT/02/scan-results.json"
  assert_fixture "$source"
  reset_course_dir
  copy_course_file "$source" /opt/course/2/scan-results.json
  python3 - "$source" /opt/course/2/images <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, "r", encoding="utf-8") as stream:
    value = json.load(stream)
images = value.get("images")
if value.get("schema") != 1 or not isinstance(images, list) or len(images) != 4:
    raise SystemExit("scenario 02 fixture is invalid")
names = [item.get("name") for item in images]
if any(not isinstance(name, str) or len(name) > 256 for name in names):
    raise SystemExit("scenario 02 image name is invalid")
with open(destination, "w", encoding="utf-8", newline="\n") as stream:
    stream.write("\n".join(names) + "\n")
PY
  chown candidate:candidate -- /opt/course/2/images
  chmod 0644 -- /opt/course/2/images
  empty_course_file /opt/course/2/good-images
}

s02_reference() {
  s02_prepare
  copy_course_file "$FIXTURE_ROOT/02/good-images.txt" /opt/course/2/good-images
}

s03_patch() {
  local path=$1
  assert_fixture "$path"
  kube --namespace default patch service kubernetes --type=merge --patch-file "$path" >/dev/null
}

s04_control_prepare() {
  remove_workload team-coral deployment stream-multiplex
  remove_workload team-coral serviceaccount stream-multiplex
  apply_fixture "$FIXTURE_ROOT/04/resources.json"
  pin_deployment team-coral stream-multiplex worker1
}

s04_control_reference() {
  remove_workload team-coral deployment stream-multiplex
  remove_workload team-coral serviceaccount stream-multiplex
  apply_fixture "$FIXTURE_ROOT/04/reference.json"
  pin_deployment team-coral stream-multiplex worker1
  kube --namespace team-coral rollout status deployment/stream-multiplex --timeout=90s >/dev/null
}

s04_control_restore() {
  remove_workload team-coral deployment stream-multiplex
  remove_workload team-coral serviceaccount stream-multiplex
}

s04_worker_prepare() {
  reset_course_dir
  copy_course_file "$FIXTURE_ROOT/04/resources.json" /opt/course/4/stream-multiplex.yaml
}

s04_worker_reference() {
  reset_course_dir
  copy_course_file "$FIXTURE_ROOT/04/reference.json" /opt/course/4/stream-multiplex.yaml
}

backup_once() {
  local source=$1 destination=$2 mode
  case "${source}:${destination}" in
    /etc/kubernetes/manifests/kube-controller-manager.yaml:$STATE_ROOT/05/controller-manager.original|\
    /var/lib/kubelet/config.yaml:$STATE_ROOT/05/kubelet-config.original|\
    /etc/docker/daemon.json:$STATE_ROOT/08/daemon.original) ;;
    *) die "backup pair is not allowlisted" ;;
  esac
  [[ -f "$source" && ! -L "$source" ]] || die "baseline file is missing or unsafe: ${source}"
  if [[ ! -e "$destination" ]]; then
    mode=$(stat -c '%a' -- "$source")
    install -m 0600 -o root -g root -- "$source" "$destination"
    printf '%s\n' "$mode" >"${destination}.mode"
    chmod 0600 -- "${destination}.mode"
  fi
}

set_yaml_value() {
  local path=$1 key=$2 value=$3 temporary
  case "${path}:${key}:${value}" in
    /etc/kubernetes/manifests/kube-controller-manager.yaml:--profiling:true|\
    /etc/kubernetes/manifests/kube-controller-manager.yaml:--profiling:false|\
    /var/lib/kubelet/config.yaml:clientCAFile:|\
    /var/lib/kubelet/config.yaml:clientCAFile:/etc/kubernetes/pki/ca.crt) ;;
    *) die "YAML mutation is not allowlisted" ;;
  esac
  temporary=$(mktemp "$SCENARIO_STATE/.yaml.XXXXXX")
  python3 - "$path" "$key" "$value" "$temporary" <<'PY'
import os
import re
import sys

source, key, value, destination = sys.argv[1:]
if os.path.getsize(source) > 2 * 1024 * 1024:
    raise SystemExit("YAML source exceeds size limit")
with open(source, "r", encoding="utf-8") as stream:
    lines = stream.readlines()
changed = False
if key == "--profiling":
    pattern = re.compile(r"^(\s*-\s*)--profiling(?:=.*)?\s*$")
    for index, line in enumerate(lines):
        match = pattern.match(line.rstrip("\n"))
        if match:
            lines[index] = f"{match.group(1)}--profiling={value}\n"
            changed = True
    if not changed:
        command = re.compile(r"^(\s*-\s*)kube-controller-manager\s*$")
        for index, line in enumerate(lines):
            match = command.match(line.rstrip("\n"))
            if match:
                lines.insert(index + 1, f"{match.group(1)}--profiling={value}\n")
                changed = True
                break
elif key == "clientCAFile":
    pattern = re.compile(r"^(\s*)clientCAFile:\s*.*$")
    rendered = f'"{value}"' if not value else value
    for index, line in enumerate(lines):
        match = pattern.match(line.rstrip("\n"))
        if match:
            lines[index] = f"{match.group(1)}clientCAFile: {rendered}\n"
            changed = True
if not changed:
    raise SystemExit("expected YAML key was not found")
with open(destination, "w", encoding="utf-8", newline="\n") as stream:
    stream.writelines(lines)
PY
  install -m "$(stat -c '%a' -- "$path")" -o root -g root -- "$temporary" "${path}.cks-new"
  mv -fT -- "${path}.cks-new" "$path"
  rm -f -- "$temporary"
}

ensure_etcd_account() {
  if ! getent group etcd >/dev/null; then
    groupadd --system etcd
    printf 'created\n' >"$SCENARIO_STATE/etcd-group-created"
    chmod 0600 -- "$SCENARIO_STATE/etcd-group-created"
  fi
  if ! id -u etcd >/dev/null 2>&1; then
    useradd --system --gid etcd --home-dir /var/lib/etcd --shell /usr/sbin/nologin etcd
    printf 'created\n' >"$SCENARIO_STATE/etcd-user-created"
    chmod 0600 -- "$SCENARIO_STATE/etcd-user-created"
  fi
}

s05_control_prepare() {
  backup_once /etc/kubernetes/manifests/kube-controller-manager.yaml "$STATE_ROOT/05/controller-manager.original"
  if [[ ! -f "$SCENARIO_STATE/etcd-owner.original" ]]; then
    stat -c '%u:%g' -- /var/lib/etcd >"$SCENARIO_STATE/etcd-owner.original"
    chmod 0600 -- "$SCENARIO_STATE/etcd-owner.original"
  fi
  ensure_etcd_account
  set_yaml_value /etc/kubernetes/manifests/kube-controller-manager.yaml --profiling true
  chown root:root -- /var/lib/etcd
}

s05_control_reference() {
  s05_control_prepare
  set_yaml_value /etc/kubernetes/manifests/kube-controller-manager.yaml --profiling false
  chown etcd:etcd -- /var/lib/etcd
}

s05_control_restore() {
  local owner
  [[ -f "$SCENARIO_STATE/controller-manager.original" && ! -L "$SCENARIO_STATE/controller-manager.original" ]] || die "controller-manager baseline is missing"
  install -m "$(<"$SCENARIO_STATE/controller-manager.original.mode")" -o root -g root -- "$SCENARIO_STATE/controller-manager.original" /etc/kubernetes/manifests/kube-controller-manager.yaml.cks-new
  mv -fT -- /etc/kubernetes/manifests/kube-controller-manager.yaml.cks-new /etc/kubernetes/manifests/kube-controller-manager.yaml
  owner=$(<"$SCENARIO_STATE/etcd-owner.original")
  [[ "$owner" =~ ^[0-9]+:[0-9]+$ ]] || die "recorded etcd owner is invalid"
  chown "$owner" -- /var/lib/etcd
  if [[ -f "$SCENARIO_STATE/etcd-user-created" ]]; then
    userdel etcd
    rm -f -- "$SCENARIO_STATE/etcd-user-created"
  fi
  if [[ -f "$SCENARIO_STATE/etcd-group-created" ]]; then
    if getent group etcd >/dev/null; then
      groupdel etcd
    fi
    rm -f -- "$SCENARIO_STATE/etcd-group-created"
  fi
}

restart_kubelet() {
  local deadline
  systemctl restart kubelet
  deadline=$((SECONDS + 60))
  until systemctl is-active --quiet kubelet; do
    (( SECONDS < deadline )) || die "kubelet did not become active"
    sleep 1
  done
}

s05_worker_prepare() {
  backup_once /var/lib/kubelet/config.yaml "$STATE_ROOT/05/kubelet-config.original"
  set_yaml_value /var/lib/kubelet/config.yaml clientCAFile ''
  chmod 0777 -- /var/lib/kubelet/config.yaml
}

s05_worker_reference() {
  s05_worker_prepare
  set_yaml_value /var/lib/kubelet/config.yaml clientCAFile /etc/kubernetes/pki/ca.crt
  chmod 0600 -- /var/lib/kubelet/config.yaml
  restart_kubelet
}

s05_worker_restore() {
  [[ -f "$SCENARIO_STATE/kubelet-config.original" && ! -L "$SCENARIO_STATE/kubelet-config.original" ]] || die "kubelet baseline is missing"
  install -m "$(<"$SCENARIO_STATE/kubelet-config.original.mode")" -o root -g root -- "$SCENARIO_STATE/kubelet-config.original" /var/lib/kubelet/config.yaml.cks-new
  mv -fT -- /var/lib/kubelet/config.yaml.cks-new /var/lib/kubelet/config.yaml
  restart_kubelet
}

s06_control_prepare() {
  remove_workload team-purple deployment immutable-deployment
  apply_fixture "$FIXTURE_ROOT/06/resources.json"
  pin_deployment team-purple immutable-deployment worker2
}

s06_control_reference() {
  remove_workload team-purple deployment immutable-deployment
  apply_fixture "$FIXTURE_ROOT/06/reference.json"
  pin_deployment team-purple immutable-deployment worker2
  kube --namespace team-purple rollout status deployment/immutable-deployment --timeout=90s >/dev/null
}

s06_control_restore() {
  remove_workload team-purple deployment immutable-deployment
}

s06_worker_prepare() {
  reset_course_dir
  copy_course_file "$FIXTURE_ROOT/06/resources.json" /opt/course/6/immutable-deployment.yaml
}

s06_worker_reference() {
  reset_course_dir
  copy_course_file "$FIXTURE_ROOT/06/reference.json" /opt/course/6/immutable-deployment-new.yaml
}

clear_psa_labels() {
  kube label namespace team-sepia \
    pod-security.kubernetes.io/audit- \
    pod-security.kubernetes.io/audit-version- \
    pod-security.kubernetes.io/warn- \
    pod-security.kubernetes.io/warn-version- \
    --overwrite >/dev/null
}

s07_control_prepare() {
  remove_workload team-sepia pod bad-pod
  clear_psa_labels
  rm -f -- "$SCENARIO_STATE/admission-warning"
}

s07_control_reference() {
  local path temporary
  remove_workload team-sepia pod bad-pod
  path="$FIXTURE_ROOT/07/reference.json"
  assert_fixture "$path"
  temporary=$(mktemp "$SCENARIO_STATE/.warning.XXXXXX")
  kube apply -f "$path" >/dev/null 2>"$temporary"
  [[ $(stat -c '%s' "$temporary") -le 8192 ]] || die "admission warning exceeds size limit"
  install -m 0600 -o root -g root -- "$temporary" "$SCENARIO_STATE/admission-warning"
  rm -f -- "$temporary"
}

s07_control_restore() {
  remove_workload team-sepia pod bad-pod
  clear_psa_labels
  rm -f -- "$SCENARIO_STATE/admission-warning"
}

s07_worker_prepare() {
  reset_course_dir
  copy_course_file "$FIXTURE_ROOT/07/resources.json" /opt/course/7/bad-pod.yaml
  empty_course_file /opt/course/7/bad-pod.log
}

s07_worker_reference() {
  reset_course_dir
  copy_course_file "$FIXTURE_ROOT/07/resources.json" /opt/course/7/bad-pod.yaml
  copy_course_file "$FIXTURE_ROOT/07/reference.json" /opt/course/7/namespace.yaml
  copy_course_file "$FIXTURE_ROOT/07/reference-warning.txt" /opt/course/7/bad-pod.log
}

set_docker_icc() {
  local value=$1 temporary deadline
  case "$value" in true|false) ;; *) die "Docker ICC value is invalid" ;; esac
  backup_once /etc/docker/daemon.json "$STATE_ROOT/08/daemon.original"
  temporary=$(mktemp "$SCENARIO_STATE/.daemon.XXXXXX")
  python3 - /etc/docker/daemon.json "$value" "$temporary" <<'PY'
import json
import os
import sys

source, raw_value, destination = sys.argv[1:]
if os.path.getsize(source) > 65536:
    raise SystemExit("Docker configuration exceeds size limit")
with open(source, "r", encoding="utf-8") as stream:
    value = json.load(stream)
if not isinstance(value, dict):
    raise SystemExit("Docker configuration is not an object")
value["icc"] = raw_value == "true"
with open(destination, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
    stream.write("\n")
PY
  install -m 0644 -o root -g root -- "$temporary" /etc/docker/daemon.json.cks-new
  mv -fT -- /etc/docker/daemon.json.cks-new /etc/docker/daemon.json
  rm -f -- "$temporary"
  systemctl restart cks-docker.service
  deadline=$((SECONDS + 60))
  until docker --host unix:///run/docker.sock info >/dev/null 2>&1; do
    (( SECONDS < deadline )) || die "Docker did not become ready"
    sleep 1
  done
}

remove_docker_containers() {
  docker --host "$DOCKER_SOCKET" rm --force container1 container2 >/dev/null 2>&1 || true
}

s08_prepare() {
  remove_docker_containers
  set_docker_icc true
}

s08_reference() {
  remove_docker_containers
  set_docker_icc false
  docker --host "$DOCKER_SOCKET" run --detach --name container1 --restart always \
    nginx:1-alpine >/dev/null
  docker --host "$DOCKER_SOCKET" run --detach --name container2 --restart always \
    nginx:1-alpine >/dev/null
}

s08_restore() {
  local deadline
  remove_docker_containers
  [[ -f "$SCENARIO_STATE/daemon.original" && ! -L "$SCENARIO_STATE/daemon.original" ]] || die "Docker baseline is missing"
  install -m "$(<"$SCENARIO_STATE/daemon.original.mode")" -o root -g root -- "$SCENARIO_STATE/daemon.original" /etc/docker/daemon.json.cks-new
  mv -fT -- /etc/docker/daemon.json.cks-new /etc/docker/daemon.json
  systemctl restart cks-docker.service
  deadline=$((SECONDS + 60))
  until docker --host unix:///run/docker.sock info >/dev/null 2>&1; do
    (( SECONDS < deadline )) || die "Docker did not become ready"
    sleep 1
  done
}

case "${SCENARIO_ID}:${ACTION}:${ROLE}" in
  01:prepare:candidate) s01_prepare ;;
  01:reference:candidate) s01_reference ;;
  01:restore:candidate) remove_course_dir ;;
  02:prepare:candidate) s02_prepare ;;
  02:reference:candidate) s02_reference ;;
  02:restore:candidate) remove_course_dir ;;
  03:prepare:control-plane) s03_patch "$FIXTURE_ROOT/03/nodeport-patch.json" ;;
  03:reference:control-plane|03:restore:control-plane) s03_patch "$FIXTURE_ROOT/03/clusterip-patch.json" ;;
  04:prepare:control-plane) s04_control_prepare ;;
  04:reference:control-plane) s04_control_reference ;;
  04:restore:control-plane) s04_control_restore ;;
  04:prepare:worker1) s04_worker_prepare ;;
  04:reference:worker1) s04_worker_reference ;;
  04:restore:worker1) remove_course_dir ;;
  05:prepare:control-plane) s05_control_prepare ;;
  05:reference:control-plane) s05_control_reference ;;
  05:restore:control-plane) s05_control_restore ;;
  05:prepare:worker1) s05_worker_prepare ;;
  05:reference:worker1) s05_worker_reference ;;
  05:restore:worker1) s05_worker_restore ;;
  06:prepare:control-plane) s06_control_prepare ;;
  06:reference:control-plane) s06_control_reference ;;
  06:restore:control-plane) s06_control_restore ;;
  06:prepare:worker2) s06_worker_prepare ;;
  06:reference:worker2) s06_worker_reference ;;
  06:restore:worker2) remove_course_dir ;;
  07:prepare:control-plane) s07_control_prepare ;;
  07:reference:control-plane) s07_control_reference ;;
  07:restore:control-plane) s07_control_restore ;;
  07:prepare:worker1) s07_worker_prepare ;;
  07:reference:worker1) s07_worker_reference ;;
  07:restore:worker1) remove_course_dir ;;
  08:prepare:worker2) s08_prepare ;;
  08:reference:worker2) s08_reference ;;
  08:restore:worker2) s08_restore ;;
  *) die "static mutation dispatch is incomplete" ;;
esac

write_lifecycle
printf '{"action":"%s","ok":true,"role":"%s","scenario_id":"%s","schema":1}\n' \
  "$ACTION" "$ROLE" "$SCENARIO_ID" >&3
