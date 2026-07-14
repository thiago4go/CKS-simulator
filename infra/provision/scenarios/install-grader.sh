#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly IDENTITY=/etc/cks-simulator/identity.json
readonly STATE_DIR=/var/lib/cks-simulator/grader
readonly GRADER_CONFIG=/etc/cks-simulator/cks-grader.kubeconfig
readonly OPERATOR_CONFIG=/etc/kubernetes/admin.conf
readonly CERT_DAYS=3650

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die "usage: install-grader.sh"
[[ ${EUID} -eq 0 ]] || die "must run as root"

for command in kubectl openssl python3 install stat base64; do
  command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
done

role=$(python3 - "$IDENTITY" <<'PY'
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
[[ "$role" == control-plane ]] || die "grader identity is installed only on control-plane"

for path in "$OPERATOR_CONFIG" /etc/kubernetes/pki/ca.crt /etc/kubernetes/pki/ca.key; do
  [[ -f "$path" && ! -L "$path" ]] || die "required control-plane file is missing or unsafe: ${path}"
done

install -d -m 0700 -o root -g root -- "$STATE_DIR" /etc/cks-simulator

if [[ ! -f "$STATE_DIR/cks-grader.key" || ! -f "$STATE_DIR/cks-grader.crt" ]]; then
  work=$(mktemp -d "$STATE_DIR/.issue.XXXXXX")
  trap 'rm -rf -- "$work"' EXIT
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$work/cks-grader.key" >/dev/null 2>&1
  openssl req -new -key "$work/cks-grader.key" \
    -subj '/CN=cks-grader/O=cks-simulator:graders' -out "$work/cks-grader.csr"
  openssl x509 -req -in "$work/cks-grader.csr" \
    -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key \
    -CAcreateserial -days "$CERT_DAYS" -sha256 -out "$work/cks-grader.crt" >/dev/null 2>&1
  openssl verify -CAfile /etc/kubernetes/pki/ca.crt "$work/cks-grader.crt" >/dev/null
  install -m 0600 -o root -g root -- "$work/cks-grader.key" "$STATE_DIR/cks-grader.key.new"
  install -m 0644 -o root -g root -- "$work/cks-grader.crt" "$STATE_DIR/cks-grader.crt.new"
  mv -fT -- "$STATE_DIR/cks-grader.key.new" "$STATE_DIR/cks-grader.key"
  mv -fT -- "$STATE_DIR/cks-grader.crt.new" "$STATE_DIR/cks-grader.crt"
  rm -rf -- "$work"
  trap - EXIT
fi

openssl pkey -in "$STATE_DIR/cks-grader.key" -noout >/dev/null 2>&1 || die "grader private key is invalid"
openssl verify -CAfile /etc/kubernetes/pki/ca.crt "$STATE_DIR/cks-grader.crt" >/dev/null || die "grader certificate is invalid"
subject=$(openssl x509 -in "$STATE_DIR/cks-grader.crt" -noout -subject -nameopt RFC2253)
case "$subject" in
  'subject=O=cks-simulator:graders,CN=cks-grader'|'subject=CN=cks-grader,O=cks-simulator:graders') ;;
  *) die "grader certificate subject is invalid" ;;
esac

admin_view=$(mktemp "$STATE_DIR/.operator-view.XXXXXX")
rendered=$(mktemp "$STATE_DIR/.kubeconfig.XXXXXX")
trap 'rm -f -- "$admin_view" "$rendered"' EXIT
kubectl --kubeconfig="$OPERATOR_CONFIG" config view --raw --flatten --minify -o json >"$admin_view"
python3 - "$admin_view" "$STATE_DIR/cks-grader.crt" "$STATE_DIR/cks-grader.key" "$rendered" <<'PY'
import base64
import json
import os
import stat
import sys

source, cert_path, key_path, destination = sys.argv[1:]
if os.path.getsize(source) > 65536:
    raise SystemExit("operator kubeconfig view exceeds size limit")
with open(source, "r", encoding="utf-8") as stream:
    value = json.load(stream)
clusters = value.get("clusters")
if not isinstance(clusters, list) or len(clusters) != 1:
    raise SystemExit("operator kubeconfig must expose exactly one cluster")
cluster = clusters[0].get("cluster")
if not isinstance(cluster, dict):
    raise SystemExit("operator cluster entry is invalid")
server = cluster.get("server")
ca_data = cluster.get("certificate-authority-data")
if not isinstance(server, str) or not server.startswith("https://") or len(server) > 512:
    raise SystemExit("operator API server is invalid")
if not isinstance(ca_data, str) or len(ca_data) > 32768:
    raise SystemExit("operator CA data is invalid")
base64.b64decode(ca_data, validate=True)

def encoded(path: str, limit: int) -> str:
    observed = os.lstat(path)
    if not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_size > limit:
        raise SystemExit("grader credential file is invalid")
    with open(path, "rb") as stream:
        return base64.b64encode(stream.read()).decode("ascii")

payload = {
    "apiVersion": "v1",
    "kind": "Config",
    "clusters": [{"name": "cks-simulator", "cluster": {"server": server, "certificate-authority-data": ca_data}}],
    "users": [{"name": "cks-grader", "user": {
        "client-certificate-data": encoded(cert_path, 32768),
        "client-key-data": encoded(key_path, 32768),
    }}],
    "contexts": [{"name": "cks-grader@cks-simulator", "context": {"cluster": "cks-simulator", "user": "cks-grader"}}],
    "current-context": "cks-grader@cks-simulator",
}
with open(destination, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
    stream.write("\n")
PY
install -m 0600 -o root -g root -- "$rendered" "$GRADER_CONFIG.new"
mv -fT -- "$GRADER_CONFIG.new" "$GRADER_CONFIG"
rm -f -- "$admin_view" "$rendered"
trap - EXIT

kubectl --kubeconfig="$OPERATOR_CONFIG" apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: team-coral
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-purple
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-sepia
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cks-grader-scenario-namespaces
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  resourceNames: ["team-coral", "team-purple", "team-sepia"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cks-grader-scenario-namespaces
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cks-grader-scenario-namespaces
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: cks-grader
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cks-grader-s03
  namespace: default
rules:
- apiGroups: [""]
  resources: ["services"]
  resourceNames: ["kubernetes"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cks-grader-s03
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cks-grader-s03
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: cks-grader
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cks-grader-s04
  namespace: team-coral
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  resourceNames: ["stream-multiplex"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cks-grader-s04
  namespace: team-coral
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cks-grader-s04
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: cks-grader
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cks-grader-s06
  namespace: team-purple
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  resourceNames: ["immutable-deployment"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cks-grader-s06
  namespace: team-purple
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cks-grader-s06
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: cks-grader
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cks-grader-s07
  namespace: team-sepia
rules:
- apiGroups: [""]
  resources: ["pods"]
  resourceNames: ["bad-pod"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cks-grader-s07
  namespace: team-sepia
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cks-grader-s07
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: cks-grader
EOF

can() {
  kubectl --kubeconfig="$GRADER_CONFIG" auth can-i "$@" --quiet
}

deny() {
  if can "$@"; then
    die "grader RBAC unexpectedly allows: $*"
  fi
}

can get services/kubernetes --namespace default || die "grader cannot read the kubernetes Service"
can get namespaces/team-sepia || die "grader cannot read the team-sepia namespace"
can get deployments.apps/stream-multiplex --namespace team-coral || die "grader cannot read scenario 04 Deployment"
can list pods --namespace team-coral || die "grader cannot discover scenario 04 Deployment Pods"
can list pods --namespace team-purple || die "grader cannot discover scenario 06 Deployment Pods"
can get pods/bad-pod --namespace team-sepia || die "grader cannot read scenario 07 Pod"

deny get secrets --all-namespaces
deny list secrets --all-namespaces
deny create deployments.apps --namespace team-coral
deny patch deployments.apps --namespace team-coral
deny delete deployments.apps --namespace team-coral
deny list deployments.apps --namespace team-coral
deny get deployments.apps/not-stream-multiplex --namespace team-coral
deny list pods --namespace default
deny get pods --subresource=log --namespace team-coral
deny create pods --subresource=exec --namespace team-coral
deny create pods --subresource=attach --namespace team-coral
deny create pods --subresource=portforward --namespace team-coral
deny get services --subresource=proxy --namespace default
deny get nodes --subresource=proxy

printf 'scenario-grader-install: passed\n'
