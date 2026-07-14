#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly SERVER_HOST=${1:-}
readonly KUBECONFIG=/etc/kubernetes/admin.conf
readonly STATE_DIR=/var/lib/cks-simulator/candidate-credential
readonly CA_CERT=/etc/kubernetes/pki/ca.crt
readonly CA_KEY=/etc/kubernetes/pki/ca.key
export KUBECONFIG

[[ ${EUID} -eq 0 ]] || { printf 'ERROR: must run as root\n' >&2; exit 1; }
[[ ${#SERVER_HOST} -le 63 && "$SERVER_HOST" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || {
  printf 'ERROR: invalid control-plane server host\n' >&2; exit 1;
}
for command in openssl sha256sum kubectl python3; do
  command -v "$command" >/dev/null 2>&1 || { printf 'ERROR: missing %s\n' "$command" >&2; exit 1; }
done
for path in "$CA_CERT" "$CA_KEY" "$KUBECONFIG"; do
  [[ -f "$path" && ! -L "$path" ]] || { printf 'ERROR: unsafe cluster credential path\n' >&2; exit 1; }
done

install -d -m 0700 -o root -g root "$STATE_DIR"
temporary=$(mktemp -d "${STATE_DIR}/.sign.XXXXXX")
trap 'rm -rf -- "${temporary:-}"' EXIT
python3 -c '
import sys
value = sys.stdin.buffer.read(8193)
if len(value) > 8192 or not value.startswith(b"-----BEGIN CERTIFICATE REQUEST-----\n") or not value.endswith(b"-----END CERTIFICATE REQUEST-----\n"):
    raise SystemExit("CSR must be one bounded canonical PEM document")
if b"PRIVATE KEY" in value or b"\x00" in value or b"\r" in value:
    raise SystemExit("CSR contains forbidden material")
sys.stdout.buffer.write(value)
' >"$temporary/candidate.csr"
openssl req -in "$temporary/candidate.csr" -noout -verify >/dev/null 2>&1 || {
  printf 'ERROR: candidate CSR is invalid\n' >&2; exit 1;
}
subject=$(openssl req -in "$temporary/candidate.csr" -noout -subject -nameopt RFC2253)
subject=${subject// /}
case "$subject" in
  'subject=O=cks-simulator:learners,CN=candidate'|'subject=CN=candidate,O=cks-simulator:learners') ;;
  *) printf 'ERROR: candidate CSR subject is invalid\n' >&2; exit 1 ;;
esac

csr_digest=$(sha256sum "$temporary/candidate.csr" | awk '{print $1}')
if [[ -f "$STATE_DIR/csr.sha256" ]]; then
  [[ ! -L "$STATE_DIR/csr.sha256" && $(<"$STATE_DIR/csr.sha256") == "$csr_digest" ]] || {
    printf 'ERROR: candidate CSR changed; destroy and rebuild the immutable lab\n' >&2; exit 1;
  }
fi
if [[ ! -f "$STATE_DIR/candidate.crt" ]]; then
  serial=${csr_digest:0:32}
  openssl x509 -req -in "$temporary/candidate.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -set_serial "0x${serial}" \
    -days 3650 -sha256 -out "$temporary/candidate.crt" >/dev/null 2>&1
  openssl verify -CAfile "$CA_CERT" "$temporary/candidate.crt" >/dev/null 2>&1
  install -m 0644 -o root -g root "$temporary/candidate.crt" "$STATE_DIR/candidate.crt.new"
  mv -fT "$STATE_DIR/candidate.crt.new" "$STATE_DIR/candidate.crt"
  printf '%s\n' "$csr_digest" >"$STATE_DIR/csr.sha256.new"
  chmod 0600 "$STATE_DIR/csr.sha256.new"
  mv -fT "$STATE_DIR/csr.sha256.new" "$STATE_DIR/csr.sha256"
fi
openssl verify -CAfile "$CA_CERT" "$STATE_DIR/candidate.crt" >/dev/null 2>&1
csr_key=$(openssl req -in "$temporary/candidate.csr" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
cert_key=$(openssl x509 -in "$STATE_DIR/candidate.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[[ "$csr_key" == "$cert_key" ]] || { printf 'ERROR: stored certificate does not match CSR\n' >&2; exit 1; }

cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cks-simulator-learners
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: cks-simulator:learners
    apiGroup: rbac.authorization.k8s.io
EOF

python3 - "$SERVER_HOST" "$CA_CERT" "$STATE_DIR/candidate.crt" <<'PY'
import base64
import json
import pathlib
import sys

host, ca_path, cert_path = sys.argv[1:]
value = {
    "schema": 1,
    "cluster_name": "cks-simulator",
    "server": f"https://{host}:6443",
    "certificate_authority_data": base64.b64encode(pathlib.Path(ca_path).read_bytes()).decode("ascii"),
    "client_certificate_data": base64.b64encode(pathlib.Path(cert_path).read_bytes()).decode("ascii"),
}
print(json.dumps(value, separators=(",", ":"), sort_keys=True))
PY
