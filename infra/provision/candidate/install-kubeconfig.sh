#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_candidate_user
for command in python3 openssl kubectl sha256sum; do
  require_command "$command"
done
home=$(candidate_home)
install -d -m 0700 -- "$home/.kube"
readonly private_key="$home/.kube/candidate.key"
assert_regular_mode "$private_key" 600
temporary=$(mktemp -d "$home/.kube/.credential.XXXXXX")
trap 'rm -rf -- "${temporary:-}"' EXIT

python3 -c '
import sys
payload = sys.stdin.buffer.read(65537)
if len(payload) > 65536 or not payload.endswith(b"\n") or payload.count(b"\n") != 1:
    raise SystemExit("credential manifest must be one bounded newline-terminated JSON record")
if b"\x00" in payload or b"\r" in payload or b"PRIVATE KEY" in payload:
    raise SystemExit("credential manifest contains forbidden material")
sys.stdout.buffer.write(payload)
' >"$temporary/input.json"

python3 - "$temporary/input.json" "$temporary" <<'PY'
import base64
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

input_path, output_dir = sys.argv[1:]
with open(input_path, "rb") as stream:
    value = json.load(stream)
expected = {
    "schema",
    "cluster_name",
    "server",
    "certificate_authority_data",
    "client_certificate_data",
}
if set(value) != expected or value["schema"] != 1 or value["cluster_name"] != "cks-simulator":
    raise SystemExit("unsupported credential manifest")
server = value["server"]
if not isinstance(server, str) or len(server) > 512:
    raise SystemExit("invalid Kubernetes server")
parsed = urlsplit(server)
if parsed.scheme != "https" or parsed.port != 6443 or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
    raise SystemExit("Kubernetes server must be an HTTPS 6443 endpoint")
host = parsed.hostname
if host is None or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    raise SystemExit("invalid Kubernetes server host")
try:
    address = ipaddress.ip_address(host)
except ValueError:
    address = None
if address is not None and (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified):
    raise SystemExit("unsafe Kubernetes server address")

for field, filename, marker in (
    ("certificate_authority_data", "ca.crt", b"CERTIFICATE"),
    ("client_certificate_data", "candidate.crt", b"CERTIFICATE"),
):
    encoded = value[field]
    if not isinstance(encoded, str) or len(encoded) > 32768:
        raise SystemExit("invalid certificate field")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise SystemExit("invalid certificate encoding")
    if len(decoded) > 16384 or b"PRIVATE KEY" in decoded:
        raise SystemExit("certificate field contains forbidden material")
    if not decoded.startswith(b"-----BEGIN " + marker + b"-----\n") or not decoded.endswith(b"-----END " + marker + b"-----\n"):
        raise SystemExit("certificate field is not canonical PEM")
    with open(f"{output_dir}/{filename}", "xb") as stream:
        stream.write(decoded)
with open(f"{output_dir}/server", "x", encoding="ascii") as stream:
    stream.write(server)
PY

openssl x509 -in "$temporary/ca.crt" -noout >/dev/null 2>&1 || die "cluster CA is invalid"
openssl x509 -in "$temporary/candidate.crt" -noout >/dev/null 2>&1 || die "candidate certificate is invalid"
openssl verify -CAfile "$temporary/ca.crt" "$temporary/candidate.crt" >/dev/null 2>&1 || die "candidate certificate is not signed by the supplied CA"
subject=$(openssl x509 -in "$temporary/candidate.crt" -noout -subject -nameopt RFC2253)
subject=${subject// /}
case "$subject" in
  'subject=O=cks-simulator:learners,CN=candidate'|'subject=CN=candidate,O=cks-simulator:learners') ;;
  *) die "candidate certificate subject is invalid" ;;
esac
key_digest=$(openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
cert_digest=$(openssl x509 -in "$temporary/candidate.crt" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[[ "$key_digest" == "$cert_digest" ]] || die "candidate certificate does not match its private key"

install -m 0644 "$temporary/ca.crt" "$home/.kube/ca.crt.new"
install -m 0644 "$temporary/candidate.crt" "$home/.kube/candidate.crt.new"
atomic_replace "$home/.kube/ca.crt.new" "$home/.kube/ca.crt"
atomic_replace "$home/.kube/candidate.crt.new" "$home/.kube/candidate.crt"
server=$(<"$temporary/server")
readonly kubeconfig="$temporary/config"
kubectl config --kubeconfig="$kubeconfig" set-cluster cks-simulator \
  --server="$server" --certificate-authority="$home/.kube/ca.crt" --embed-certs=false >/dev/null
kubectl config --kubeconfig="$kubeconfig" set-credentials candidate \
  --client-certificate="$home/.kube/candidate.crt" --client-key="$home/.kube/candidate.key" --embed-certs=false >/dev/null
kubectl config --kubeconfig="$kubeconfig" set-context candidate@cks-simulator \
  --cluster=cks-simulator --user=candidate >/dev/null
kubectl config --kubeconfig="$kubeconfig" use-context candidate@cks-simulator >/dev/null
chmod 0600 "$kubeconfig"
install_if_changed "$kubeconfig" "$home/.kube/config" 0600 || true
printf 'candidate kubeconfig installed\n'
