#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'cluster-provision: %s\n' "$*" >&2
}

require_env() {
  local name
  for name in "$@"; do
    [[ -n ${!name:-} ]] || die "required environment value is missing: ${name}"
  done
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
require_env NODE_NAME NODE_IP
command -v python3 >/dev/null 2>&1 || die "required command is unavailable: python3"

# Join credentials arrive only on standard input. Clear any inherited values and
# disable automatic exporting before assigning the validated shell variables so
# neither secret can reach kubeadm through its environment.
set +a
unset BOOTSTRAP_TOKEN DISCOVERY_TOKEN_CA_CERT_HASH CONTROL_PLANE_ENDPOINT CRI_SOCKET
readonly EXPECTED_CRI_SOCKET='unix:///run/containerd/containerd.sock'

framed_join_material=''
if ! framed_join_material="$(python3 -c '
import sys

payload = sys.stdin.buffer.read(513)
if len(payload) > 512 or not payload.endswith(b"\n") or b"\0" in payload:
    raise SystemExit(64)
try:
    payload.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(64)
sys.stdout.buffer.write(payload + b"\x1e")
')"; then
  die "join material must be ASCII, newline-terminated, and at most 512 bytes"
fi
[[ "$framed_join_material" == *$'\x1e' ]] || die "join material framing failed"
join_material=${framed_join_material%$'\x1e'}
unset framed_join_material

join_remainder=$join_material
take_join_line() {
  [[ "$join_remainder" == *$'\n'* ]] || die "join material had an invalid record count"
  JOIN_LINE=${join_remainder%%$'\n'*}
  join_remainder=${join_remainder#*$'\n'}
}

take_join_line
endpoint_line=$JOIN_LINE
take_join_line
token_line=$JOIN_LINE
take_join_line
ca_hash_line=$JOIN_LINE
take_join_line
cri_socket_line=$JOIN_LINE
[[ -z "$join_remainder" ]] || die "unexpected data after join material"
unset JOIN_LINE join_remainder join_material

[[ "$endpoint_line" == CONTROL_PLANE_ENDPOINT=* ]] || die "join material endpoint field is invalid"
[[ "$token_line" == BOOTSTRAP_TOKEN=* ]] || die "join material token field is invalid"
[[ "$ca_hash_line" == DISCOVERY_TOKEN_CA_CERT_HASH=* ]] || die "join material CA hash field is invalid"
[[ "$cri_socket_line" == CRI_SOCKET=* ]] || die "join material CRI socket field is invalid"
CONTROL_PLANE_ENDPOINT=${endpoint_line#CONTROL_PLANE_ENDPOINT=}
BOOTSTRAP_TOKEN=${token_line#BOOTSTRAP_TOKEN=}
DISCOVERY_TOKEN_CA_CERT_HASH=${ca_hash_line#DISCOVERY_TOKEN_CA_CERT_HASH=}
CRI_SOCKET=${cri_socket_line#CRI_SOCKET=}
unset endpoint_line token_line ca_hash_line cri_socket_line

[[ "$NODE_NAME" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ && ${#NODE_NAME} -le 63 ]] \
  || die "invalid exact worker hostname"
[[ "$CONTROL_PLANE_ENDPOINT" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?:6443$ ]] \
  || die "controlPlaneEndpoint must be an exact stable DNS hostname on port 6443"
[[ "$BOOTSTRAP_TOKEN" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || die "invalid bootstrap token"
[[ "$DISCOVERY_TOKEN_CA_CERT_HASH" =~ ^sha256:[0-9a-f]{64}$ ]] || die "invalid discovery CA hash"
[[ "$CRI_SOCKET" == "$EXPECTED_CRI_SOCKET" ]] || die "invalid CRI socket"
python3 -c 'import ipaddress, sys; ipaddress.IPv4Address(sys.argv[1])' "$NODE_IP" \
  || die "invalid worker node IP"
observed_hostname=$(hostname --short)
[[ "$observed_hostname" == "$NODE_NAME" || "$observed_hostname" == "lima-${NODE_NAME}" ]] \
  || die "local hostname does not match the immutable Lima worker identity"
ip -4 -o address show scope global \
  | awk '{sub(/\/.*/, "", $4); print $4}' \
  | grep -Fx "$NODE_IP" >/dev/null \
  || die "expected worker node IP is not assigned locally"

verify_existing_membership() {
  local kubeconfig=/etc/kubernetes/kubelet.conf server client_cert resolved_cert cert_subject ca_data ca_file ca_hash api_ip
  [[ -f "$kubeconfig" && ! -L "$kubeconfig" ]] || die "existing kubelet.conf is not a regular trusted file"
  server=$(kubectl --kubeconfig "$kubeconfig" config view --raw --minify \
    -o jsonpath='{.clusters[0].cluster.server}')
  [[ "$server" == "https://${CONTROL_PLANE_ENDPOINT}" ]] \
    || die "existing kubelet API endpoint mismatch"
  client_cert=$(kubectl --kubeconfig "$kubeconfig" config view --raw --minify \
    -o jsonpath='{.users[0].user.client-certificate}')
  [[ "$client_cert" == /var/lib/kubelet/pki/kubelet-client-current.pem ]] \
    || die "existing kubelet client certificate path mismatch"
  resolved_cert=$(readlink -f -- "$client_cert")
  [[ "$resolved_cert" == /var/lib/kubelet/pki/kubelet-client-*.pem \
    && -f "$resolved_cert" && ! -L "$resolved_cert" ]] \
    || die "existing kubelet client certificate is unsafe"
  cert_subject=$(openssl x509 -in "$resolved_cert" -noout -subject -nameopt RFC2253)
  [[ "$cert_subject" == "subject=CN=system:node:${NODE_NAME},O=system:nodes" ]] \
    || die "existing kubelet node identity mismatch"
  ca_data=$(kubectl --kubeconfig "$kubeconfig" config view --raw --minify \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
  [[ -n "$ca_data" ]] || die "existing kubelet kubeconfig has no embedded cluster CA"
  ca_file=$(mktemp)
  trap 'rm -f -- "$ca_file"' RETURN
  printf '%s' "$ca_data" | base64 --decode >"$ca_file" || die "existing kubelet cluster CA is invalid"
  ca_hash=$(openssl x509 -pubkey -in "$ca_file" \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | sha256sum \
    | awk '{print "sha256:" $1}')
  [[ "$ca_hash" == "$DISCOVERY_TOKEN_CA_CERT_HASH" ]] \
    || die "existing kubelet cluster CA hash mismatch"
  api_ip=$(kubectl --kubeconfig "$kubeconfig" get node "$NODE_NAME" \
    -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
  [[ "$api_ip" == "$NODE_IP" ]] || die "existing API node IP mismatch"
  rm -f -- "$ca_file"
  trap - RETURN
}

if [[ -e /etc/kubernetes/kubelet.conf || -L /etc/kubernetes/kubelet.conf ]]; then
  log "verifying existing worker membership before replay"
  verify_existing_membership
else
  log "joining exact worker ${NODE_NAME} to ${CONTROL_PLANE_ENDPOINT}"
  join_status=0
  kubeadm join --config /dev/stdin <<EOF || join_status=$?
apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: "${CONTROL_PLANE_ENDPOINT}"
    token: "${BOOTSTRAP_TOKEN}"
    caCertHashes:
      - "${DISCOVERY_TOKEN_CA_CERT_HASH}"
nodeRegistration:
  criSocket: "${CRI_SOCKET}"
  name: "${NODE_NAME}"
  kubeletExtraArgs:
    - name: node-ip
      value: "${NODE_IP}"
EOF
  unset BOOTSTRAP_TOKEN
  [[ $join_status -eq 0 ]] || die "kubeadm worker join failed"
fi
unset BOOTSTRAP_TOKEN

systemctl enable kubelet >/dev/null
systemctl restart kubelet
systemctl is-active --quiet kubelet || die "kubelet did not become active"

for attempt in $(seq 1 60); do
  if (verify_existing_membership) >/dev/null 2>&1; then
    log "worker membership and immutable identity verified"
    exit 0
  fi
  sleep 5
done
die "worker API membership did not verify within five minutes"
