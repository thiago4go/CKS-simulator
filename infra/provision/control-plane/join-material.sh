#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
readonly CRI_SOCKET='unix:///run/containerd/containerd.sock'

require_root
require_env NODE_NAME CONTROL_PLANE_ENDPOINT
require_command kubeadm
require_command openssl
require_command sha256sum
validate_control_plane_endpoint "$NODE_NAME"
[[ -f /etc/kubernetes/pki/ca.crt && ! -L /etc/kubernetes/pki/ca.crt ]] \
  || die "cluster CA certificate is not a regular trusted file"

token=''
cleanup_token() {
  if [[ -n "$token" ]]; then
    kubeadm token delete "$token" >/dev/null 2>&1 || true
  fi
}
trap cleanup_token ERR INT TERM

token=$(kubeadm token create --ttl 15m) || die "failed to create 15-minute bootstrap token"
[[ "$token" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || die "kubeadm returned an invalid bootstrap token"
ca_hash=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | sha256sum \
  | awk '{print $1}')
[[ "$ca_hash" =~ ^[0-9a-f]{64}$ ]] || die "failed to derive the cluster CA public-key hash"

printf -v material '%s\n%s\n%s\n%s\n' \
  "CONTROL_PLANE_ENDPOINT=${CONTROL_PLANE_ENDPOINT}" \
  "BOOTSTRAP_TOKEN=${token}" \
  "DISCOVERY_TOKEN_CA_CERT_HASH=sha256:${ca_hash}" \
  "CRI_SOCKET=${CRI_SOCKET}"
[[ ${#material} -le 512 ]] || die "join material exceeded the 512-byte output bound"
printf '%s' "$material"
trap - ERR INT TERM
