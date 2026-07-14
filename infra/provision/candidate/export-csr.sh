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
require_command openssl
home=$(candidate_home)
install -d -m 0700 -- "$home/.kube"
readonly private_key="$home/.kube/candidate.key"
readonly csr="$home/.kube/candidate.csr"

if [[ ! -e "$private_key" && ! -L "$private_key" ]]; then
  temporary_key=$(mktemp "$home/.kube/.candidate-key.XXXXXX")
  trap 'rm -f -- "${temporary_key:-}" "${temporary_csr:-}"' EXIT
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$temporary_key" >/dev/null 2>&1
  chmod 0600 "$temporary_key"
  atomic_replace "$temporary_key" "$private_key"
fi
assert_regular_mode "$private_key" 600
[[ $(file_uid "$private_key") == "$EUID" ]] || die "candidate Kubernetes key is not candidate-owned"
openssl pkey -in "$private_key" -noout >/dev/null 2>&1 || die "candidate Kubernetes key is invalid"

if [[ ! -e "$csr" && ! -L "$csr" ]]; then
  temporary_csr=$(mktemp "$home/.kube/.candidate-csr.XXXXXX")
  trap 'rm -f -- "${temporary_key:-}" "${temporary_csr:-}"' EXIT
  openssl req -new -key "$private_key" -subj '/CN=candidate/O=cks-simulator:learners' -out "$temporary_csr"
  chmod 0644 "$temporary_csr"
  atomic_replace "$temporary_csr" "$csr"
fi
assert_regular_mode "$csr" 644
openssl req -in "$csr" -noout -verify >/dev/null 2>&1 || die "candidate CSR is invalid"
subject=$(openssl req -in "$csr" -noout -subject -nameopt RFC2253)
[[ "$subject" == 'subject=O=cks-simulator:learners,CN=candidate' ]] || die "candidate CSR subject is invalid"
key_digest=$(openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
csr_digest=$(openssl req -in "$csr" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[[ "$key_digest" == "$csr_digest" ]] || die "candidate CSR does not match its private key"
[[ $(python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]))' "$csr") -le 8192 ]] || die "candidate CSR exceeds the export bound"
cat -- "$csr"
