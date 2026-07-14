#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_root
require_command kubeadm
require_command python3
set +a
unset BOOTSTRAP_TOKEN
framed_token=''
if ! framed_token="$(python3 -c '
import re
import sys

payload = sys.stdin.buffer.read(65)
if len(payload) > 64 or re.fullmatch(rb"[a-z0-9]{6}\.[a-z0-9]{16}\n", payload) is None:
    raise SystemExit(64)
sys.stdout.buffer.write(payload + b"\x1e")
')"; then
  die "bootstrap token input must be one exact newline-terminated token"
fi
[[ "$framed_token" == *$'\x1e' ]] || die "bootstrap token framing failed"
token=${framed_token%$'\x1e'}
token=${token%$'\n'}
unset framed_token
token_id=${token%%.*}
unset token
kubeadm token delete "$token_id" >/dev/null || die "bootstrap token revocation failed"
log "bootstrap token revoked"
