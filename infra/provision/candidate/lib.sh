#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly CANDIDATE_USER=candidate
readonly CANDIDATE_HOME=/home/candidate
readonly LEARNER_KEY_NAME=cks-learner-ed25519

die() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

require_root() {
  [[ ${EUID} -eq 0 ]] || { die "must run as root"; return 1; }
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || { die "required command not found: $1"; return 1; }
}

require_candidate_user() {
  local expected=$CANDIDATE_USER
  # Offline tests run the same operations against an isolated HOME. The hook
  # cannot grant privilege and is rejected for uid 0.
  if [[ -n ${CKS_CANDIDATE_TEST_USER:-} ]]; then
    (( EUID != 0 )) || { die "test user override is forbidden for root"; return 1; }
    expected=$CKS_CANDIDATE_TEST_USER
  fi
  [[ $(id -un) == "$expected" ]] || { die "must run as the candidate user"; return 1; }
  [[ ${HOME:-} == /* && -d ${HOME:-} && ! -L ${HOME:-} ]] || { die "candidate HOME is unsafe"; return 1; }
}

candidate_home() {
  if [[ -n ${CKS_CANDIDATE_TEST_USER:-} ]]; then
    printf '%s' "$HOME"
  else
    printf '%s' "$CANDIDATE_HOME"
  fi
}

read_exact_public_key() {
  python3 -c '
import base64
import re
import struct
import sys

payload = sys.stdin.buffer.read(513)
match = re.fullmatch(
    rb"ssh-ed25519 ([A-Za-z0-9+/]+={0,2}) candidate@cks-simulator\n",
    payload,
)
if match is None or len(payload) > 512:
    raise SystemExit("expected one exact newline-terminated learner Ed25519 public key")
try:
    blob = base64.b64decode(match.group(1), validate=True)
except ValueError:
    raise SystemExit("invalid learner public key encoding")
if len(blob) < 4:
    raise SystemExit("invalid learner public key blob")
size = struct.unpack(">I", blob[:4])[0]
if blob[4:4 + size] != b"ssh-ed25519":
    raise SystemExit("learner public key blob is not Ed25519")
sys.stdout.buffer.write(payload)
'
}

assert_regular_mode() {
  local path=$1 expected_mode=$2 mode
  [[ -f "$path" && ! -L "$path" ]] || { die "required regular file is missing: ${path}"; return 1; }
  mode=$(python3 -c 'import os,sys; print(format(os.stat(sys.argv[1], follow_symlinks=False).st_mode & 0o777, "o"))' "$path") || return 1
  [[ "$mode" == "$expected_mode" ]] || { die "unexpected mode on ${path}"; return 1; }
}

file_uid() {
  python3 -c 'import os,sys; print(os.stat(sys.argv[1], follow_symlinks=False).st_uid)' "$1"
}

atomic_replace() {
  python3 -c 'import os,sys; os.replace(sys.argv[1], sys.argv[2])' "$1" "$2"
}

assert_candidate_password_locked() {
  local status
  status=$(passwd --status "$CANDIDATE_USER") || return 1
  [[ $(awk '{print $2}' <<<"$status") == L ]] || { die "candidate password is not locked"; return 1; }
}

assert_candidate_has_no_sudo() {
  local result
  if (( EUID == 0 )); then
    if runuser -u "$CANDIDATE_USER" -- sudo -n true </dev/null >/dev/null 2>&1; then
      die "candidate unexpectedly has sudo on the workstation"
      return 1
    fi
  else
    result=0
    sudo -n true </dev/null >/dev/null 2>&1 || result=$?
    (( result != 0 )) || { die "candidate unexpectedly has sudo on the workstation"; return 1; }
  fi
}

install_if_changed() {
  local source=$1 destination=$2 mode=$3
  if [[ -f "$destination" && ! -L "$destination" ]] && cmp -s -- "$source" "$destination"; then
    chmod "$mode" "$destination"
    return 1
  fi
  install -m "$mode" "$source" "${destination}.new"
  atomic_replace "${destination}.new" "$destination"
  return 0
}

restore_persistent_host_key() {
  local persistent=$1 active=$2 derived declared changed=0 destination
  assert_regular_mode "$persistent" 600 || return 2
  assert_regular_mode "${persistent}.pub" 600 || return 2
  for destination in "$active" "${active}.pub"; do
    [[ ! -L "$destination" ]] || { die "active SSH host key path is unsafe"; return 2; }
  done
  derived=$(ssh-keygen -y -f "$persistent" | awk '{print $1 " " $2}') || return 2
  declared=$(awk '{print $1 " " $2}' "${persistent}.pub") || return 2
  [[ "$derived" == "$declared" ]] || { die "persistent SSH host keypair mismatch"; return 2; }
  if [[ -f "$active" ]] && cmp -s -- "$persistent" "$active"; then
    chmod 0600 "$active" || return 2
  else
    install -m 0600 "$persistent" "${active}.new" || return 2
    atomic_replace "${active}.new" "$active" || return 2
    changed=1
  fi
  if [[ -f "${active}.pub" ]] && cmp -s -- "${persistent}.pub" "${active}.pub"; then
    chmod 0644 "${active}.pub" || return 2
  else
    install -m 0644 "${persistent}.pub" "${active}.pub.new" || return 2
    atomic_replace "${active}.pub.new" "${active}.pub" || return 2
    changed=1
  fi
  (( changed == 1 ))
}
