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
home=$(candidate_home)
readonly ssh_dir="$home/.ssh"
[[ ! -L "$ssh_dir" ]] || die "unsafe candidate SSH directory"
install -d -m 0700 -- "$ssh_dir"
[[ -d "$ssh_dir" && ! -L "$ssh_dir" ]] || die "candidate SSH directory is unsafe"
chmod 0700 "$ssh_dir"

readonly private_key="$ssh_dir/$LEARNER_KEY_NAME"
readonly public_key="${private_key}.pub"
if [[ ! -e "$private_key" ]]; then
  [[ ! -L "$private_key" && ! -L "$public_key" ]] || die "candidate SSH key path is unsafe"
  rm -f -- "$public_key"
  ssh-keygen -q -t ed25519 -N '' -C candidate@cks-simulator -f "$private_key"
fi
[[ -f "$private_key" && ! -L "$private_key" ]] || die "learner private key is missing or unsafe"
chmod 0600 "$private_key"
ssh-keygen -l -f "$private_key" | grep -Fq '(ED25519)' || die "learner key is not Ed25519"

temporary_public=$(mktemp "$ssh_dir/.learner-public.XXXXXX")
trap 'rm -f -- "${temporary_public:-}"' EXIT
{
  ssh-keygen -y -f "$private_key" | awk '{printf "%s %s", $1, $2}'
  printf ' candidate@cks-simulator\n'
} >"$temporary_public"
chmod 0644 "$temporary_public"
mv -fT -- "$temporary_public" "$public_key"
printf 'candidate home configured\n'
