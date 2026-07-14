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
readonly private_key="$home/.ssh/$LEARNER_KEY_NAME"
readonly public_key="${private_key}.pub"
assert_regular_mode "$private_key" 600
assert_regular_mode "$public_key" 644
[[ $(file_uid "$private_key") == "$EUID" ]] || die "learner private key is not candidate-owned"

derived=$(ssh-keygen -y -f "$private_key" | awk '{print $1 " " $2}')
exported=$(<"$public_key")
[[ "$exported" == "$derived candidate@cks-simulator" ]] || die "learner public key does not match its private key"
printf '%s\n' "$exported" | read_exact_public_key
