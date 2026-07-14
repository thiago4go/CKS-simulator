#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_root
readonly public_key="$(read_exact_public_key)"
readonly persistent_host_key=/etc/ssh/cks-simulator-host-ed25519_key
readonly active_host_key=/etc/ssh/ssh_host_ed25519_key
getent passwd "$CANDIDATE_USER" >/dev/null || die "candidate node account is missing"
assert_candidate_password_locked
assert_regular_mode "$CANDIDATE_HOME/.ssh/authorized_keys" 600
[[ $(<"$CANDIDATE_HOME/.ssh/authorized_keys") == "$public_key" ]] || die "managed authorized_keys differs from the supplied learner key"
assert_regular_mode /etc/sudoers.d/cks-candidate 440
[[ $(</etc/sudoers.d/cks-candidate) == 'candidate ALL=(ALL:ALL) NOPASSWD: ALL' ]] || die "candidate sudo contract is not exact"
runuser -u "$CANDIDATE_USER" -- sudo -n true </dev/null >/dev/null || die "candidate passwordless sudo is unavailable"
assert_regular_mode "$persistent_host_key" 600
assert_regular_mode "${persistent_host_key}.pub" 600
assert_regular_mode "$active_host_key" 600
assert_regular_mode "${active_host_key}.pub" 644
cmp -s -- "$persistent_host_key" "$active_host_key" || die "active SSH private host key is not persistent"
cmp -s -- "${persistent_host_key}.pub" "${active_host_key}.pub" || die "active SSH public host key is not persistent"

effective=$(sshd -T -C user=candidate,host=localhost,addr=127.0.0.1)
for setting in \
  'authenticationmethods publickey' \
  'pubkeyauthentication yes' \
  'passwordauthentication no' \
  'kbdinteractiveauthentication no' \
  'allowtcpforwarding no' \
  'allowagentforwarding no' \
  'x11forwarding no' \
  'permittunnel no' \
  'permituserrc no'; do
  grep -Fxq "$setting" <<<"$effective" || die "node SSH policy mismatch: ${setting}"
done
printf 'candidate node account check passed\n'
