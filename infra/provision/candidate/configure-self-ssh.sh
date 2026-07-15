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
for command in getent install runuser sshd ssh-keygen systemctl; do
  require_command "$command"
done
readonly public_key="$(read_exact_public_key)"
account=$(getent passwd "$CANDIDATE_USER") || die "candidate account is missing"
IFS=: read -r account_name _ account_uid _ _ account_home account_shell <<<"$account"
[[ "$account_name" == "$CANDIDATE_USER" && "$account_uid" =~ ^[0-9]+$ && "$account_uid" -ge 1000 ]] \
  || die "candidate account is unsafe"
[[ "$account_home" == "$CANDIDATE_HOME" && "$account_shell" == /bin/bash ]] \
  || die "candidate account has unexpected home or shell"
readonly persistent_host_key=/etc/ssh/cks-simulator-host-ed25519_key
readonly active_host_key=/etc/ssh/ssh_host_ed25519_key

if [[ ! -e "$persistent_host_key" ]]; then
  [[ ! -L "$persistent_host_key" ]] || die "persistent SSH host key path is unsafe"
  ssh-keygen -q -t ed25519 -N '' -C cks-simulator -f "$persistent_host_key"
fi
assert_regular_mode "$persistent_host_key" 600
assert_regular_mode "${persistent_host_key}.pub" 600
if restore_persistent_host_key "$persistent_host_key" "$active_host_key"; then
  :
else
  restore_status=$?
  (( restore_status == 1 )) || exit "$restore_status"
fi

runuser -u "$CANDIDATE_USER" -- env HOME="$CANDIDATE_HOME" /bin/bash -c '
set -Eeuo pipefail
umask 077
[[ -d "$HOME" && ! -L "$HOME" ]] || exit 1
[[ ! -L "$HOME/.ssh" ]] || exit 1
install -d -m 0700 -- "$HOME/.ssh"
temporary=$(mktemp "$HOME/.ssh/.authorized-keys.XXXXXX")
trap '\''rm -f -- "${temporary:-}"'\'' EXIT
printf "%s\n" "$1" >"$temporary"
chmod 0600 "$temporary"
mv -fT -- "$temporary" "$HOME/.ssh/authorized_keys"
' bash "$public_key"

temporary=$(mktemp)
trap 'rm -f -- "${temporary:-}"' EXIT
cat >"$temporary" <<'EOF'
Match User candidate
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    X11Forwarding no
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTunnel no
    PermitUserRC no
EOF
install -d -m 0755 -o root -g root /run/sshd /etc/ssh/sshd_config.d
install_if_changed "$temporary" /etc/ssh/sshd_config.d/60-cks-candidate.conf 0644 || true
sshd -t
systemctl reload-or-restart ssh.service
systemctl is-active --quiet ssh || die "SSH service is not active"
assert_candidate_password_locked
assert_candidate_has_no_sudo
printf 'candidate self-SSH configured\n'
