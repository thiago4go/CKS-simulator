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
for command in useradd passwd install getent sshd ssh-keygen systemctl visudo runuser sudo; do
  require_command "$command"
done
readonly public_key="$(read_exact_public_key)"
readonly persistent_host_key=/etc/ssh/cks-simulator-host-ed25519_key
readonly active_host_key=/etc/ssh/ssh_host_ed25519_key

# cloud-init in the Lima Ubuntu image rotates the default SSH host key during
# boot. Keep a simulator-owned key on the guest disk and restore it before the
# learner trust manifest is rendered. The private host key never leaves the
# node; only its public half is read by the orchestrator.
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

if ! getent passwd "$CANDIDATE_USER" >/dev/null; then
  useradd --create-home --home-dir "$CANDIDATE_HOME" --shell /bin/bash \
    --comment 'CKS learner' "$CANDIDATE_USER"
fi
account=$(getent passwd "$CANDIDATE_USER")
IFS=: read -r name _ uid _ _ home shell <<<"$account"
[[ "$name" == "$CANDIDATE_USER" && "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 ]] || die "unsafe candidate account"
[[ "$home" == "$CANDIDATE_HOME" && "$shell" == /bin/bash ]] || die "candidate account has unexpected home or shell"
passwd --lock "$CANDIDATE_USER" >/dev/null

sudoers=$(mktemp)
sshd_config=$(mktemp)
trap 'rm -f -- "${sudoers:-}" "${sshd_config:-}"' EXIT
runuser -u "$CANDIDATE_USER" -- env HOME="$CANDIDATE_HOME" /bin/bash -c '
set -Eeuo pipefail
umask 077
ssh_dir="$HOME/.ssh"
[[ ! -L "$ssh_dir" ]] || exit 1
install -d -m 0700 -- "$ssh_dir"
[[ -d "$ssh_dir" && ! -L "$ssh_dir" ]] || exit 1
temporary=$(mktemp "$ssh_dir/.authorized-keys.XXXXXX")
trap '"'"'rm -f -- "${temporary:-}"'"'"' EXIT
printf "%s\n" "$1" >"$temporary"
chmod 0600 "$temporary"
mv -fT -- "$temporary" "$ssh_dir/authorized_keys"
' bash "$public_key"
printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$CANDIDATE_USER" >"$sudoers"
cat >"$sshd_config" <<'EOF'
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

install -d -m 0755 -o root -g root /etc/sudoers.d /etc/ssh/sshd_config.d
install -m 0440 -o root -g root -- "$sudoers" /etc/sudoers.d/cks-candidate.new
visudo -cf /etc/sudoers.d/cks-candidate.new >/dev/null
mv -fT -- /etc/sudoers.d/cks-candidate.new /etc/sudoers.d/cks-candidate

install_if_changed "$sshd_config" /etc/ssh/sshd_config.d/60-cks-candidate.conf 0644 || true
sshd -t
# Reload unconditionally after on-disk key/config verification. If a prior run
# was interrupted after replacing a key but before reload, the next replay must
# repair sshd's in-memory state even though the files are already converged.
systemctl reload ssh
systemctl is-active --quiet ssh || die "SSH service is not active after candidate access convergence"

assert_candidate_password_locked
runuser -u "$CANDIDATE_USER" -- sudo -n true </dev/null >/dev/null
printf 'candidate node account configured\n'
