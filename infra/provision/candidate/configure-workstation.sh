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
for command in useradd usermod passwd runuser ssh-keygen install getent; do
  require_command "$command"
done

if ! getent passwd "$CANDIDATE_USER" >/dev/null; then
  useradd --create-home --home-dir "$CANDIDATE_HOME" --shell /bin/bash \
    --comment 'CKS learner' "$CANDIDATE_USER"
fi

account=$(getent passwd "$CANDIDATE_USER")
IFS=: read -r name _ uid _ _ home shell <<<"$account"
[[ "$name" == "$CANDIDATE_USER" && "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 ]] || die "unsafe candidate account"
[[ "$home" == "$CANDIDATE_HOME" && "$shell" == /bin/bash ]] || die "candidate account has unexpected home or shell"
passwd --lock "$CANDIDATE_USER" >/dev/null

for group in sudo admin wheel; do
  if getent group "$group" >/dev/null && id -nG "$CANDIDATE_USER" | tr ' ' '\n' | grep -Fxq "$group"; then
    gpasswd --delete "$CANDIDATE_USER" "$group" >/dev/null
  fi
done
rm -f -- /etc/sudoers.d/candidate /etc/sudoers.d/cks-candidate

# Everything below the candidate-owned home runs with candidate privileges.
# A hostile ~/.ssh symlink can therefore only cause a fail-closed permission
# error; this root reconciler never follows it while mutating a target.
runuser -u "$CANDIDATE_USER" -- env \
  HOME="$CANDIDATE_HOME" USER="$CANDIDATE_USER" LOGNAME="$CANDIDATE_USER" \
  "${SCRIPT_DIR}/configure-home.sh"

assert_candidate_password_locked
assert_candidate_has_no_sudo
printf 'candidate workstation account configured\n'
