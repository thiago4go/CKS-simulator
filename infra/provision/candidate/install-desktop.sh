#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

readonly VNC_PORT=5901
readonly NOVNC_PORT=6080
readonly VNC_UNIT=/etc/systemd/system/cks-candidate-vnc.service
readonly NOVNC_UNIT=/etc/systemd/system/cks-candidate-novnc.service
readonly NOVNC_PACKAGE=/usr/share/novnc/package.json
readonly VNC_DIR=/home/candidate/.vnc
readonly VNC_XSTARTUP=/home/candidate/.vnc/xstartup
readonly OPENBOX_CONFIG=/home/candidate/.config/openbox
readonly OPENBOX_MENU=/home/candidate/.config/openbox/menu.xml
readonly OPENBOX_AUTOSTART=/home/candidate/.config/openbox/autostart

require_root
for command in apt-get awk cat chmod chown cmp env getent id install mktemp mv passwd rm runuser sleep sort ss stat systemctl timeout; do
  require_command "$command"
done

fail_closed() {
  systemctl stop cks-candidate-novnc.service >/dev/null 2>&1 || true
  systemctl stop cks-candidate-vnc.service >/dev/null 2>&1 || true
}

temporary=
cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "${temporary:-}"
  if (( status != 0 )); then
    fail_closed
  fi
  exit "$status"
}
trap cleanup EXIT

[[ $(command -v apt-get) == /usr/bin/apt-get ]] || die "apt-get must resolve to /usr/bin/apt-get"
[[ -r /etc/os-release ]] || die "Ubuntu release metadata is unavailable"
os_id=$(/bin/bash -c 'source /etc/os-release; printf "%s" "${ID:-}"')
[[ "$os_id" == ubuntu ]] || die "candidate desktop provisioning requires Ubuntu"

account=$(getent passwd "$CANDIDATE_USER") || die "candidate account is missing"
IFS=: read -r name _ uid gid _ home shell <<<"$account"
[[ "$name" == "$CANDIDATE_USER" && "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 ]] || die "unsafe candidate account"
[[ "$gid" =~ ^[0-9]+$ ]] || die "unsafe candidate primary group"
[[ "$home" == "$CANDIDATE_HOME" && "$shell" == /bin/bash ]] || die "candidate account has unexpected home or shell"
group_record=$(getent group "$gid") || die "candidate primary group is missing"
IFS=: read -r group_name _ group_gid _ <<<"$group_record"
[[ "$group_name" == "$CANDIDATE_USER" ]] || die "candidate primary group has an unexpected name"
[[ "$group_gid" == "$gid" ]] || die "candidate primary group has an unexpected gid"
[[ -d "$CANDIDATE_HOME" && ! -L "$CANDIDATE_HOME" ]] || die "candidate home path is unsafe"
[[ $(stat -c '%u:%g' -- "$CANDIDATE_HOME") == "${uid}:${gid}" ]] || die "candidate home ownership is unsafe"
assert_candidate_password_locked
assert_candidate_has_no_sudo

if systemctl is-active --quiet display-manager.service \
  || systemctl is-enabled --quiet display-manager.service; then
  die "display manager must not be active or enabled"
fi

export DEBIAN_FRONTEND=noninteractive
timeout 600 apt-get update
timeout 600 apt-get install --yes --no-install-recommends \
  tigervnc-standalone-server \
  novnc \
  websockify \
  openbox \
  xterm \
  dbus-x11 \
  xauth \
  fonts-dejavu-core \
  netsurf-gtk

for binary in \
  /usr/bin/dbus-run-session \
  /usr/bin/netsurf-gtk \
  /usr/bin/openbox-session \
  /usr/bin/tigervncserver \
  /usr/bin/vim.basic \
  /usr/bin/websockify \
  /usr/bin/xauth \
  /usr/bin/xterm; do
  [[ -x "$binary" && ! -L "$binary" ]] || die "required desktop binary is missing or unsafe: ${binary}"
done
[[ -d /usr/share/novnc && ! -L /usr/share/novnc ]] || die "noVNC web root is missing or unsafe"
[[ -f /usr/share/novnc/vnc.html && ! -L /usr/share/novnc/vnc.html ]] || die "noVNC client is missing or unsafe"
[[ -f /usr/share/novnc/vnc_lite.html && ! -L /usr/share/novnc/vnc_lite.html ]] || die "noVNC lite client is missing or unsafe"
[[ -d /etc/systemd/system && ! -L /etc/systemd/system ]] || die "systemd unit path is unsafe"

ensure_candidate_directory() {
  local path=$1 mode=$2
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || die "candidate path is unsafe: ${path}"
  else
    runuser -u "$CANDIDATE_USER" -- install -d -m "$mode" -- "$path"
  fi
  [[ $(stat -c '%u:%g' -- "$path") == "${uid}:${gid}" ]] || die "candidate path ownership is unsafe: ${path}"
  runuser -u "$CANDIDATE_USER" -- chmod "$mode" -- "$path"
}

ensure_candidate_directory "$VNC_DIR" 0700
ensure_candidate_directory "$CANDIDATE_HOME/.config" 0700
ensure_candidate_directory "$OPENBOX_CONFIG" 0700

temporary=$(mktemp -d)
chmod 0755 "$temporary"

cat >"$temporary/xstartup" <<'EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec dbus-run-session -- openbox-session
EOF

cat >"$temporary/openbox-menu.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_menu xmlns="http://openbox.org/3.4/menu">
  <menu id="root-menu" label="CKS Candidate">
    <item label="Terminal">
      <action name="Execute"><command>/usr/bin/xterm</command></action>
    </item>
    <item label="Vim">
      <action name="Execute"><command>/usr/bin/xterm -title Vim -e /usr/bin/vim.basic</command></action>
    </item>
    <item label="NetSurf">
      <action name="Execute"><command>/usr/bin/netsurf-gtk</command></action>
    </item>
  </menu>
</openbox_menu>
EOF

cat >"$temporary/openbox-autostart" <<'EOF'
#!/bin/sh
/usr/bin/xterm -title 'CKS Candidate Terminal' &
EOF

cat >"$temporary/novnc-package.json" <<'EOF'
{"name":"@novnc/novnc","version":"1.3.0"}
EOF

cat >"$temporary/cks-candidate-vnc.service" <<'EOF'
[Unit]
Description=CKS candidate TigerVNC desktop
After=network.target
Wants=network.target

[Service]
Type=simple
User=candidate
Group=candidate
Environment=HOME=/home/candidate
Environment=USER=candidate
Environment=LOGNAME=candidate
WorkingDirectory=/home/candidate
UMask=0077
ExecStartPre=/usr/bin/test -x /home/candidate/.vnc/xstartup
ExecStart=/usr/bin/tigervncserver :1 -fg -geometry 1280x800 -depth 24 -rfbport 5901 -localhost yes -interface 127.0.0.1 -SecurityTypes None -AcceptCutText=0 -SendCutText=0 -xstartup /home/candidate/.vnc/xstartup
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/candidate
RestrictAddressFamilies=AF_UNIX AF_INET
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

cat >"$temporary/cks-candidate-novnc.service" <<'EOF'
[Unit]
Description=CKS candidate loopback-only noVNC bridge
Requires=cks-candidate-vnc.service
After=cks-candidate-vnc.service
PartOf=cks-candidate-vnc.service

[Service]
Type=simple
User=candidate
Group=candidate
Environment=HOME=/home/candidate
WorkingDirectory=/
UMask=0077
ExecStart=/usr/bin/websockify --web=/usr/share/novnc 127.0.0.1:6080 127.0.0.1:5901
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX AF_INET
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$temporary"/*
chmod 0755 "$temporary/xstartup" "$temporary/openbox-autostart"

file_changed=0

install_candidate_file() {
  local source=$1 destination=$2 mode=$3 status
  if runuser -u "$CANDIDATE_USER" -- env \
    HOME="$CANDIDATE_HOME" USER="$CANDIDATE_USER" LOGNAME="$CANDIDATE_USER" \
    /bin/bash -c '
      set -Eeuo pipefail
      source=$1
      destination=$2
      mode=$3
      [[ -f "$source" && ! -L "$source" ]]
      if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] || exit 20
      fi
      if [[ -f "$destination" ]] && cmp -s -- "$source" "$destination"; then
        chmod "$mode" -- "$destination"
        exit 0
      fi
      rm -f -- "${destination}.new"
      install -m "$mode" -- "$source" "${destination}.new"
      mv -fT -- "${destination}.new" "$destination"
      exit 10
    ' candidate-desktop-install "$source" "$destination" "$mode"; then
    return 0
  else
    status=$?
  fi
  (( status == 10 )) || die "candidate destination path is unsafe: ${destination}"
  file_changed=1
}

install_root_file() {
  local source=$1 destination=$2 mode=$3
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] || die "destination path is unsafe: ${destination}"
  fi
  if [[ -f "$destination" ]] && cmp -s -- "$source" "$destination"; then
    chown root:root "$destination"
    chmod "$mode" "$destination"
    return
  fi
  [[ ! -e "${destination}.new" && ! -L "${destination}.new" ]] || die "temporary destination path is unsafe: ${destination}.new"
  install -m "$mode" -o root -g root -- "$source" "${destination}.new"
  mv -fT -- "${destination}.new" "$destination"
  file_changed=1
}

install_owned_file() {
  local source=$1 destination=$2 owner=$3 group=$4 mode=$5
  case "${owner}:${group}" in
    candidate:candidate) install_candidate_file "$source" "$destination" "$mode" ;;
    root:root) install_root_file "$source" "$destination" "$mode" ;;
    *) die "unsupported desktop file ownership: ${owner}:${group}" ;;
  esac
  local expected_uid expected_gid
  expected_uid=$(id -u "$owner")
  expected_gid=$(id -g "$group")
  [[ -f "$destination" && ! -L "$destination" ]] || die "desktop file is missing or unsafe: ${destination}"
  [[ $(stat -c '%u:%g:%a' -- "$destination") == "${expected_uid}:${expected_gid}:${mode#0}" ]] \
    || die "desktop file contract is invalid: ${destination}"
}

install_owned_file "$temporary/xstartup" "$VNC_XSTARTUP" "$CANDIDATE_USER" "$CANDIDATE_USER" 0755
install_owned_file "$temporary/openbox-menu.xml" "$OPENBOX_MENU" "$CANDIDATE_USER" "$CANDIDATE_USER" 0644
install_owned_file "$temporary/openbox-autostart" "$OPENBOX_AUTOSTART" "$CANDIDATE_USER" "$CANDIDATE_USER" 0755
install_owned_file "$temporary/cks-candidate-vnc.service" "$VNC_UNIT" root root 0644
install_owned_file "$temporary/cks-candidate-novnc.service" "$NOVNC_UNIT" root root 0644
install_owned_file "$temporary/novnc-package.json" "$NOVNC_PACKAGE" root root 0644

systemctl daemon-reload
systemctl enable cks-candidate-vnc.service cks-candidate-novnc.service >/dev/null
if (( file_changed == 1 )) \
  || ! systemctl is-active --quiet cks-candidate-vnc.service \
  || ! systemctl is-active --quiet cks-candidate-novnc.service; then
  systemctl restart cks-candidate-vnc.service
  systemctl restart cks-candidate-novnc.service
fi

wait_for_exact_listener() {
  local port=$1 listeners attempt
  local expected="127.0.0.1:${port}"
  for (( attempt = 0; attempt < 40; attempt++ )); do
    listeners=$(ss -H -ltn "sport = :${port}" | awk '{print $4}' | sort -u)
    if [[ "$listeners" == "$expected" ]]; then
      return 0
    fi
    [[ -z "$listeners" ]] || die "unexpected listener for TCP ${port}: ${listeners}"
    sleep 0.25
  done
  die "loopback listener did not start on TCP ${port}"
}

wait_for_exact_listener "$VNC_PORT"
wait_for_exact_listener "$NOVNC_PORT"
systemctl is-active --quiet cks-candidate-vnc.service
systemctl is-active --quiet cks-candidate-novnc.service
systemctl is-enabled --quiet cks-candidate-vnc.service
systemctl is-enabled --quiet cks-candidate-novnc.service
if systemctl is-active --quiet display-manager.service \
  || systemctl is-enabled --quiet display-manager.service; then
  die "display manager must not be active or enabled"
fi

printf 'candidate desktop installed on loopback-only noVNC port %s\n' "$NOVNC_PORT"
