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
require_command python3
require_command ssh-keygen
home=$(candidate_home)
readonly inventory=${CKS_INVENTORY_PATH:-${SCRIPT_DIR}/../../inventory.json}
[[ -f "$inventory" && ! -L "$inventory" ]] || die "inventory is missing or unsafe"
install -d -m 0700 -- "$home/.ssh"
temporary=$(mktemp -d "$home/.ssh/.access.XXXXXX")
trap 'rm -rf -- "${temporary:-}"' EXIT

python3 -c '
import sys
payload = sys.stdin.buffer.read(32769)
if len(payload) > 32768 or not payload.endswith(b"\n") or payload.count(b"\n") != 1:
    raise SystemExit("SSH access manifest must be one bounded newline-terminated JSON record")
if b"\r" in payload or b"\x00" in payload:
    raise SystemExit("SSH access manifest contains forbidden bytes")
sys.stdout.buffer.write(payload)
' >"$temporary/input.json"

python3 - "$inventory" "$home" "$temporary" "$temporary/input.json" <<'PY'
import base64
import ipaddress
import json
import re
import struct
import sys

inventory_path, home, output_dir, input_path = sys.argv[1:]
try:
    with open(input_path, "rb") as stream:
        value = json.load(stream)
    with open(inventory_path, "r", encoding="utf-8") as stream:
        inventory = json.load(stream)
except (json.JSONDecodeError, OSError) as error:
    raise SystemExit(f"invalid SSH access manifest: {error}")
if set(value) != {"schema", "aliases"} or value["schema"] != 1:
    raise SystemExit("unsupported SSH access manifest")
declared = inventory.get("aliases")
if not isinstance(declared, dict):
    raise SystemExit("SSH alias inventory is invalid")
managed = {}
for alias, declaration in declared.items():
    if not isinstance(alias, str) or not isinstance(declaration, dict):
        raise SystemExit("SSH alias inventory is invalid")
    scenario_roles = declaration.get("scenario_roles")
    if not isinstance(scenario_roles, dict) or not scenario_roles:
        raise SystemExit("SSH alias scenario inventory is invalid")
    managed[alias] = set(scenario_roles.values())
    for scenario_id, role in scenario_roles.items():
        if not isinstance(scenario_id, str) or not re.fullmatch(r"(?:0[1-9]|1[0-7])", scenario_id):
            raise SystemExit("SSH alias scenario ID is invalid")
        task_alias = f"{alias}-q{scenario_id}"
        if task_alias in managed:
            raise SystemExit("SSH task alias is duplicated")
        managed[task_alias] = {role}
if set(value["aliases"]) != set(managed):
    raise SystemExit("SSH access manifest must contain every managed base and task alias")

config = []
known_hosts = []
host_pattern = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
key_pattern = re.compile(r"ssh-ed25519 ([A-Za-z0-9+/]+={0,2})")
for alias in sorted(managed):
    entry = value["aliases"][alias]
    if not isinstance(entry, dict) or set(entry) != {"role", "host", "host_key"}:
        raise SystemExit("invalid SSH alias record")
    allowed_roles = managed[alias]
    if entry["role"] not in allowed_roles:
        raise SystemExit("SSH alias role is not declared by inventory")
    host = entry["host"]
    if not isinstance(host, str) or not host_pattern.fullmatch(host):
        raise SystemExit("invalid SSH alias host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified):
        raise SystemExit("unsafe SSH alias address")
    match = key_pattern.fullmatch(entry["host_key"])
    if match is None:
        raise SystemExit("only exact Ed25519 host keys are accepted")
    try:
        blob = base64.b64decode(match.group(1), validate=True)
    except ValueError:
        raise SystemExit("invalid SSH host key encoding")
    if len(blob) < 4:
        raise SystemExit("invalid SSH host key blob")
    size = struct.unpack(">I", blob[:4])[0]
    if blob[4:4 + size] != b"ssh-ed25519":
        raise SystemExit("SSH host key blob is not Ed25519")
    config.extend([
        f"Host {alias}",
        f"    HostName {host}",
        f"    HostKeyAlias {alias}",
        "    User candidate",
        f"    IdentityFile {home}/.ssh/cks-learner-ed25519",
        "    IdentitiesOnly yes",
        "    StrictHostKeyChecking yes",
        "    UpdateHostKeys no",
        f"    UserKnownHostsFile {home}/.ssh/known_hosts",
        "    PasswordAuthentication no",
        "    KbdInteractiveAuthentication no",
        "    PubkeyAuthentication yes",
        "    ForwardAgent no",
        "    ForwardX11 no",
        "    ForwardX11Trusted no",
        "    ClearAllForwardings yes",
        "",
    ])
    known_hosts.append(f"{alias} {entry['host_key']}")

with open(f"{output_dir}/config", "x", encoding="utf-8", newline="\n") as stream:
    stream.write("\n".join(config))
with open(f"{output_dir}/known_hosts", "x", encoding="utf-8", newline="\n") as stream:
    stream.write("\n".join(known_hosts) + "\n")
PY

chmod 0600 "$temporary/config" "$temporary/known_hosts"
ssh-keygen -l -f "$temporary/known_hosts" >/dev/null
install_if_changed "$temporary/config" "$home/.ssh/config" 0600 || true
install_if_changed "$temporary/known_hosts" "$home/.ssh/known_hosts" 0600 || true
printf 'candidate SSH access installed\n'
