#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 027

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
readonly manifest=${CKS_CANDIDATE_TOOLS_MANIFEST:-${SCRIPT_DIR}/tools.env}

require_root
require_command timeout
[[ -f "$manifest" && ! -L "$manifest" ]] || die "candidate tool manifest is missing or unsafe"
# shellcheck disable=SC1090
source "$manifest"
: "${KUBECTL_VERSION:?}" "${KUBECTL_URL:?}" "${KUBECTL_SHA256:?}"
: "${TRIVY_VERSION:?}" "${TRIVY_URL:?}" "${TRIVY_SHA256:?}" "${TRIVY_DB_IMAGE:?}"
: "${YQ_VERSION:?}" "${YQ_URL:?}" "${YQ_SHA256:?}"
[[ "$KUBECTL_VERSION" == 1.35.6 && "$KUBECTL_URL" == "https://dl.k8s.io/release/v1.35.6/bin/linux/arm64/kubectl" ]] || die "unexpected kubectl pin"
[[ "$TRIVY_VERSION" == 0.72.0 && "$TRIVY_URL" == "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-ARM64.tar.gz" ]] || die "unexpected Trivy pin"
[[ "$TRIVY_DB_IMAGE" =~ ^[^[:space:]@]+:[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || die "Trivy DB must be digest pinned"
[[ "$YQ_VERSION" == 4.53.2 && "$YQ_URL" == "https://github.com/mikefarah/yq/releases/download/v4.53.2/yq_linux_arm64" ]] || die "unexpected yq pin"
for digest in "$KUBECTL_SHA256" "$TRIVY_SHA256" "$YQ_SHA256"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid candidate tool digest"
done

export DEBIAN_FRONTEND=noninteractive
timeout 600 apt-get update
timeout 600 apt-get install --yes --no-install-recommends \
  bash-completion ca-certificates curl gzip jq less openssh-client openssl tar vim wget

temporary=$(mktemp -d)
trap 'rm -rf -- "${temporary:-}" "${trivy_fixture:-}"' EXIT

download() {
  local url=$1 digest=$2 output=$3
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
    --retry 3 --connect-timeout 15 --max-time 300 --output "$output" "$url"
  printf '%s  %s\n' "$digest" "$output" | sha256sum --check --status
}

download "$KUBECTL_URL" "$KUBECTL_SHA256" "$temporary/kubectl"
install -m 0755 -o root -g root -- "$temporary/kubectl" /usr/local/bin/kubectl.new
mv -fT -- /usr/local/bin/kubectl.new /usr/local/bin/kubectl

download "$YQ_URL" "$YQ_SHA256" "$temporary/yq"
install -m 0755 -o root -g root -- "$temporary/yq" /usr/local/bin/yq.new
mv -fT -- /usr/local/bin/yq.new /usr/local/bin/yq

download "$TRIVY_URL" "$TRIVY_SHA256" "$temporary/trivy.tar.gz"
tar -xzf "$temporary/trivy.tar.gz" -C "$temporary" trivy
[[ -f "$temporary/trivy" && ! -L "$temporary/trivy" ]] || die "Trivy archive did not contain the expected binary"
install -m 0755 -o root -g root -- "$temporary/trivy" /usr/local/bin/trivy.new
mv -fT -- /usr/local/bin/trivy.new /usr/local/bin/trivy

readonly trivy_cache=/home/candidate/.cache/trivy
run_candidate() {
  runuser -u candidate -- env HOME=/home/candidate /bin/bash -c \
    'cd "$HOME"; exec "$@"' bash "$@"
}
[[ ! -L /home/candidate/.cache ]] || die "candidate cache path is unsafe"
run_candidate install -d -m 0755 /home/candidate/.cache "$trivy_cache"
run_candidate timeout 600 trivy image \
  --cache-dir "$trivy_cache" --db-repository "$TRIVY_DB_IMAGE" --download-db-only
[[ -f "$trivy_cache/db/trivy.db" && ! -L "$trivy_cache/db/trivy.db" ]] || die "Trivy vulnerability DB was not installed"
trivy_fixture="$temporary/cks-rootfs-smoke"
chmod 0755 "$temporary"
install -d -m 0755 -o root -g root \
  "$trivy_fixture/etc" "$trivy_fixture/usr/lib" "$trivy_fixture/var/lib/dpkg"
install -m 0644 -o root -g root /etc/os-release "$trivy_fixture/etc/os-release"
install -m 0644 -o root -g root /etc/lsb-release "$trivy_fixture/etc/lsb-release"
install -m 0644 -o root -g root /usr/lib/os-release "$trivy_fixture/usr/lib/os-release"
install -m 0644 -o root -g root /var/lib/dpkg/status "$trivy_fixture/var/lib/dpkg/status"
run_candidate timeout 600 trivy rootfs \
  --cache-dir "$trivy_cache" --skip-db-update --skip-java-db-update --scanners vuln \
  --format json "$trivy_fixture" >"$temporary/trivy-rootfs.json"
python3 - "$temporary/trivy-rootfs.json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as stream:
    value = json.load(stream)
os_value = value.get("Metadata", {}).get("OS", {})
if (
    value.get("SchemaVersion") != 2
    or os_value != {"Family": "ubuntu", "Name": "24.04"}
    or not isinstance(value.get("Results"), list)
    or not value["Results"]
):
    raise SystemExit("Trivy offline rootfs scan produced no structured evidence")
PY
rm -rf -- "$trivy_fixture"

kubectl version --client --output=json | python3 -c 'import json,sys; assert json.load(sys.stdin)["clientVersion"]["gitVersion"] == "v1.35.6"'
trivy --version | grep -Fqx 'Version: 0.72.0'
yq --version | grep -Fq 'version v4.53.2'
printf 'candidate tools installed\n'
