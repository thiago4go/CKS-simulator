#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

readonly REQUIRED_FALCO_VERSION='0.44.1'
readonly REQUIRED_FALCO_CHART_VERSION='9.1.0'
readonly REQUIRED_INGRESS_NGINX_VERSION='1.15.1'
readonly REQUIRED_INGRESS_NGINX_CHART_VERSION='4.15.1'
readonly KUBECONFIG=${KUBECONFIG:-/etc/kubernetes/admin.conf}
readonly ADDON_TIMEOUT_SECONDS=${CKS_ADDON_TIMEOUT_SECONDS:-720}
export KUBECONFIG

require_root
load_tools_inputs
require_vars \
  FALCO_VERSION FALCO_CHART_VERSION FALCO_IMAGE FALCO_CHART_URL FALCO_CHART_SHA256 \
  FALCO_CHART_INSTALLED_SHA256 \
  INGRESS_NGINX_VERSION INGRESS_NGINX_CHART_VERSION INGRESS_NGINX_CHART_URL \
  INGRESS_NGINX_CHART_SHA256 INGRESS_NGINX_CHART_INSTALLED_SHA256
for command in curl sha256sum python3 helm kubectl; do
  require_command "$command"
done
[[ -f "$KUBECONFIG" && ! -L "$KUBECONFIG" ]] || { die "control-plane kubeconfig is missing or unsafe"; exit 1; }
validate_positive_timeout CKS_ADDON_TIMEOUT_SECONDS "$ADDON_TIMEOUT_SECONDS" 1800
[[ "$FALCO_VERSION" == "$REQUIRED_FALCO_VERSION" ]] || die "Falco must be ${REQUIRED_FALCO_VERSION}"
[[ "$FALCO_CHART_VERSION" == "$REQUIRED_FALCO_CHART_VERSION" ]] || die "Falco chart must be ${REQUIRED_FALCO_CHART_VERSION}"
[[ "$INGRESS_NGINX_VERSION" == "$REQUIRED_INGRESS_NGINX_VERSION" ]] || die "ingress-nginx must be ${REQUIRED_INGRESS_NGINX_VERSION}"
[[ "$INGRESS_NGINX_CHART_VERSION" == "$REQUIRED_INGRESS_NGINX_CHART_VERSION" ]] || die "ingress-nginx chart must be ${REQUIRED_INGRESS_NGINX_CHART_VERSION}"
assert_digest_pinned_image "$FALCO_IMAGE"

ensure_chart() {
  local name=$1 url=$2 digest=$3 installed_digest=$4 destination=$5 temporary
  if artifact_is_current "$installed_digest" "$destination"; then
    return 0
  fi
  mkdir -p -- "$(dirname -- "$destination")"
  temporary=$(mktemp "${destination}.XXXXXX")
  download_sha256 "$name" "$url" "$digest" "$temporary"
  install_text_if_changed "$temporary" "$destination" 0600
  rm -f -- "$temporary"
  artifact_is_current "$installed_digest" "$destination" || die "installed ${name} chart fingerprint mismatch"
}

assert_chart_versions() {
  local chart=$1 chart_version=$2 app_version=$3 metadata
  metadata=$(helm show chart "$chart") || { die "cannot inspect verified Helm chart"; return 1; }
  grep -Fxq "version: ${chart_version}" <<< "$metadata" || { die "Helm chart version mismatch"; return 1; }
  grep -Eq "^appVersion: ['\"]?${app_version}['\"]?$" <<< "$metadata" || { die "Helm chart appVersion mismatch"; return 1; }
}

readonly CHART_DIR="${CKS_TOOLS_STATE_DIR}/charts"
readonly FALCO_CHART="${CHART_DIR}/falco-${FALCO_CHART_VERSION}.tgz"
readonly INGRESS_CHART="${CHART_DIR}/ingress-nginx-${INGRESS_NGINX_CHART_VERSION}.tgz"
ensure_chart falco-chart "$FALCO_CHART_URL" "$FALCO_CHART_SHA256" "$FALCO_CHART_INSTALLED_SHA256" "$FALCO_CHART"
ensure_chart ingress-nginx-chart "$INGRESS_NGINX_CHART_URL" "$INGRESS_NGINX_CHART_SHA256" "$INGRESS_NGINX_CHART_INSTALLED_SHA256" "$INGRESS_CHART"
assert_chart_versions "$FALCO_CHART" "$FALCO_CHART_VERSION" "$FALCO_VERSION"
assert_chart_versions "$INGRESS_CHART" "$INGRESS_NGINX_CHART_VERSION" "$INGRESS_NGINX_VERSION"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

falco_registry=${FALCO_IMAGE%%/*}
falco_remainder=${FALCO_IMAGE#*/}
falco_repository=${falco_remainder%%:*}
falco_tag=${falco_remainder#*:}
cat > "${work}/falco-values.yaml" <<EOF
image:
  registry: "${falco_registry}"
  repository: "${falco_repository}"
  tag: "${falco_tag}"
driver:
  kind: modern_ebpf
  loader:
    enabled: false
collectors:
  enabled: false
falcoctl:
  artifact:
    install:
      enabled: false
    follow:
      enabled: false
falco:
  config_files: []
  rules_files:
    - /etc/falco/rules.d
customRules:
  cks-simulator-capability-smoke.yaml: |-
    - rule: CKS Simulator fresh capability event
      desc: Detect only uniquely named files created by the capability gate
      condition: evt.type in (open, openat, openat2) and fd.name startswith /tmp/cks-simulator-falco-smoke-
      output: "CKS_SIMULATOR_FALCO_SMOKE file=%fd.name proc=%proc.name"
      priority: WARNING
      source: syscall
      tags: [cks-simulator-capability-smoke]
EOF
helm template falco "$FALCO_CHART" --namespace falco --skip-tests \
  --values "${work}/falco-values.yaml" > "${work}/falco-rendered.yaml"
assert_rendered_images_pinned "${work}/falco-rendered.yaml" "$FALCO_IMAGE"
helm upgrade --install falco "$FALCO_CHART" \
  --namespace falco --create-namespace --values "${work}/falco-values.yaml" \
  --atomic --history-max 2 --wait --timeout "${ADDON_TIMEOUT_SECONDS}s"

cat > "${work}/ingress-values.yaml" <<'EOF'
controller:
  service:
    type: NodePort
  admissionWebhooks:
    enabled: false
EOF
helm template ingress-nginx "$INGRESS_CHART" --namespace ingress-nginx --skip-tests \
  --values "${work}/ingress-values.yaml" > "${work}/ingress-rendered.yaml"
assert_rendered_images_pinned "${work}/ingress-rendered.yaml"
helm upgrade --install ingress-nginx "$INGRESS_CHART" \
  --namespace ingress-nginx --create-namespace --values "${work}/ingress-values.yaml" \
  --atomic --history-max 2 --wait --timeout "${ADDON_TIMEOUT_SECONDS}s"

helm get manifest falco --namespace falco > "${work}/falco-installed.yaml"
assert_rendered_images_pinned "${work}/falco-installed.yaml" "$FALCO_IMAGE"
helm get manifest ingress-nginx --namespace ingress-nginx > "${work}/ingress-installed.yaml"
assert_rendered_images_pinned "${work}/ingress-installed.yaml"
kubectl rollout status daemonset/falco --namespace falco --timeout="${ADDON_TIMEOUT_SECONDS}s"
kubectl rollout status deployment/ingress-nginx-controller --namespace ingress-nginx --timeout="${ADDON_TIMEOUT_SECONDS}s"

log "Falco modern_ebpf ${FALCO_VERSION} and ingress-nginx ${INGRESS_NGINX_VERSION} converged from verified local charts"
