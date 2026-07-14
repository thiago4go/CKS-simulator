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
readonly inventory=${CKS_INVENTORY_PATH:-${SCRIPT_DIR}/../../inventory.json}
assert_candidate_has_no_sudo
for command in kubectl trivy yq jq curl wget openssl ssh ssh-keygen vim less timeout; do
  require_command "$command"
done
[[ -f "$home/.cache/trivy/db/trivy.db" && ! -L "$home/.cache/trivy/db/trivy.db" ]] || die "Trivy vulnerability DB is missing"

assert_regular_mode "$home/.ssh/$LEARNER_KEY_NAME" 600
assert_regular_mode "$home/.ssh/${LEARNER_KEY_NAME}.pub" 644
assert_regular_mode "$home/.ssh/config" 600
assert_regular_mode "$home/.ssh/known_hosts" 600
derived=$(ssh-keygen -y -f "$home/.ssh/$LEARNER_KEY_NAME" | awk '{print $1 " " $2}')
[[ $(<"$home/.ssh/${LEARNER_KEY_NAME}.pub") == "$derived candidate@cks-simulator" ]] || die "learner SSH keypair mismatch"
ssh-keygen -l -f "$home/.ssh/known_hosts" >/dev/null

python3 - "$inventory" "$home/.ssh/known_hosts" <<'PY'
import json
import sys

inventory_path, known_hosts_path = sys.argv[1:]
with open(inventory_path, "r", encoding="utf-8") as stream:
    expected = set(json.load(stream)["aliases"])
with open(known_hosts_path, "r", encoding="utf-8") as stream:
    lines = [line.rstrip("\n") for line in stream]
observed = {line.split(" ", 1)[0] for line in lines}
if observed != expected or len(lines) != len(expected):
    raise SystemExit("known_hosts does not contain exactly the managed aliases")
PY

for alias in cks3477 cks8930 cks5608 cks2546 cks7262 cks4024; do
  effective=$(ssh -G "$alias" 2>/dev/null)
  for requirement in \
    'stricthostkeychecking true:StrictHostKeyChecking' \
    'identitiesonly yes:IdentitiesOnly' \
    "hostkeyalias ${alias}:HostKeyAlias" \
    'updatehostkeys false:UpdateHostKeys' \
    'passwordauthentication no:PasswordAuthentication' \
    'kbdinteractiveauthentication no:KbdInteractiveAuthentication' \
    'pubkeyauthentication true:PubkeyAuthentication' \
    'forwardagent no:ForwardAgent' \
    'forwardx11 no:ForwardX11' \
    'clearallforwardings yes:ClearAllForwardings'; do
    setting=${requirement%%:*}
    label=${requirement#*:}
    grep -Fxq "$setting" <<<"$effective" || die "SSH ${label} mismatch for ${alias}"
  done
  timeout 20 ssh -o BatchMode=yes -o ConnectTimeout=10 "$alias" -- sudo -n true </dev/null
done

for path_mode in \
  "$home/.kube/config:600" \
  "$home/.kube/candidate.key:600" \
  "$home/.kube/candidate.crt:644" \
  "$home/.kube/ca.crt:644"; do
  assert_regular_mode "${path_mode%:*}" "${path_mode##*:}"
done
cluster=$(kubectl config --kubeconfig="$home/.kube/config" view --minify -o jsonpath='{.contexts[0].context.cluster}')
user=$(kubectl config --kubeconfig="$home/.kube/config" view --minify -o jsonpath='{.contexts[0].context.user}')
client_key=$(kubectl config --kubeconfig="$home/.kube/config" view --minify -o jsonpath='{.users[0].user.client-key}')
client_cert=$(kubectl config --kubeconfig="$home/.kube/config" view --minify -o jsonpath='{.users[0].user.client-certificate}')
ca=$(kubectl config --kubeconfig="$home/.kube/config" view --minify -o jsonpath='{.clusters[0].cluster.certificate-authority}')
[[ "$cluster" == cks-simulator && "$user" == candidate ]] || die "candidate kubeconfig identity is wrong"
[[ "$client_key" == "$home/.kube/candidate.key" && "$client_cert" == "$home/.kube/candidate.crt" && "$ca" == "$home/.kube/ca.crt" ]] || die "candidate kubeconfig credential paths are wrong"
openssl verify -CAfile "$home/.kube/ca.crt" "$home/.kube/candidate.crt" >/dev/null
key_digest=$(openssl pkey -in "$home/.kube/candidate.key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
cert_digest=$(openssl x509 -in "$home/.kube/candidate.crt" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[[ "$key_digest" == "$cert_digest" ]] || die "candidate Kubernetes keypair mismatch"

kubectl version --request-timeout=10s >/dev/null
kubectl version --client --output=json | python3 -c 'import json,sys; assert json.load(sys.stdin)["clientVersion"]["gitVersion"] == "v1.35.6"'
trivy --version | grep -Fqx 'Version: 0.72.0'
yq --version | grep -Fq 'version v4.53.2'
jq --version >/dev/null
curl --version >/dev/null
wget --version >/dev/null
openssl version >/dev/null
ssh -V 2>&1 | grep -Fq OpenSSH
vim --version >/dev/null
less --version >/dev/null
[[ -r /usr/share/bash-completion/bash_completion ]] || die "bash completion is missing"
printf 'candidate doctor passed\n'
