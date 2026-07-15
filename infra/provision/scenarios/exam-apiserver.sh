#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly IDENTITY=/etc/cks-simulator/identity.json
readonly APISERVER_MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml
readonly OPERATOR_CONFIG=/etc/kubernetes/admin.conf
readonly STATE_ROOT=/var/lib/cks-simulator/scenarios

fail() { printf 'exam apiserver composition failed\n' >&2; exit 1; }
trap fail ERR
[[ $# -eq 1 ]]
readonly ACTION=$1
case "$ACTION" in reference|restore-17) ;; *) fail ;; esac
[[ $EUID -eq 0 ]]
[[ $(jq -er '.role' "$IDENTITY") == control-plane ]]
for command in install jq kubectl mktemp mv sleep; do command -v "$command" >/dev/null; done

readonly baseline=${STATE_ROOT}/12/apiserver.original
for path in \
  "$baseline" \
  "${STATE_ROOT}/14/apiserver.original" \
  "${STATE_ROOT}/17/apiserver.original" \
  /opt/course/12/webhook/admission-config.yaml \
  /opt/course/12/webhook/webhook.yaml \
  /etc/kubernetes/etcd/ec.yaml; do
  [[ -f "$path" && ! -L "$path" ]]
done
if [[ "$ACTION" == reference ]]; then
  [[ -f /etc/kubernetes/audit/policy.yaml && ! -L /etc/kubernetes/audit/policy.yaml ]]
fi

temporary=$(mktemp "${STATE_ROOT}/17/.exam-apiserver.XXXXXX")
trap 'rm -f -- "${temporary:-}"' EXIT
kubectl patch --local --type=merge -f "$baseline" --patch='{}' -o json \
  | jq --arg action "$ACTION" '
    def ensure_image_policy:
      if any(startswith("--enable-admission-plugins=")) then
        map(if startswith("--enable-admission-plugins=") and (contains("ImagePolicyWebhook") | not)
            then . + ",ImagePolicyWebhook" else . end)
      else . + ["--enable-admission-plugins=ImagePolicyWebhook"] end;
    .spec.containers[0].command =
      ((.spec.containers[0].command
        | map(select((
            startswith("--admission-control-config-file=")
            or startswith("--encryption-provider-config=")
            or startswith("--audit-policy-file=")
            or startswith("--audit-log-path=")
            or startswith("--audit-log-maxbackup=")
            or startswith("--audit-log-maxage=")
            or startswith("--audit-log-maxsize=")
          ) | not))
        | ensure_image_policy)
       + [
          "--admission-control-config-file=/etc/kubernetes/webhook/admission-config.yaml",
          "--encryption-provider-config=/etc/kubernetes/etcd/ec.yaml"
        ]
       + (if $action == "reference" then [
          "--audit-policy-file=/etc/kubernetes/audit/policy.yaml",
          "--audit-log-path=/etc/kubernetes/audit/logs/audit.log",
          "--audit-log-maxbackup=1",
          "--audit-log-maxage=30",
          "--audit-log-maxsize=100"
        ] else [] end))
    | .spec.containers[0].volumeMounts =
      ((.spec.containers[0].volumeMounts
        | map(select(.name != "image-policy-webhook" and .name != "etcd-encryption" and .name != "audit")))
       + [
          {name:"image-policy-webhook",mountPath:"/etc/kubernetes/webhook",readOnly:true},
          {name:"etcd-encryption",mountPath:"/etc/kubernetes/etcd",readOnly:true}
        ]
       + (if $action == "reference" then [
          {name:"audit",mountPath:"/etc/kubernetes/audit",readOnly:false}
        ] else [] end))
    | .spec.volumes =
      ((.spec.volumes
        | map(select(.name != "image-policy-webhook" and .name != "etcd-encryption" and .name != "audit")))
       + [
          {name:"image-policy-webhook",hostPath:{path:"/opt/course/12/webhook",type:"Directory"}},
          {name:"etcd-encryption",hostPath:{path:"/etc/kubernetes/etcd",type:"Directory"}}
        ]
       + (if $action == "reference" then [
          {name:"audit",hostPath:{path:"/etc/kubernetes/audit",type:"Directory"}}
        ] else [] end))
  ' >"$temporary"

staged=$(mktemp /etc/kubernetes/.kube-apiserver-exam.XXXXXX)
kubectl patch --local --type=merge -f "$temporary" --patch='{}' -o yaml >"$staged"
chmod 0600 "$staged"
chown root:root "$staged"
if cmp -s -- "$staged" "$APISERVER_MANIFEST"; then
  rm -f -- "$staged"
else
  mv -fT -- "$staged" "$APISERVER_MANIFEST"
  sleep 8
  deadline=$((SECONDS + 180))
  until kubectl --kubeconfig="$OPERATOR_CONFIG" get --raw=/readyz >/dev/null 2>&1; do
    (( SECONDS < deadline ))
    sleep 2
  done
fi

manifest=$(kubectl patch --local --type=merge -f "$APISERVER_MANIFEST" --patch='{}' -o json)
jq -e --arg action "$ACTION" '
  ([.spec.containers[0].command[] | select(. == "--admission-control-config-file=/etc/kubernetes/webhook/admission-config.yaml")] | length == 1)
  and ([.spec.containers[0].command[] | select(. == "--encryption-provider-config=/etc/kubernetes/etcd/ec.yaml")] | length == 1)
  and (if $action == "reference"
       then ([.spec.containers[0].command[] | select(. == "--audit-log-maxbackup=1")] | length == 1)
         and ([.spec.containers[0].volumeMounts[] | select(.name == "image-policy-webhook" or .name == "etcd-encryption" or .name == "audit")] | length == 3)
       else ([.spec.containers[0].command[] | select(startswith("--audit-"))] | length == 0)
         and ([.spec.containers[0].volumeMounts[] | select(.name == "audit")] | length == 0)
       end)
' <<<"$manifest" >/dev/null
printf 'combined exam apiserver %s installed\n' "$ACTION"
