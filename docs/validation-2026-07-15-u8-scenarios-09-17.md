# U8 validation: full-tier scenarios 09–17

Date: 2026-07-15 (Australia/Melbourne)

## Accepted implementation

- Root-owned, SHA-256-verified mutation and observation helpers with fixed
  per-scenario and per-role dispatch.
- Read-only, least-privilege grader transport; graders remain stateless pure
  evaluators over bounded canonical snapshots.
- Real AppArmor enforcement, gVisor runtime evidence, Secret consumers,
  ImagePolicyWebhook admission, Cilium metadata isolation, AES-GCM encryption
  at rest, ingress TLS, Falco syscall events and API-server audit events.
- Untouched observations receive no prerequisite credit. Positive live evidence
  is gated on the exact candidate configuration for that scenario.
- Static-pod scenarios preserve the original kube-apiserver manifest and wait
  for `/readyz` on both mutation and restore.

Falco 0.44.1 in this lab uses the syscall source without container metadata
fields. The two custom rules therefore grade real host-configuration access and
kill syscall events without relying on unavailable `container.*` output fields.

## Offline gates

- `python3 -m unittest discover -s tests -p 'test_*.py'`: **331 passed**.
- Python compile, Bash syntax, strict JSON parsing and `git diff --check`:
  passed.
- Structured security/correctness review: no write-capable observer operation,
  admin kubeconfig use, embedded private key, unbounded observation payload or
  broad grader mutation permission found.

## Live development evidence

Development lab:

- Name: `u8-live-b`
- Lab UUID: `7a1c5fd9-caec-4644-8e78-40f68ba0822f`
- Result: candidate-ready from zero provider state; full doctor replay passed
  11/11, including stopped-VM `/run/sshd` convergence.
- Cluster: exactly three Ready Kubernetes 1.35.6 nodes.

| Scenario | Untouched | Reference | Repeated grade | Restore |
|---|---:|---:|---|---|
| 09 AppArmor | FAIL 0 | PASS 100 | identical | validated |
| 10 gVisor | FAIL 0 | PASS 100 | identical | validated |
| 11 Secrets | FAIL 0 | PASS 100 | identical | validated |
| 12 Image policy | FAIL 0 | PASS 100 | identical | validated |
| 13 Metadata egress | FAIL 0 | PASS 100 | identical | validated |
| 14 Encryption at rest | FAIL 0 | PASS 100 | identical | validated |
| 15 Ingress TLS | FAIL 0 | PASS 100 | identical | validated |
| 16 Falco | FAIL 0 | PASS 100 | identical | validated |
| 17 Audit policy | FAIL 0 | PASS 100 | identical | validated |

Machine summary: `{"attempted":9,"passed":9,"status":"PASS"}`.

This is U8 development evidence, not the final release receipt: reviewed helper
and fixture fixes were re-synchronised into the disposable lab while the matrix
was being debugged. U9/U10 must destroy it and prove the committed bundle with
fresh, unmodified IaC builds.

## Defects found by the live matrix

- Scenario 13's metadata HTTP daemon inherited the transport descriptor and
  could hold a command open; the daemon now closes descriptor 3 explicitly.
- Scenario 14 restored the encryption provider before deleting the encrypted
  test Secret. Restore now deletes while decryption is still available, then
  returns the kube-apiserver to its original manifest.
- Scenario 15 could grade before ingress-nginx had reloaded the TLS Secret. The
  reference helper now waits for both HTTPS routes to answer.
- Falco rejected unavailable container metadata fields on one replacement Pod;
  the rules now use fields exposed by the installed syscall source.
- Baseline audit traffic could resemble solution evidence. Audit events now
  count only when the exact policy and retention configuration are present.

All interrupted attempts were restored through the reviewed lifecycle helper;
the final lab remained healthy and in the `validated` phase after scenario 17.
