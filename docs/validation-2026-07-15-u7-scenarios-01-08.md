# U7 validation: full-tier scenarios 01–08

Date: 2026-07-15 (Australia/Melbourne)

## Accepted implementation

- Four-machine Lima lab: candidate, control-plane, worker1 and worker2.
- Kubernetes 1.35.6 with three kubeadm nodes and Cilium 1.19.5.
- Separate root-owned mutation and observation entrypoints with fixed dispatch.
- Atomic provider/guest ownership proof before every scenario command.
- Least-privilege `cks-grader` Kubernetes identity; observations do not use
  `admin.conf` and expose no write, exec, proxy, Secret or impersonation access.
- Immutable canonical grade snapshots evaluated by stateless, I/O-free graders.
- Fixed denominator, cross-source evidence for candidate-controlled artifacts,
  helper digest checks, bounded JSON and exact restore fingerprints.
- Docker 29.6.1 isolated from Kubernetes containerd with a pinned ARM64 nginx
  image and read-only effective bridge ICC observation.

Kubernetes 1.35 no longer has the historical
`--kubernetes-service-node-port` API-server flag. Scenario 03 therefore prepares
the built-in `default/kubernetes` Service itself as `NodePort:31000`; the learner
must return that API exposure to `ClusterIP` with no NodePort.

## Offline gates

- `python3 -m unittest discover -s tests -p 'test_*.py'`: **329 passed**.
- Python compile, Bash syntax, JSON parsing, generated-manifest freshness and
  `git diff --check`: passed.
- Fake live contract: untouched FAIL, reference PASS, identical repeated grade,
  exact restore and per-command verified guest identity.

## Live IaC evidence

Accepted lab:

- Name: `u7-live-d`
- Lab UUID: `db31fb89-c5e3-4988-85ec-4d99be63849b`
- Result: candidate-ready from zero provider state.
- Cluster: exactly three Ready Kubernetes 1.35.6 nodes.

Serial matrix, run from one unchanged bundle revision:

| Scenario | Untouched | Reference | Repeated grade | Restore |
|---|---:|---:|---|---|
| 01 Contexts | FAIL 0 | PASS 100 | identical | validated |
| 02 Image scanning | FAIL 0 | PASS 100 | identical | validated |
| 03 API exposure | FAIL 0 | PASS 100 | identical | validated |
| 04 SA token | FAIL 0 | PASS 100 | identical | validated |
| 05 CIS | FAIL 0 | PASS 100 | identical | validated |
| 06 Immutable root | FAIL 0 | PASS 100 | identical | validated |
| 07 PSA | FAIL 0 | PASS 100 | identical | validated |
| 08 Docker ICC | FAIL 0 | PASS 100 | identical | validated |

Machine receipt: `{"attempted":8,"passed":8,"status":"PASS"}`.

## Failure/recovery evidence

- `u7-live-a`: observer stdout contamination found in scenario 02; exact destroy.
- `u7-live-b`: idempotent temporary etcd-group cleanup bug found; exact destroy.
- `u7-live-c`: actual kubeadm restore baseline clarified; exact destroy.
- A later stopped-VM doctor replay exposed that Ubuntu's volatile `/run/sshd`
  directory was absent before `sshd -t`. Candidate-node convergence now recreates
  it on every run; the mandatory U9 clean destroy/rebuild gate covers this fix.
- Every retry used a new UUID-derived handle set and a fresh IaC build. No failed
  lab was patched in place or adopted by prefix.

## Determinism note

Scenario 02 uses the installed pinned Trivy binary and pinned database contract,
but grades the frozen four-image vulnerability oracle and learner output rather
than running Trivy during grade. This keeps grading read-only and prevents later
registry or vulnerability-database changes from altering an attempt.
