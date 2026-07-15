# Full VM release validation

Date: 2026-07-15 (Australia/Melbourne)

## Decision

**PASS.** The Apple Silicon full tier is accepted as a proper local CKS
practice environment for the frozen 17-scenario catalog. It is provisioned as
IaC; installation of Kubernetes and security tooling is outside the learner
tasks.

Authoritative machine receipt:
[`docs/receipts/full-release-2026-07-15.json`](receipts/full-release-2026-07-15.json)

Receipt run ID: `863d4812-5a3a-48e8-a8d2-bcbbae4c5178`.

## Validated platform

- Host: Apple Silicon macOS, 18 logical CPUs, 48 GiB RAM.
- Provider: Lima 2.1.4 using `vz` and `user-v2` networking.
- Guests: Ubuntu 24.04 ARM64 release 20260615.
- Kubernetes: 1.35.6, one control plane and two workers.
- Runtime/network: containerd.io 2.2.6, Cilium 1.19.5.
- Security stack: gVisor release-20260706.0 (`systrap`), Falco 0.44.1
  modern eBPF, ingress-nginx 1.15.1, Docker 29.6.1, Trivy 0.72.0 and
  kube-bench 0.15.6 (training-only).
- Allocation: four VMs, 12 vCPUs, 24 GiB RAM and 160 GiB sparse disk maximum.

All downloaded images, charts and binaries were checked against the digests in
`infra/versions.json`.

## Authoritative full gate

Command:

```sh
./bin/cks-simulator e2e \
  --tier full \
  --destroy-rebuild \
  --name release-20260715-r2 \
  --json
```

Overall duration: **2997.4 seconds (49m57s)**.

| Build | Lab UUID | IaC | Idempotent | Scenarios | Recovery | Cleanup | Duration |
|---|---|---:|---:|---:|---:|---:|---:|
| A | `72db0ef8-4b33-4132-b869-9a7093af1d3e` | pass | pass | 17/17 | pass | ordinary, exact, no residual paths | 2245.2s |
| B | `455ad376-b7cb-4e53-9338-9cec4c8c5a4f` | pass | pass | baseline build | n/a | ordinary, exact, no residual paths | 752.2s |

Build B began only after all Build A handles were absent. The UUIDs, guest
addresses and provider handles differ, proving a new IaC build rather than reuse.
Neither cleanup needed break-glass.

## Scenario matrix

Every row passed untouched `FAIL 0`, reference `PASS 100`, identical repeated
grade and restore to health-attested `validated`.

| ID | Security area | Result |
|---:|---|---:|
| 01 | kubeconfig contexts and certificates | PASS |
| 02 | image vulnerability scanning | PASS |
| 03 | Kubernetes API exposure | PASS |
| 04 | service-account token hardening | PASS |
| 05 | CIS-oriented node changes | PASS |
| 06 | immutable root filesystem | PASS |
| 07 | Pod Security Admission | PASS |
| 08 | Docker bridge isolation | PASS |
| 09 | AppArmor enforcement | PASS |
| 10 | gVisor RuntimeClass | PASS |
| 11 | Secret migration and consumers | PASS |
| 12 | ImagePolicyWebhook | PASS |
| 13 | metadata egress isolation | PASS |
| 14 | AES-GCM encryption at rest | PASS |
| 15 | ingress TLS and routing | PASS |
| 16 | Falco custom syscall rules | PASS |
| 17 | API-server audit policy | PASS |

The recovery rehearsal prepared scenario 12, selected
`operator-transport` with API availability declared false, executed the exact
reviewed restore and returned to `validated`.

## Failed gate that improved the release

The first committed release attempt (`1082d856-785c-42a1-bc0b-18c08474d35b`)
failed closed at 16/17. Scenario 13 returned before live policy evidence had
converged; Build A was destroyed exactly and Build B was not started. Commit
`e304352` added a bounded wait for simultaneous metadata denial plus peer and
DNS allowance. The authoritative fresh run then passed scenario 13 and the
entire gate.

## Quick-tier regression

Command: `./bin/cks-simulator e2e --tier quick --name quick-release-20260715 --json`.

- Result: **15/15, score 100, PASS**.
- Duration: **53.3 seconds**.
- Live Kind fixtures: 04, 06, 07, 11 and 15.
- Cleanup: cluster deleted; no Kind clusters remained.

## Offline and cleanup evidence

- `python3 -m unittest discover -s tests -p 'test_*.py'`: **340 passed**.
- Python compile, Bash syntax, strict JSON parsing and `git diff --check`: pass.
- Structured security/correctness review: pass after hardening the receipt root
  against symlinks and non-owner-only directories.
- Final Lima inventory: zero instances.
- Final Kind inventory: zero clusters.
- Full state tombstones report both accepted builds `destroyed`; machine receipt
  cleanup entries contain no residual lab paths.

## Scope caveats

This is a high-fidelity local practice lab, not the official Linux Foundation
exam environment or an official score predictor. kube-bench output is
training-only for Kubernetes 1.35. The validated Cilium claim applies only to
the pinned 1.35.6/1.19.5 combination and its behavioral receipt.
