# Compact VM sizing validation — 2026-07-15

## Decision

The full tier now uses 10 GiB of guest RAM instead of 24 GiB. The topology and
security boundaries are unchanged; only the memory allocation and host-memory
preflight were reduced.

| Guest | Previous | Compact |
|---|---:|---:|
| Candidate | 4 GiB | 2 GiB |
| Control plane | 8 GiB | 4 GiB |
| Worker 1 | 6 GiB | 2 GiB |
| Worker 2 | 6 GiB | 2 GiB |
| **Total** | **24 GiB** | **10 GiB** |

Kubernetes documents 2 GiB per node as a practical floor for its memory-limit
exercises. The control plane retains twice that floor because it also hosts
etcd, static Pods, Cilium's operator, CoreDNS and scenario-driven API-server
restarts. The candidate retains 2 GiB for Trivy and other course tools.

## Live evidence

- Lab: `compact-20260715`
- UUID: `9b2a3cd7-05da-471a-9c3a-4d53aa92c64e`
- Spec SHA-256: `8f29597c5e519924b4da5da2873fe71165b058ccdce7ee28decffe23412242ce`
- Bundle SHA-256: `ee32b027ad7104d21e63e06acf67f779270e3b7916e1fed259bedd06ddada13b`
- Host: Apple Silicon macOS, 18 logical CPUs, 48 GiB RAM, Lima 2.1.4
- Fresh provision: `candidate-ready` in 11 minutes 52 seconds
- Replay-safe provision: same UUID and identities returned to `validated` in
  approximately 1 minute 35 seconds
- Offline suite: 340/340 tests passed
- Host/template preflight: 11/11 checks passed

Fresh provisioning behaviorally verified the three-node kubeadm/Cilium
cluster, gVisor, Falco, ingress, Docker isolation and candidate toolchain. Five
memory-sensitive scenario lifecycles were then run against the same lab:

| Scenario | Result | Duration |
|---|---:|---:|
| 10 — gVisor | PASS 100, repeat-identical, restored | 30.6 s |
| 13 — Cilium metadata policy | PASS 100, repeat-identical, restored | 95.1 s |
| 14 — encryption at rest | PASS 100, repeat-identical, restored | 221.9 s |
| 16 — Falco | PASS 100, repeat-identical, restored | 133.5 s |
| 17 — API audit | PASS 100, repeat-identical, restored | 227.8 s |

After the final health-attested restore:

| Guest | Used | Available | Swap | Kernel OOM events |
|---|---:|---:|---:|---:|
| Candidate | 241 MiB | 1,717 MiB | 0 | 0 |
| Control plane | 1,284 MiB | 2,619 MiB | 0 | 0 |
| Worker 1 | 669 MiB | 1,288 MiB | 0 | 0 |
| Worker 2 | 627 MiB | 1,330 MiB | 0 | 0 |

All three Kubernetes nodes reported `MemoryPressure=False`. The expected
control-plane component restarts caused by scenarios 14 and 17 occurred, but
there were no OOM kills and the complete restore health gate passed.

## Trade-off and entropy decision

Encryption and audit restores take longer on the compact allocation because a
single Cilium operator must reconverge after API-server restarts. This is an
acceptable practice-lab trade-off; correctness and restore guarantees remain
unchanged. No profile framework or fifth configuration was added—the compact
allocation replaces the oversized default directly.

## Cleanup

Ordinary exact destroy succeeded, a second destroy was idempotent, and the
durable tombstone ended at sequence 18 with every exact provider handle proven
absent. `limactl list` returned zero instances, Kind returned zero clusters,
and the lab directory retained only its expected `state.json` tombstone.
