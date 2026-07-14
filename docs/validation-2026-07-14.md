# CKS Simulator Validation - 2026-07-14

## Verdict

The kind-based quick tier is release-ready.

- Release gate: **100.0/100 (A)** - 15/15 live gates passed.
- Offline regression suite: **21/21 passed**.
- Artifact grading coverage: **17/17 scenarios** expose deterministic partial-credit criteria.
- Live fixture coverage: **5/17 scenarios (29.4%)** - scenarios 04, 06, 07, 11, and 15.
- Full machine-level CKS fidelity: **incomplete by design on kind** - 10 scenarios require host/runtime capabilities that a stock kind cluster does not provide.

The release score grades the simulator software and its declared quick-tier contract. It is not an official CKS exam score and does not claim that unsupported host-level exercises ran on kind.

## Tested environment

- Host: macOS 26.5, arm64
- Container runtime: Docker Desktop
- kind: v0.29.0 project-local pinned fallback
- Kubernetes node image: `kindest/node:v1.35.1`
- Topology: one control plane and two workers

## Live E2E receipt

Command:

```sh
CKS_KIND_USE_GLOBAL=0 ./bin/cks-simulator e2e --name cks-simulator-e2e-final2
```

Passed gates:

1. Docker daemon available.
2. kubectl client available.
3. Pinned kind client available.
4. OpenSSL client available.
5. Every declared live fixture was present.
6. Scenario 15 generated a certificate and mode-`0600` private key.
7. Disposable owned cluster provisioned.
8. A second provision reused the healthy cluster safely.
9. Exactly three nodes reported Ready.
10. Scenario 04 fixture applied; all three objects observed and Deployment Available.
11. Scenario 06 fixture applied; both objects observed and Deployment Available.
12. Scenario 07 fixture passed server-side validation without scheduling its privileged Pod.
13. Scenario 11 fixture applied; all six objects observed and Deployment Available.
14. Scenario 15 baseline applied and generated TLS Secret termination was verified on the Ingress.
15. Cluster and isolated state were deleted.

Result: `e2e score: 100.0/100 (pass); 15/15 gates passed`.

## Defects found and corrected

- kind returned before both workers were Ready. Provisioning now waits for every node and reuse requires exactly three Ready nodes.
- E2E could reuse and then delete a pre-existing simulator-owned cluster. Existing cluster names or ownership markers are now refused and left untouched.
- Failed kind queries could be interpreted as confirmed cluster absence. E2E now uses a tri-state presence check and fails closed.
- Failed diagnostic exports could be reported as available. A path is published only after a successful export created it.
- Cleanup-only failures had no diagnostic attempt. Remaining owned clusters now trigger log export after failed cleanup.
- Scenario 07 automatically scheduled a privileged Pod. E2E now performs a server-side dry-run while the learner's explicit `scenario --apply` workflow remains available.
- Workload fixtures used a mutable image tag. E2E workload images are pinned to a multi-architecture digest.
- Scenario 15 stored an invalid TLS placeholder and partially seeded the solution. It now seeds the unsolved Ingress/Services and generates a private self-signed certificate/key in project state with mode `0600`.
- Concurrent E2E runs could claim the same name. Claims are now created atomically and bound to a unique run token.
- A missing allowlisted live fixture could silently reduce the E2E denominator. The release gate now verifies the complete declared fixture set before provisioning.
- A failed scenario 15 reset could delete existing learner artifacts before OpenSSL failed. TLS material is now generated before replacement begins, preserving prior work on failure.
- JSON mode could emit plain-text domain errors. Expected failures now retain a machine-readable error envelope.
- Grading was all-or-nothing and marker-only. It now reports criterion-level partial credit, normalized per scenario, with explicit artifact-only scope.

## Compatibility grade

| Support class | Scenarios | Quick-tier treatment |
|---|---:|---|
| Native | 4 | Live Kubernetes API fixture validation |
| Partial | 3 | Artifact grading for all; scenario 15 has a live baseline |
| Unsupported on stock kind | 10 | Artifact grading only; never counted as live-validated |

## Platform decision

Docker Compose with privileged Ubuntu containers is not the full-tier answer. Those containers still share one Docker host kernel, require risky nesting for Docker-in-Docker/systemd, and cannot faithfully isolate AppArmor, gVisor, Falco, kernel-event, or kubeadm node-filesystem work.

The recommended architecture is:

1. Keep this kind environment as the fast quick tier.
2. Add an optional three-node Ubuntu VM tier using Lima on macOS and kubeadm.
3. Run Cilium, AppArmor, gVisor, Falco, audit logging, encryption-at-rest, CIS/kubelet, Docker daemon, and static Pod exercises only in that VM tier.

The VM tier is required before the overall project can claim full CKS machine-level fidelity.
