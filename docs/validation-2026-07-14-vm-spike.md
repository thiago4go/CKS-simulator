# VM capability spike validation — 2026-07-14

## Result

The disposable Apple Silicon/Lima capability spike passed. The accepted run
created a candidate VM plus one Kubernetes control plane and two workers,
validated the required ARM64 kernel/runtime capabilities, destroyed all four
instances, and left no Lima instance behind.

Command:

```sh
./scripts/validate-full-capabilities --json all --lab-id cks-spike-cap15
```

Accepted receipt: `.cks-state/full-spike/cks-spike-cap15/receipt.json` (generated,
not tracked). Claim UUID: `1c547a90-e73e-4964-8a43-d14c406c1d77`.

## Accepted evidence

- Base lab: four owned Ubuntu 24.04 ARM64 VMs; Kubernetes 1.35.6; exactly one
  Ready control plane and two Ready workers; Cilium 1.19.5 agents and Envoy
  fully rolled out and healthy.
- Security matrix: 11/11 probes passed — Kubernetes version, node readiness,
  Cilium version, deterministic connectivity, enforced allow/deny policy,
  AppArmor denial, gVisor `systrap`, Falco modern-eBPF event capture, Trivy
  configuration finding, training-only kube-bench execution, and ingress TLS.
- Runtime boundary: the digest-pinned Docker binary ran a digest-pinned
  BusyBox container through its isolated socket while Kubernetes continued to
  use system containerd.
- Post-Docker matrix: 2/2 probes passed — all nodes remained Ready and the
  deterministic Cilium connectivity suite passed again.
- Falco loaded only the locally supplied rule directory, opened the syscall
  source with the modern BPF probe, and observed a newly generated nonce-bound
  file-open event. No OCI plugin or driver-loader image was admitted.
- Provenance consistency: all 15 staged source inputs, including the four Lima
  VM templates, were SHA-256 identified; the receipt claim UUID matched the
  current local claim; the largest captured detail was 2,551 UTF-8 bytes,
  below the 4,096-byte bound.
- Cleanup: the receipt proves all four exact recorded handles returned zero for
  both stop and delete and no claimed handle remained. An independent post-run
  `limactl list` check also returned no global Lima instances.

## Failure-driven hardening chronology

The failed runs were retained as evidence rather than rewritten as success:

| Run | Outcome | Finding and resulting hardening |
|---|---|---|
| `cap1` | Broad matrix passed | Proved the capabilities, but predated bounded diagnostics and source provenance, so it is not the release receipt. |
| `cap2` | Failed | A transient worker readiness snapshot exposed a race; the validator now waits explicitly for every node. |
| `cap3` | Failed | The broad internet/FQDN Cilium matrix was externally variable and diagnostics hid the failing test; diagnostics were reprioritized and the release gate was narrowed to a non-zero local subset. |
| `cap4` | Failed | The first regex selected zero Cilium tests and Falco registered the container plugin twice; a non-zero action assertion and closed plugin policy were added. |
| `cap5` | Failed | Disabling collectors removed plugin configuration while a Kubernetes metadata output field still required it; the event became nonce-bound and syscall-only. |
| `cap6` | Failed | The pinned Falco image's `config.d` re-enabled the container plugin; image config fragments were explicitly excluded. |
| `cap7` | Failed | Bundled default rules still required the plugin; the probe was restricted to its reviewed local rule directory. |
| `cap8` | Passed, superseded | The full hardened matrix and exact cleanup passed, but review found that only two Cilium tests were selected despite a seven-test claim, failed starts could lose their pending handle, the Lima templates were absent from provenance, and the Cilium chart checksum was recorded but not consumed. |
| `cap9` | Failed closed | The first exact Cilium gate used top-level test names, while the CLI filters qualified `test/scenario` names; its non-zero-selection assertion rejected the run. |
| `cap10` | Passed, superseded | The checksum-verified local Cilium chart, exact connectivity gate, 15-input provenance, bounded receipt, and cleanup passed. Final review then found a predictable-name ownership race, interruption paths that could bypass cleanup, and imprecise local-evidence wording. |
| `cap11` | Intentionally interrupted | Exercised the repaired interruption path during bootstrap: the failed receipt recorded `KeyboardInterrupt`, all four exact UUID-bound handles were deleted, secrets were scrubbed, and Lima was empty. |
| `cap12` | Intentionally interrupted | Stopped an early build after review found standalone preflight could report a misleading collision result; cleanup deleted both the completed and pending exact handles and left Lima empty. |
| `cap13` | Failed closed | One Cilium Envoy pod was still converging when local service connectivity began. One action failed, the remaining baseline probes were not misreported, and exact cleanup passed. Explicit Cilium and Envoy rollout gates were added at both base and capability boundaries. |
| `cap14` | Passed, superseded | The complete matrix and cleanup passed. Final review then found that the new Cilium/Envoy rollout gate ran before baseline connectivity but was not repeated after Docker startup. |
| `cap15` | Accepted | Six base checks, readiness-gated Cilium connectivity both before and after Docker, the 11-probe baseline, the two-probe post-Docker matrix, UUID-derived provider ownership, 15 matching source hashes, bounded diagnostics, secret scrubbing, and exact four-handle cleanup all passed. |

## Scope and caveats

This is the U2 capability decision gate, not the finished simulator release.
It proves that the chosen four-VM architecture can support the required CKS
workloads on this host. Provider-neutral lifecycle, candidate isolation,
scenario prepare/grade/restore, and the two-build final release gate remain
separate implementation units.

Cilium's published support material does not yet make an unqualified
Kubernetes 1.35 compatibility claim for this pinned combination. The project
therefore records the upstream gap and accepts the combination only through
repeatable behavioral connectivity and policy tests. kube-bench 0.15.6 is
training evidence only because it has no authoritative Kubernetes 1.35
benchmark mapping.
