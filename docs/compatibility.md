# Full-tier compatibility contract

The full tier is an opt-in Ubuntu ARM64 VM lab. Package installation and
cluster bootstrap are infrastructure work; the learner starts from a working
candidate workstation and a working three-node kubeadm cluster.

## Supported host

- Apple Silicon macOS with Lima 2.1.4 and the Virtualization.framework (`vz`)
  driver.
- At least 80 GiB free disk.
- At least 16 logical CPUs and 16 GiB host RAM for `standard`.
- At least 8 logical CPUs and 12 GiB host RAM for `low`.
- Four guests on Lima's `user-v2` network with no host-directory mounts.

Run `./bin/cks-simulator setup --tier full` to install the pinned Lima release
project-locally and verify this contract. Hardware capacity checks are reported
but are not bypassed by setup.

The `low` guest allocation passed every scenario and an independent rebuild at
exactly eight total guest vCPUs. The validation host had 18 logical CPUs; an
actual eight-logical-CPU Mac should run the destructive E2E gate once to close
the remaining host-contention evidence gap.

The validated host has 18 logical CPUs, 48 GiB RAM, and approximately 429 GiB
free disk. Linux VM providers are a future portability target; they are not
part of this release gate.

## Guest allocation

| Guest | vCPU | `standard` memory | `low` memory | Sparse disk |
|---|---:|---:|---:|---:|
| Candidate | 2 | 2 GiB | 1 GiB | 30 GiB |
| Control plane | 4 | 4 GiB | 2 GiB | 50 GiB |
| Worker 1 | 3 | 2 GiB | 1 GiB | 40 GiB |
| Worker 2 | 3 | 2 GiB | 1 GiB | 40 GiB |

The guests therefore reserve 10 GiB under `standard` and exactly 5 GiB under
`low`. Both allocations were validated on the declared 48 GiB Apple Silicon
host. The 16 GiB and 12 GiB host values are preflight floors preserving host
headroom; those exact host sizes have not been physically release-tested, and
8 GiB hosts are not claimed as supported. Operators should close other
memory-heavy applications while running the full tier.

The default remains `standard`. The `low` validation completed all 17
repeatable scenario grades and restores on recovered Build A, then passed an
independent clean Build B, idempotent replay, full doctor, and exact cleanup.
Neither build used swap or logged an OOM kill. Build A encountered a transient
`systemd-logind` stall on a worker during the candidate SSH doctor. This makes
`low` a validated resource-constrained option with less operational margin,
not the recommended profile.

## Pinned capability set

| Component | Pin | Release claim |
|---|---|---|
| Lima | 2.1.4 | Host provider; exact version required |
| Ubuntu | 24.04 ARM64, release 20260615 | Image digest must match `infra/versions.json` |
| Kubernetes | 1.35.6 | kubeadm, kubelet and kubectl use the same package version |
| containerd.io | 2.2.6 | Kubernetes CRI with systemd cgroups |
| Cilium | 1.19.5 | Accepted only after connectivity and policy enforcement tests |
| gVisor | release-20260706.0 | ARM64 `systrap`; no nested KVM dependency |
| Falco | 0.44.1 / chart 9.1.0 | Modern eBPF driver must observe a real event |
| Trivy | 0.72.0 | Candidate scanner |
| kube-bench | 0.15.6 | Training evidence only; not authoritative CIS for Kubernetes 1.35 |
| Helm | 3.21.3 | Add-on installer |
| crictl | 1.35.0 | Runtime diagnostics |

## Capability acceptance

Installed binaries are not sufficient. A full-tier capability receipt must
prove all of the following on disposable infrastructure:

- exactly one control plane and two workers become Ready;
- Cilium passes connectivity checks and enforces both allow and deny traffic;
- DNS resolves and serves traffic across nodes;
- AppArmor allows the control case and denies the protected operation;
- a pod runs under gVisor `systrap`, with runtime evidence distinct from runc;
- Falco's modern eBPF driver observes a newly generated event;
- Docker on worker 2 runs a container without becoming Kubernetes' CRI and a
  Docker restart does not break Cilium forwarding;
- Trivy scans a pinned input and detects an expected result;
- kube-bench runs and is labelled training-only for this Kubernetes release;
- a generated TLS certificate terminates HTTPS through ingress;
- candidate and node network negative probes cannot reach host-control
  services or unrelated Lima guests.

Any failed capability blocks a full-tier release claim. The validator does not
silently downgrade Kubernetes, Cilium, or the evidence standard.

## Validated upstream caveats

Cilium's published compatibility material is not fully consistent for
Kubernetes 1.35. This release accepts the exact Kubernetes 1.35.6 / Cilium
1.19.5 pair only because two clean builds passed the behavioral networking,
policy and cleanup gates. It is not a blanket claim for other patch versions.

API-server restarts used by audit, admission and encryption scenarios can cause
the single Cilium operator to lose leader election and enter kubelet restart
backoff. Scenario restore waits for natural recovery and the complete Cilium
health gate; it does not manually restart or waive the operator.

kube-bench 0.15.6 has no Kubernetes 1.35 benchmark mapping. Its output is useful
practice material, but must never be described as authoritative compliance
evidence. Falco 0.44.1's syscall-only deployment does not expose container
metadata fields, so the validated custom rules use real syscall evidence
without claiming unavailable `container.*` enrichment.
