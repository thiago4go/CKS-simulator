# Full-tier compatibility contract

The full tier is an opt-in Ubuntu ARM64 VM lab. Package installation and
cluster bootstrap are infrastructure work; the learner starts from a working
candidate workstation and a working three-node kubeadm cluster.

## Supported host

- Apple Silicon macOS with Lima 2.1.4 and the Virtualization.framework (`vz`)
  driver.
- At least 16 logical CPUs, 40 GiB RAM, and 200 GiB free disk.
- Four guests on Lima's `user-v2` network with no host-directory mounts.

The validated host has 18 logical CPUs, 48 GiB RAM, and approximately 429 GiB
free disk. Linux VM providers are a future portability target; they are not
part of this release gate.

## Guest allocation

| Guest | vCPU | Memory | Sparse disk |
|---|---:|---:|---:|
| Candidate | 2 | 4 GiB | 30 GiB |
| Control plane | 4 | 8 GiB | 50 GiB |
| Worker 1 | 3 | 6 GiB | 40 GiB |
| Worker 2 | 3 | 6 GiB | 40 GiB |

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

## Known upstream risk

Cilium's published compatibility material is not fully consistent for
Kubernetes 1.35. The simulator therefore treats the pinned combination as an
unverified hypothesis until its behavioral gate passes. kube-bench 0.15.6 has
no Kubernetes 1.35 benchmark mapping; its output is useful practice material,
but must never be described as authoritative compliance evidence.
