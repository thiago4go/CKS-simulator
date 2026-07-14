---
title: U4 VM Cluster Validation
date: 2026-07-14
status: passed
scope: four-VM Lima lifecycle through addons-ready
---

# U4 VM Cluster Validation

## Result

U4 passed on an Apple Silicon Mac with Lima 2.1.4 and native ARM64 VZ guests. The accepted run created a candidate VM plus one kubeadm control plane and two workers from an empty Lima inventory, reached `addons-ready`, recovered a deliberately partial Cilium release, recovered a stopped control plane, destroyed every exact owned instance, and proved a second destroy was a no-op.

This receipt covers the VM, Ubuntu, containerd, kubeadm, Cilium, state, replay, and ownership boundary only. Candidate credentials/tooling, scenarios, grading, and the two-build full release gate remain U5-U10 work.

## Accepted topology

| Role | vCPU | Memory | Accepted IP | Cluster member |
|---|---:|---:|---|---|
| candidate | 2 | 4 GiB | 192.168.104.103 | no |
| control-plane | 4 | 8 GiB | 192.168.104.104 | yes |
| worker1 | 3 | 6 GiB | 192.168.104.105 | yes |
| worker2 | 3 | 6 GiB | 192.168.104.106 | yes |

- Kubernetes: `v1.35.6`
- containerd: `2.2.6` with the systemd cgroup driver
- Ubuntu: `24.04.4 LTS`, ARM64, cgroup v2
- Cilium chart: `1.19.5`
- Cilium CLI: `v0.19.5`
- Bound provisioning-spec SHA-256: `d4cbd629817d77dbc34da5d3fd0d1519d726c05b3d0358da74fee9f3875472ea`
- Bound provisioning-bundle SHA-256: `4cffe35a08a496aa2f87c921c45e1777fac9ac7e4195db7f427f2fa2a346392c`

## Evidence

The final clean build recorded exactly:

```text
declared -> vms-created -> os-ready -> cluster-ready -> addons-ready
```

Independent live checks proved:

- exactly three Ready Kubernetes nodes with the recorded IPs;
- kubelet `v1.35.6` and `containerd://2.2.6` on all nodes;
- Cilium DaemonSet `3/3`, Envoy DaemonSet `3/3`, operator `1/1`, and CoreDNS `2/2`;
- pod CIDR `10.244.0.0/16` and service CIDR `10.96.0.0/12` in the live controller-manager command;
- one `05-cilium.conflist` on each node and no second effective CNI configuration;
- digest-qualified Cilium, Envoy, and operator images;
- zero secrets of type `bootstrap.kubernetes.io/token` after bootstrap and replay;
- four immutable VM observations with unique IP, MAC, product UUID, machine UUID, and matching provisioning-spec digest.

## Recovery and negative tests

The implementation was corrected against failures observed in clean builds, including shell readonly-variable collisions, Lima hostname differences, worker certificate identity verification, and an eager node-readiness check. The accepted implementation additionally passed these deliberate faults:

1. A transient Lima `Broken` status during worker2 creation recovered without duplicate resources or a false phase advance.
2. Deleting `daemonset/cilium-envoy` left an incomplete owned release. Replay used the verified local chart and Helm upgrade path, restored Envoy to `3/3`, and retained two valid Helm revision records.
3. Stopping the control-plane VM exercised immutable digest/fingerprint restart authorization. Replay waited for `/readyz` before API checks and returned to `addons-ready` without adding journal phases.
4. Repeated provision preserved the same inventory, observations, and five verified phases.
5. Exact destroy used fresh ownership evidence around stop and delete, reached `destroyed`, and left Lima empty. A second destroy returned `destroyed` with the same seven journal entries and performed no provider mutation.
6. Ordinary cleanup refuses marker or ownership loss. The weaker recovery path requires explicit break-glass authorization and the exact lab UUID.

## Offline and review gates

- `python3 -m unittest discover -s tests -q`: 204 tests passed.
- `CKS_KIND_USE_GLOBAL=0 ./bin/cks-simulator e2e --name cks-simulator-u4-regression`: 15/15 quick-tier live gates passed and the disposable Kind cluster was deleted.
- All provisioning shell scripts passed `bash -n`.
- All four Lima production templates passed `limactl validate`.
- The generated versions manifest matched `infra/versions.json`.
- Python bytecode compilation and `git diff --check` passed.
- A secret scan outside intentional test fixtures returned no findings.
- Independent correctness and security reviews returned no findings after remediation.

## Cleanup proof

The accepted lab UUID was `937ccf81-60bf-42cc-98ff-119a8fde15a9`. After exact destroy, `limactl list` reported no instance. Durable tombstone state remains local and contains no bootstrap token, kubeconfig, private key, or learner credential.
