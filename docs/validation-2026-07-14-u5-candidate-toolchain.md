---
title: U5 Candidate and CKS Toolchain Validation
date: 2026-07-14
status: passed
scope: four-VM Lima lifecycle through candidate-ready
---

# U5 Candidate and CKS Toolchain Validation

## Result

U5 passed on Apple Silicon with Lima 2.1.4 and native ARM64 Ubuntu 24.04 guests. The accepted `u5-live-l` run built the four-VM lab from an empty Lima inventory, installed and behavior-tested the pinned CKS toolchain, configured the isolated learner workstation, reached `candidate-ready`, stopped all four VMs, reconciled the same immutable IaC, preserved every learner and node trust artifact, opened the real candidate shell, and destroyed every VM. A second destroy was an ownership-checked no-op.

This receipt covers the workstation, node access, pinned tools, security add-ons, trust flow, stopped-VM replay, full doctor, release-integrity gate, quick-tier regression, and cleanup boundary. Scenario mutation, full-tier grading, release E2E, and final operator documentation remain U6-U10 work.

## Accepted topology and provenance

| Role | vCPU | Memory | Disk | Accepted IP | Purpose |
|---|---:|---:|---:|---|---|
| candidate | 2 | 4 GiB | 30 GiB | 192.168.104.154 | learner workstation only |
| control-plane | 4 | 8 GiB | 50 GiB | 192.168.104.155 | kubeadm control plane and cluster tools |
| worker1 | 3 | 6 GiB | 40 GiB | 192.168.104.156 | AppArmor and gVisor exercises |
| worker2 | 3 | 6 GiB | 40 GiB | 192.168.104.157 | isolated Docker exercises |

- Accepted lab UUID: `648231d9-dbab-4cdb-b60f-4a6bb9e387e4`
- Provisioning-spec SHA-256: `038f78d500e261f172d254ffbbb9d8ba7973299faa246e607f013b17ba949b13`
- Provisioning-bundle SHA-256: `2f2c68998c249f6947382231107d796c6e93d52f6cf192394379af5598a95c70`
- Kubernetes `1.35.6`, Cilium/chart `0.19.5`/`1.19.5`, Helm `3.21.3`
- Trivy `0.72.0`, kube-bench `0.15.6`, etcdctl `3.6.6`, yq `4.53.2`
- Falco/chart `0.44.1`/`9.1.0`, ingress-nginx/chart `1.15.1`/`4.15.1`
- Docker `29.6.1` on worker2 and gVisor `release-20260706.0` with `systrap` on worker1

The four observations retained the same machine ID, MAC address, product UUID, IP address, provisioning-spec digest, and provisioning-bundle digest through stopped-VM replay.

## Trust and workstation evidence

Before destruction, the lifecycle journal remained exactly:

```text
declared -> vms-created -> os-ready -> cluster-ready -> addons-ready -> candidate-ready
```

Replay appended no duplicate phase. Destruction then appended only `cleanup-pending -> destroyed`.

The candidate account is password-locked, has no workstation sudo, and owns the learner SSH and Kubernetes private keys. Node-side candidate accounts are password-locked and have passwordless sudo for CKS exercises. The host transfers only the learner SSH public key, CSR, signed certificate, CA certificate, and public node host keys. It never receives or persists learner private keys or `admin.conf`.

Public continuity evidence was byte-identical before and after stopped-VM reconcile:

| Artifact | Accepted fingerprint or SHA-256 |
|---|---|
| learner SSH public key | `SHA256:YJNwTuaI0t25QfcHSBMnTk+mGNiv1XyacsliMkYxY0Y` |
| Kubernetes private-key public DER | `90bedc9d7f5d24d393825a9c2bda686743cfc9e4897832fd434230dfa97b1d39` |
| learner certificate | `C0:C9:56:DE:EB:85:D1:64:A2:B0:49:09:A8:5A:E9:B4:F1:68:96:15:FE:3B:C3:75:86:AF:78:A9:A2:5D:D9:A8` |
| candidate kubeconfig | `8696bba12d014b2cfe4d9dcdf981eddc7232013126b8e0e4484d1059cba5a576` |
| candidate SSH config | `d1ed6d63c72b3da6d477481b4c46fe8289bea48f02199497d853933feffab401` |
| candidate known_hosts | `798f7ab5cf7679422054ba3dafd9a1ea69934699942de115e0993c5e5fc1363e` |
| control-plane SSH host public key | `24be858842f57496ed5a49ee747e43746646dab39734c6600ee2ddbc5c5368f3` |
| worker1 SSH host public key | `e6547e356b821a6ec24b9c8c83c6ba3921cb59f011bd529da3c686ea4198cac6` |
| worker2 SSH host public key | `d1901accd558337a3024404a09527f33008069462aa2522268eb71596209715e` |

Each simulator-owned persistent node host public key was also byte-identical to the active OpenSSH public key. Strict SSH verification uses exact aliases, `HostKeyAlias`, `IdentitiesOnly`, `StrictHostKeyChecking`, a dedicated known-hosts file, and `UpdateHostKeys no`.

The real `shell --tier full` path opened as `candidate` on `lima-cks-648231d9dbab4cdb-candidate`. From that shell, `kubectl get nodes -o name` returned exactly the control plane and two workers.

## Behavioral capability gates

The accepted provision, doctor, replay, and shell path verified:

- exactly three Ready kubeadm nodes and healthy Cilium, Envoy, CoreDNS, and operator workloads;
- cross-node traffic before policy, default-deny behavior, and allowed traffic after NetworkPolicy;
- local and pod-level AppArmor allow/deny behavior on worker1;
- a pod running through the pinned gVisor `runsc` runtime on worker1;
- an isolated Docker daemon/container on worker2 without replacing kubelet's system containerd;
- etcd endpoint health and structured kube-bench evidence;
- a fresh Falco modern-eBPF event;
- HTTP and HTTPS ingress behavior;
- candidate tool versions, Trivy's digest-pinned offline database, and a real minimal Ubuntu rootfs scan;
- six non-interactive strict SSH handshakes from the candidate workstation to the declared exercise aliases.

## Artifact and archive integrity

Every transport artifact is digest-pinned. A host-side release gate downloaded or reused each real release, verified the transport digest, reproduced the exact guest extraction and mode normalization, and matched 10 host-pinned installed-artifact fingerprints.

The shared archive contract rejects non-regular members, traversal, aliases, duplicates, file ancestors, Unicode/casefold collisions, overlong paths/components/depth, more than 4,096 members, more than 1 GiB expanded content, unbounded decompressed streams, and PAX/GNU extension allocation bombs. A compressed combined-maximum fixture with 1 GiB total payload, 4,096 members, and one bounded PAX record per member is accepted by both host and guest validators. A 16 MiB compressed PAX metadata bomb is rejected before extraction.

The release cache is owner-only, rejects unsafe destination types and oversized or growing artifacts, hashes network bytes through the original temporary descriptor, publishes atomically at mode `0600`, and holds an owner-only advisory lock across the complete hash-to-consumption transaction.

## Automated and review gates

- `python3 -m unittest discover -q`: 276 tests passed on the frozen source used for the accepted live run.
- Python compilation, every provisioning script's `bash -n`, generated-manifest freshness, and `git diff --check` passed.
- The real release-integrity gate matched all 10 installed fingerprints after both a fresh-cache download and cached replay.
- `CKS_KIND_USE_GLOBAL=0 ./bin/cks-simulator e2e --name cks-simulator-u5-final`: 15/15 quick-tier gates passed with a score of 100/100, and the Kind cluster was deleted.
- Independent correctness, testing, and reliability reviewers returned no findings after remediation. The security review's concrete archive, redirect, cache, and filesystem findings were fixed and covered by the final behavioral suite; a replacement final security worker was unavailable and did not produce additional findings.

## Cleanup proof

Exact destroy reached `destroyed`; a second destroy returned the same result without provider mutation. `limactl list` and `kind get clusters` then reported no instances or clusters. A durable-state scan found no private-key block, embedded client credential, bootstrap token, or kubeconfig material.
