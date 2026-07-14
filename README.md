# CKS Simulator

A small, local Kubernetes security practice environment based on the supplied CKS Simulator A brief (Kubernetes 1.35). It uses a three-node [kind](https://kind.sigs.k8s.io/) cluster and `kubectl`, with no Python packages required.

The simulator is intentionally honest about the boundary between Kubernetes API practice and node/runtime work. Scenarios that require AppArmor, gVisor, Falco, Cilium, Docker daemon configuration, kube-bench, or kubeadm static-pod edits are catalogued with explicit compatibility metadata instead of pretending that a stock kind node reproduces them.

## Quick start

```sh
./bin/cks-simulator doctor
./bin/cks-simulator provision
./bin/cks-simulator list
./bin/cks-simulator scenario create 06 --apply
./bin/cks-simulator shell
./bin/cks-simulator check 06
./bin/cks-simulator grade 06
./bin/cks-simulator e2e
./bin/cks-simulator delete
```

`provision` writes kubeconfig only to `.cks-state/kubeconfig-<cluster-name>`; it does not merge into `~/.kube/config`. Docker Desktop (or another Docker-compatible runtime) must be running. The default cluster is `cks-simulator`, with one control-plane and two workers, using `kindest/node:v1.35.1`.

The CLI uses a pinned kind v0.29.0 fallback in `tools/kind`. If a global `kind` is present it is used by default; set `CKS_KIND_USE_GLOBAL=0` to force the project-local pinned fallback. The fallback downloads into `.cks-state/bin/` and verifies the release checksum for macOS and Linux on amd64/arm64. OpenSSL is used to generate scenario 15's private TLS practice key inside project state; private keys are not stored in the repository.

## CLI

```text
doctor [--json]                         Check local prerequisites and compatibility
provision [--name NAME] [--image IMAGE] Create the multi-node cluster
delete [--name NAME] [--force]          Delete the owned cluster and isolated kubeconfig
reset [--name NAME] [--image IMAGE]     Delete then provision the owned cluster
list [--json]                           List all 17 scenarios
shell [--node NAME]                     Open a shell in a kind node
scenario create ID [--apply]            Seed a scenario fixture, optionally apply it
scenario reset ID [--apply]             Recreate a scenario fixture
check ID [--root PATH]                  Check learner artifacts
grade ID|all [--root PATH] [--json]     Score artifact criteria from 0 to 100
e2e [--name NAME] [--json] [--keep]    Run the disposable live kind release gate
```

Scenario artifacts live in `.cks-state/scenarios/<id>/artifacts/`. The `TASK.md` file and any source manifests are placed alongside them. A check is deterministic and local: it reads the expected artifact files and does not need a running cluster.

`grade` awards equal partial credit to the independently checkable criteria inside each scenario and normalizes each scenario to 100. `grade all` weights all 17 scenarios equally. This is artifact evidence, not an official CKS exam score and not proof that a host-dependent task ran successfully. `check` remains strict and exits successfully only at 100/100.

`e2e` is the functional release gate. It creates a uniquely named, owned cluster, waits for all three nodes, proves provisioning is idempotent, applies an explicit allowlist of stock-kind-compatible fixtures, waits for workloads, and deletes the cluster in a `finally` cleanup. Scenario 07 is validated with a server-side dry-run so the deliberately privileged Pod is never scheduled automatically. Workload images are digest-pinned. On failure, successful kind log exports are reported under `.cks-state/e2e-logs/`. Use `--keep` only for deliberate debugging. An explicit E2E name is refused when a cluster or ownership marker already exists, so the gate cannot reuse and delete an older lab.

The CLI records an ownership marker for each provisioned cluster and refuses to delete or apply to a same-named cluster it did not create. `provision` is idempotent for a healthy owned cluster; use `reset --force` only when you intentionally need to remove an unowned same-named cluster. `scenario create` refuses to replace an existing exercise, while explicit `scenario reset` recreates it and clears its prior artifacts.

## Compatibility model

Each catalog entry has one of these values:

- `native`: the fixture uses ordinary Kubernetes objects and is suitable for a stock kind cluster.
- `partial`: the Kubernetes objects can be seeded, but the supplied task also needs an addon or host integration not included by default.
- `unsupported`: the task depends on a host kernel, node daemon, container runtime, or control-plane filesystem that kind does not provide.

The compatibility label is guidance, not a score. Artifact checks still work for every scenario, so a learner can practise the command and configuration shape even when the live side cannot be reproduced locally.

Current live fixture coverage is scenarios 04, 06, 07, 11, and 15. The remaining partial scenarios have no safe stock-kind fixture, and unsupported scenarios are never presented as live-validated. Use a Linux VM or the original simulator for AppArmor, gVisor, Falco, Cilium, Docker daemon, kube-bench, and kubeadm control-plane filesystem work.

## Platform decision

kind is the quick tier, not a complete machine-level CKS replica. A Docker Compose stack of privileged Ubuntu containers is not a higher-fidelity replacement: the containers still share one Docker host kernel, systemd/kubeadm nesting is brittle, and AppArmor, gVisor, Falco, and host runtime behavior remain distorted.

The recommended future full tier is three Ubuntu virtual machines provisioned with kubeadm (Lima on macOS, or an equivalent VM provider on Linux). That tier can expose real systemd services, `/etc/kubernetes` static Pod manifests, `/var/lib/kubelet`, containerd/Docker daemon configuration, AppArmor, Cilium, gVisor, Falco, audit logs, and encryption-at-rest. It is intentionally not represented by the kind E2E score.

## Tests

```sh
python3 -m unittest discover -v
```

The test suite uses temporary state directories and never calls Docker, kind, or kubectl.
