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
./bin/cks-simulator delete
```

`provision` writes kubeconfig only to `.cks-state/kubeconfig`; it does not merge into `~/.kube/config`. Docker Desktop (or another Docker-compatible runtime) must be running. The default cluster is `cks-simulator`, with one control-plane and two workers, using `kindest/node:v1.35.1`.

The CLI uses a pinned kind v0.29.0 fallback in `tools/kind`. If a global `kind` is present it is used by default; set `CKS_KIND_USE_GLOBAL=0` to force the project-local pinned fallback. The fallback downloads into `.cks-state/bin/` and verifies the release checksum for macOS and Linux on amd64/arm64.

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
```

Scenario artifacts live in `.cks-state/scenarios/<id>/artifacts/`. The `TASK.md` file and any source manifests are placed alongside them. A check is deterministic and local: it reads the expected artifact files and does not need a running cluster.

The CLI records an ownership marker for each provisioned cluster and refuses to delete or apply to a same-named cluster it did not create. `provision` is idempotent for a healthy owned cluster; use `reset --force` only when you intentionally need to remove an unowned same-named cluster. `scenario create` refuses to replace an existing exercise, while explicit `scenario reset` recreates it and clears its prior artifacts.

## Compatibility model

Each catalog entry has one of these values:

- `native`: the fixture uses ordinary Kubernetes objects and is suitable for a stock kind cluster.
- `partial`: the Kubernetes objects can be seeded, but the supplied task also needs an addon or host integration not included by default.
- `unsupported`: the task depends on a host kernel, node daemon, container runtime, or control-plane filesystem that kind does not provide.

The compatibility label is guidance, not a score. Artifact checks still work for every scenario, so a learner can practise the command and configuration shape even when the live side cannot be reproduced locally.

## Tests

```sh
python3 -m unittest discover -v
```

The test suite uses temporary state directories and never calls Docker, kind, or kubectl.
