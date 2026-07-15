# CKS Simulator

`CKS-simulator` is a local Kubernetes security practice environment with two
explicit fidelity tiers:

- **Full (recommended):** four isolated Ubuntu ARM64 VMs on Apple Silicon: a
  candidate workstation plus one kubeadm control plane and two workers. It
  provides real systemd, containerd, Cilium, AppArmor, gVisor, Falco, ingress,
  audit logging, encryption at rest, Docker and node filesystems.
- **Quick:** a disposable three-node Kind cluster for fast API-object and
  artifact practice. It is useful, but it is not a machine-level CKS replica.

The lab provisions the environment and tools as IaC. The learner is tested on
security tasks, not on installing Kubernetes, Cilium, Falco, scanners or the
simulator itself.

## Full VM lab

Validated host requirements:

- Apple Silicon macOS;
- Lima 2.1.4;
- at least 16 logical CPUs, 16 GiB RAM and 200 GiB free disk; and
- approximately 10 GiB guest RAM while the lab is running.

The compact allocation is 2 GiB for the candidate, 4 GiB for the control
plane, and 2 GiB for each worker. This is the measured default, not an
installation estimate: fresh provisioning and the memory-sensitive gVisor,
Cilium, encryption-at-rest, Falco and audit scenario lifecycles passed at this
size without swap, OOM events or node memory pressure.

Start and use the lab:

```sh
./bin/cks-simulator doctor --tier full
./bin/cks-simulator provision --tier full --name cks-simulator
./bin/cks-simulator doctor --tier full --lab --name cks-simulator
./bin/cks-simulator shell --tier full --name cks-simulator

./bin/cks-simulator scenario prepare 09 --tier full --name cks-simulator
# Complete the task from the candidate workstation.
./bin/cks-simulator grade 09 --tier full --name cks-simulator --json
./bin/cks-simulator scenario restore 09 --tier full --name cks-simulator

./bin/cks-simulator delete --tier full --name cks-simulator
```

Scenario operations are serial. `prepare` creates an untouched zero-score
attempt and records an exact write-ahead recovery claim. `grade` is read-only,
uses root-owned observations and a least-privilege grader identity, and never
executes a learner-supplied script. `restore` returns the lab to a health-
attested baseline. Use a new lab name after deletion; destroyed state is kept as
an ownership tombstone and is never silently adopted.

The full release gate is destructive and normally takes about 50 minutes on the
validated host:

```sh
./bin/cks-simulator e2e \
  --tier full \
  --destroy-rebuild \
  --name my-release-check \
  --json
```

Build A runs the recovery rehearsal and all 17 scenario lifecycles. It must be
destroyed and verified absent before Build B is provisioned independently from
IaC, replayed idempotently and destroyed. `--keep` is explicit and cannot be
combined with `--destroy-rebuild`.

## Quick Kind lab

The default tier remains lightweight and requires Docker, kubectl and Kind:

```sh
./bin/cks-simulator doctor
./bin/cks-simulator provision
./bin/cks-simulator list
./bin/cks-simulator scenario create 06 --apply
./bin/cks-simulator grade 06
./bin/cks-simulator e2e --json
./bin/cks-simulator delete
```

Quick-tier kubeconfig and scenario state remain under `.cks-state/`; the CLI
does not merge into `~/.kube/config`. Its release gate covers five safe live
fixtures and deterministic artifact grading for all 17 scenarios. Host-kernel,
runtime and static-pod claims belong only to the full tier.

## Safety and ownership

- VM names derive from a random lab UUID, not from a discoverable prefix.
- Every mutating operation verifies the provider handle and root-owned guest
  identity against immutable state.
- Candidate credentials are separate from operator and grader credentials.
- Guests have no host-directory mounts; temporary join material is revoked.
- Ordinary deletion uses only the exact recorded inventory. UUID-bound
  break-glass is explicit, and a release gate remains failed even if it is
  needed to finish cleanup.
- Private keys, kubeconfigs, downloaded binaries and generated lab state are
  never committed.

See [the runbook](docs/runbook.md), [architecture](docs/architecture.md), and
[compatibility contract](docs/compatibility.md) for operational detail.

## Tests

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

The offline suite uses dependency-injected providers and temporary state; it
does not require live VMs, Docker, Kind or kubectl. Live release evidence is
recorded separately under `docs/validation-*.md` and `docs/receipts/`.
