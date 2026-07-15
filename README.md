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

Validated platform requirements:

- Apple Silicon macOS;
- Lima 2.1.4;
- at least 16 logical CPUs and 200 GiB free disk; and
- 16 GiB host RAM for the default `standard` profile, or 12 GiB for `low`.

| Profile | Candidate | Control plane | Each worker | Guest total | Status |
|---|---:|---:|---:|---:|---|
| `standard` | 2 GiB | 4 GiB | 2 GiB | 10 GiB | Recommended default |
| `low` | 1 GiB | 2 GiB | 1 GiB | 5 GiB | Validated resource-constrained option |

`low` is exactly 50% of the default guest RAM. Validation covered all 17
repeatable scenario grades and restores on Build A, followed by destroy and an
independent clean Build B provision, replay, doctor and double-destroy. Neither
build used swap or logged an OOM kill. Build A needed diagnostic recovery from
a transient `systemd-logind` stall on a 1 GiB worker, so `standard` remains
recommended. The 12 GiB low-profile host floor preserves headroom; an 8 GiB
Mac is not claimed as supported because that host size has not been
release-tested.

Start and use the lab:

```sh
./bin/cks-simulator setup --tier full
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

`setup --tier full` installs the exact tested Lima release under the ignored
project-local `.cks-tools/` directory, verifies its published SHA-256, and then
runs the same host preflight as `doctor`. It is idempotent and does not install
Homebrew or modify global packages. CPU, RAM, and free-disk failures remain
explicit because software installation cannot repair host capacity.

For a resource-constrained host, select `low` when creating the lab:

```sh
./bin/cks-simulator setup --tier full --memory-profile low
./bin/cks-simulator doctor --tier full --memory-profile low
./bin/cks-simulator provision --tier full --memory-profile low --name cks-low
```

The profile is bound immutably in lab state. Later `provision`, `doctor --lab`,
and `shell` commands infer it when the option is omitted; explicitly requesting
a different profile fails before guest mutation. Changing profile requires
destroying the lab and creating a new name.

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
