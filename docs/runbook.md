# Full VM lab runbook

## 1. Preflight

From the project root:

```sh
./bin/cks-simulator setup --tier full --json
./bin/cks-simulator doctor --tier full --json
```

`setup` installs the checksum-pinned Lima 2.1.4 release inside `.cks-tools/`
when an exact compatible installation is not already available. It is safe to
repeat and does not alter Homebrew or other global packages. It then emits all
host checks; a nonzero result can therefore mean the software was installed
successfully but CPU, RAM, or disk capacity is still below the supported floor.

All 11 doctor checks must pass. The validated platform is Apple Silicon macOS
with Lima 2.1.4 and 80+ GiB free disk. The default `standard` profile requires
16+ logical CPUs and 16+ GiB host RAM. The resource-constrained `low` profile
uses eight guest vCPUs and 5 GiB guest RAM and requires 8+ logical host CPUs
and 12+ GiB host RAM:

```sh
./bin/cks-simulator doctor --tier full --memory-profile low --json
```

A stopped existing lab needs only the replay disk reserve reported by
`doctor --lab`; creating missing VM disks requires the full reserve.

## 2. Provision and verify

```sh
./bin/cks-simulator provision --tier full --name cks-simulator --json
./bin/cks-simulator doctor --tier full --lab --name cks-simulator --json
```

Provisioning is replay-safe. A second `provision` verifies identities, restores
volatile guest state, reapplies the committed bundle and reruns capability
checks. It does not create a second cluster or rotate to unrecorded machines.

Expected `standard` resources are four VMs, 12 guest vCPUs, 10 GiB guest RAM
and up to 160 GiB sparse virtual disk allocation. `low` uses 1/3/2/2 guest
vCPUs and 1/2/1/1 GiB guest RAM. Initial provision commonly takes 10–15
minutes; lower-resource hosts may take longer.

To select the 50%-RAM profile for a new lab:

```sh
./bin/cks-simulator provision \
  --tier full \
  --memory-profile low \
  --name cks-low \
  --json
```

This allocates 1 GiB to the candidate, 2 GiB to the control plane, and 1 GiB
to each worker. The selection is immutable and persisted; subsequent lifecycle
commands infer `low` when `--memory-profile` is omitted. A conflicting explicit
profile fails closed. Use a new lab name after destroy to change profiles.
Low-profile labs created before the eight-vCPU contract must likewise be
destroyed and recreated; replay will refuse their old immutable specification.

## 3. Enter the candidate workstation

```sh
./bin/cks-simulator shell --tier full --name cks-simulator
```

The shell logs in as `candidate`. kubectl, crictl, Trivy, kube-bench, Docker
client material and course files are preinstalled where scenarios require them.
The candidate cannot read operator state, root mutation/observation helpers,
reference fixtures or host files.

## 4. Practise one scenario

```sh
./bin/cks-simulator scenario prepare 14 --tier full --name cks-simulator --json
# Work from the candidate shell.
./bin/cks-simulator grade 14 --tier full --name cks-simulator --json
./bin/cks-simulator scenario restore 14 --tier full --name cks-simulator --json
```

Only one scenario can be active. `grade` may be repeated and must not mutate
state. Always restore before starting another scenario. If an operation fails,
run the same `scenario restore` command first; degraded labs accept the exact
reviewed restore for their active write-ahead claim.

## 5. Stop, resume, and diagnose

Lima may stop VMs outside this CLI. Resume through reconciliation:

```sh
./bin/cks-simulator provision --tier full --name cks-simulator --json
./bin/cks-simulator doctor --tier full --lab --name cks-simulator --json
```

Do not rename Lima instances, edit `.cks-state`, copy guest identities, or
manually adopt a machine. Identity or inventory mismatch requires deletion and
a new lab name.

For an active scenario failure:

1. retain the CLI error and scenario ID;
2. run `scenario restore ID --tier full --name NAME --json`;
3. run full lab doctor;
4. if operator transport or guest identity is unavailable, destroy and rebuild;
5. use break-glass only when ordinary exact cleanup refuses and the recorded
   UUID is known.

Break-glass syntax:

```sh
./bin/cks-simulator delete \
  --tier full \
  --name cks-simulator \
  --break-glass \
  --expected-lab-id 00000000-0000-4000-8000-000000000000 \
  --json
```

Replace the example UUID with the exact ID from trusted state/CLI output.

## 6. Destroy

```sh
./bin/cks-simulator delete --tier full --name cks-simulator --json
```

Success means every exact handle is absent and state is a `destroyed`
tombstone. Reuse is intentionally refused; choose a new name for the next lab.

## 7. Release validation

```sh
./bin/cks-simulator e2e \
  --tier full \
  --destroy-rebuild \
  --name release-check \
  --json
```

Allow about 50 minutes on the validated host. A PASS requires 17/17 Build A
scenarios, recovery rehearsal, two idempotent IaC builds, ordinary cleanup for
both builds and no residual lab paths. Build B is skipped if Build A or its
cleanup fails. Receipts are stored mode `0600` under
`.cks-state/full-e2e/<run-uuid>/receipt.json`.

The quick regression remains:

```sh
./bin/cks-simulator e2e --tier quick --json
```
