# Full VM lab runbook

## 1. Preflight

From the project root:

```sh
./bin/cks-simulator doctor --tier full --json
```

All 11 checks must pass. The validated platform is Apple Silicon macOS with
Lima 2.1.4, 16+ logical CPUs, 40+ GiB RAM and 200+ GiB free disk. A stopped
existing lab needs only the replay reserve reported by `doctor --lab`; creating
missing VM disks requires the full reserve.

## 2. Provision and verify

```sh
./bin/cks-simulator provision --tier full --name cks-simulator --json
./bin/cks-simulator doctor --tier full --lab --name cks-simulator --json
```

Provisioning is replay-safe. A second `provision` verifies identities, restores
volatile guest state, reapplies the committed bundle and reruns capability
checks. It does not create a second cluster or rotate to unrecorded machines.

Expected resources are four VMs, 12 guest vCPUs, 24 GiB guest RAM and up to
160 GiB sparse disk allocation. Initial provision commonly takes 10–15 minutes.

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
