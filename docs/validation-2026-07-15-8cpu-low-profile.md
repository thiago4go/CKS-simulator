# Eight-CPU low-profile validation — 2026-07-15

## Result

**PASS with a host-specific caveat.** The existing state-bound `low` profile
now allocates exactly eight guest vCPUs and 5 GiB guest RAM across the same four
VM topology. All 17 scenario lifecycles and an independent clean rebuild passed.
The release host had 18 logical CPUs, so exact guest CPU limits were exercised
but an eight-logical-CPU physical Mac still requires one external confirmation
run before the host floor can be described as physically tested.

## Resource contract

| Role | vCPU | RAM | Sparse virtual disk cap |
|---|---:|---:|---:|
| Candidate | 1 | 1 GiB | 30 GiB |
| Control plane | 3 | 2 GiB | 50 GiB |
| Worker 1 | 2 | 1 GiB | 40 GiB |
| Worker 2 | 2 | 1 GiB | 40 GiB |
| **Total** | **8** | **5 GiB** | **160 GiB virtual** |

The low-profile host preflight floor is eight logical CPUs and 12 GiB RAM.
The measured physical backing reached 18.33 GiB after every scenario, plus
0.57 GiB of shared Lima cache. The creation reserve is therefore reduced from
200 GiB to 80 GiB, more than four times the observed complete-lab footprint.
The 160 GiB value remains a sparse virtual growth cap, not an up-front host
allocation.

## Build A — complete scenario gate

- Run ID: `af0b0c58-5fcc-4cef-8911-ff95c469f9d9`
- Lab ID: `163654fc-ac79-4051-b26b-ebb1ef030d34`
- Fresh provision: zero Lima instances to `candidate-ready`
- Exact observed CPUs: `1/3/2/2`
- Exact observed RAM: `1/2/1/1 GiB`
- Idempotent provisioning replay: passed
- Operator-transport recovery rehearsal for scenario 12: passed
- Scenarios attempted/passed: `17/17`
- Every untouched score: `0/100 FAIL`
- Every reference score: `100/100 PASS`
- Every repeated grade: identical
- Every restore: returned to a health-attested validated baseline
- Release duration: 1,974.2 seconds
- Final guest swap: zero on every VM
- Final kernel OOM events: zero on every VM
- Peak measured owned Lima backing: 18.33 GiB

Build A was retained only for measurement, then destroyed through the ordinary
owned-resource path. Lima reported zero instances and `~/.lima` returned to its
empty baseline.

## Build B — independent rebuild and cleanup

- Lab ID: `73ddb2a9-7986-44ee-a7eb-a7d129b184bc`
- Started from zero Lima instances under the new 80 GiB creation reserve
- Reached `candidate-ready` without intervention
- Exact observed CPUs and RAM again matched `1/3/2/2` and `1/2/1/1 GiB`
- Provision replay inferred the stored `low` profile and passed
- `doctor --lab` passed all host checks and behavioral reconciliation
- An explicit `standard` replay failed before guest mutation; the state SHA-256
  and final journal entry remained unchanged
- Every guest again reported zero swap and zero OOM events
- Ordinary destroy passed; repeated destroy was an idempotent no-op
- Final Lima inventory: zero instances

## Support decision

The reduced guest allocation is behaviorally validated and the simulator now
accepts an eight-logical-CPU host when `--memory-profile low` is selected.
`standard` remains the recommended default because the low profile has less
memory and scheduling margin. The one residual evidence gap is physical host
contention on an actual eight-logical-CPU Mac; run the documented destructive
E2E gate there to close that machine-specific gap.
