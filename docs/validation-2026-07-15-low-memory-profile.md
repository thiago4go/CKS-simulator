# Low-memory profile validation — 2026-07-15

## Result

**PASS with reduced-margin caveat.** The parameterized `low` profile allocates
exactly 50% of the default guest memory: candidate 1 GiB, control plane 2 GiB,
and 1 GiB per worker, for 5 GiB total. `standard` remains the
recommended 10 GiB default.

## Environment

- Apple Silicon macOS, 18 logical CPUs, 48 GiB RAM
- Lima 2.1.4 with the `vz` driver and Ubuntu 24.04 ARM64 guests
- Kubernetes 1.35.6, Cilium 1.19.5, Falco 0.44.1, gVisor release-20260706.0
- Profile state: `provisioning_profile: low`
- Exact live Lima memory: 1/2/1/1 GiB across the four roles

The 12 GiB host preflight floor was not physically tested. It preserves 7 GiB
above the 5 GiB guest allocation. An 8 GiB host is intentionally not claimed.

## Evidence

Build A started from zero Lima instances and reached `addons-ready`. Its first
candidate doctor timed out because `systemd-logind` on worker 1 accepted SSH
authentication but stalled before launching the session. The guest had about
329 MiB available, no swap, no OOM log, and no sustained PSI pressure. Killing
the wedged service process allowed systemd to restart it; the exact candidate
doctor then passed. This repair was diagnostic and prevents Build A from being
treated as a clean-build release pass.

After normal replay, Build A passed the full 17-scenario matrix:

- untouched attempt: 0/100 for every scenario;
- reference solution: 100/100 for every scenario;
- repeated grade: identical 100/100 for every scenario;
- restore: health-attested `validated` baseline for every scenario;
- no guest swap, kernel OOM kill, or sustained memory pressure at final sample.

Build A was destroyed and Lima reported zero instances. Build B then started
from an empty provider inventory with a new lab UUID and no manual intervention.
It reached `candidate-ready`, passed an idempotent replay with the profile
omitted, and passed `doctor --lab`; state inference correctly retained `low`.
An explicit `standard` replay was rejected for immutable profile drift before
guest mutation. Build B was destroyed twice idempotently and Lima again
reported zero instances.

Final Build B memory samples were:

| Guest | Available | Swap | OOM kills |
|---|---:|---:|---:|
| Candidate | 709 MiB | 0 | 0 |
| Control plane | 745 MiB | 0 | 0 |
| Worker 1 | 363 MiB | 0 | 0 |
| Worker 2 | 281 MiB | 0 | 0 |

## Support decision

`low` is usable and behaviorally validated as a resource-constrained option,
including all grading paths and an independent clean rebuild. The transient
Build A login-service stall and the narrow worker headroom mean it has less
operational margin than `standard`. The CLI therefore keeps `standard` as the
default and requires explicit `--memory-profile low` when creating a low lab.

Follow-up validation later reduced the same profile to eight total guest vCPUs
and lowered its host CPU floor to eight. See
`validation-2026-07-15-8cpu-low-profile.md`; it supersedes this document only
for CPU allocation and disk-reserve claims.
