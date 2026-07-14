# U6 Scenario Lifecycle and Trusted Grading Validation

Date: 2026-07-15 (Australia/Melbourne)

## Outcome

U6 establishes the offline contract for all 17 full-tier scenarios without
claiming that their live handlers already exist. Every catalog entry remains
`planned`; U7 and U8 must install and validate the real handlers before changing
an entry to `supported`.

The existing Kind tier remains the default. Full-tier grade, prepare, and
restore require explicit `--tier full` routing.

## Proven contracts

- The catalog contains ordered IDs 01 through 17 exactly once, with a static
  handler identity, target role, prerequisites, recovery class, untouched
  baseline contract, and restore contract for each entry.
- Catalog values are validated data and never become imports or shell commands.
- Preparation writes an attempt UUID and attempt-bound fingerprint before any
  handler mutation; the handler must independently return the observed
  fingerprint.
- Exactly one scenario attempt can be active for a lab.
- Live grading uses a fixed criterion denominator, rejects duplicate,
  undeclared, missing, or metadata-disagreeing evidence, and never awards a
  criterion from guest-only evidence.
- Grading uses a separately registered grader that cannot also expose
  prepare/restore, receives a capability-minimal immutable context, and runs
  under a state-write prohibition covering creation and replacement. Successful
  probes do not append a state phase and compare persistent state plus
  out-of-band live health before and after every probe, including exception
  paths; any probe fault degrades the attempt and requires recovery.
- Failed preparation or restoration retains the authenticated attempt in a
  degraded state; the exact handler can retry restoration and return the lab to
  its trusted baseline.
- Legacy `validated`, `scenario-prepared`, and `graded` journals remain readable
  for fresh attestation or cleanup, while new generic transitions into scenario
  phases are refused.
- Full-tier grade returns success only for `PASS`; learner failure, partial
  completion, lab breakage, and tampering remain non-zero outcomes.
- Quick-tier catalog JSON hides additive full-tier metadata and existing quick
  grade behavior remains the omitted-tier default.

## Verification

The final U6 offline suite completed with **324 passing tests** after the last
review fix and before commit.

Additional checks:

- Python compilation completed for `cks_simulator` and `tests`.
- `jq empty` accepted the scenario catalog and versioned infrastructure JSON.
- Every provisioning shell entrypoint passed `bash -n`.
- Generated U5 manifests matched `infra/versions.json`.
- `git diff --check` reported no whitespace errors.
- Secret-pattern matches were confined to deliberate redaction test fixtures;
  no generated key, kubeconfig, token, or lab credential was added.

No VM or Kind instance was required for U6 because all live handlers remain
`planned`. U7 and U8 own the serial live scenario matrix.

## Review history

An independent correctness review initially found four P1 issues: grader
mutation detection, unrecoverable degraded attempts, legacy journal rejection,
and replayable preparation claims. Later security/testing passes found
scenario-residue, mutation-laundering, state-creation, option-routing and output
contract gaps. The implementation was revised to add
capability-minimal grading with before/after integrity attestation, authenticated
degraded restoration, separate expected/observed prepare and restore
fingerprints, legacy recovery compatibility, attempt-bound contracts, structural
mutator/grader separation, write guards for state creation/replacement, recovery
selection, and complete CLI assertions. The final correctness review returned
clean; actual U7/U8 graders remain gated on read-only transports and credentials
before catalog support can change from `planned`.
