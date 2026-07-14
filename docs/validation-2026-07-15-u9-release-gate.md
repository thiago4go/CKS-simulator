# U9 validation: full-tier release gate and recovery

Date: 2026-07-15 (Australia/Melbourne)

## Gate contract

`cks-simulator e2e --tier full --destroy-rebuild --json` now owns two unique
UUID-backed lab names and emits one bounded machine-readable receipt. Build A
proves idempotent IaC, operator-transport recovery, and the exact 17-scenario
lifecycle matrix. It is destroyed and reverified absent before Build B may
start. Build B proves a clean IaC reprovision, idempotent convergence and exact
cleanup.

For every scenario, the receipt requires:

- untouched `FAIL 0`;
- reference `PASS 100`;
- an identical repeated grade; and
- restore to `validated` with no active scenario.

Ordinary cleanup uses only the immutable inventory in the write-ahead state.
If it fails, UUID-bound break-glass may remove the exact resources, but the
release gate remains failed and records that cleanup-only defect. Provider
discovery is never broadened to a name prefix.

## Security and failure gates

- Explicit `--keep` is incompatible with `--destroy-rebuild`.
- Any pre-existing build state is refused before Build A starts.
- Receipts use a unique directory, mode `0700`, and file mode `0600` beneath a
  verified owner-only, non-symlink state root.
- Errors are bounded and redacted; no private key, kubeconfig or temporary
  bootstrap credential is copied into the receipt.
- Build B is not started unless Build A, including ordinary exact cleanup,
  passes.
- Interrupted scenario work is restored when operator transport and guest
  identity remain available; missing identity or transport requires rebuild
  without discovery or adoption.

## Verification

- Full offline suite: **340 tests passed**.
- Python compile and `git diff --check`: passed.
- Live recovery rehearsal on development lab `u8-live-b`: scenario 12 selected
  `operator-transport`, restored successfully, health-attested `validated`.
- Exact development-lab cleanup: UUID
  `7a1c5fd9-caec-4644-8e78-40f68ba0822f` reached `destroyed`; all four exact
  `cks-7a1c5fd9caec4644-*` Lima handles were absent afterward.

The authoritative two-build release receipt is U10 work and must use the
committed gate from zero Lima provider state.
