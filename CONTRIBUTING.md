# Contributing

Keep the host CLI stdlib-only. Changes must stay inside this project repository
boundary and preserve the explicit quick/full tier split.

## Development loop

1. Add or update catalog metadata before changing a scenario fixture.
2. Preserve quick fixtures such as `resources.json`; full-only resources use an
   explicit name such as `full-resources.json`.
3. Keep full mutations and observations in fixed root-owned dispatch helpers.
   Observers must remain read-only, bounded and independent of learner input.
4. Mark quick compatibility `partial` or `unsupported` when stock Kind lacks the
   required addon, kernel, daemon or control-plane filesystem. Full support is a
   separate catalog field and requires live VM evidence.
5. Add deterministic dependency-injected tests under `tests/`; offline tests
   must not require Docker, Kind, Lima or a running cluster.
6. Run `python3 -m unittest discover -s tests -p 'test_*.py'`, Bash/Python syntax
   checks, `git diff --check`, and the relevant live tier gate.

Scenario changes are incomplete until they prove untouched `FAIL 0`, reference
`PASS 100`, identical repeated grade, exact restore and health attestation.
Changes to VM IaC or full scenarios require a fresh destroy/rebuild receipt.

Do not add credentials, private keys, downloaded binaries, kubeconfigs or
generated lab state to source control. Sanitized release receipts may be added
under `docs/receipts/` after review.
