# Contributing

Keep the simulator stdlib-only and portable across macOS and Linux. Changes should stay inside this project repository boundary.

## Development loop

1. Add or update catalog metadata before changing a scenario fixture.
2. Keep live resources in `scenarios/fixtures/<id>/resources.json` and keep learner evidence rules in `scenarios/catalog.json`.
3. Mark a scenario `partial` or `unsupported` when it depends on an addon, kernel feature, daemon, or control-plane host filesystem absent from stock kind.
4. Add deterministic tests under `tests/`; tests must not require Docker or a running cluster.
5. Run `python3 -m unittest discover -v` and exercise `./bin/cks-simulator --help`.

Do not add credentials, downloaded binaries, kubeconfigs, or generated scenario state to source control. The project-local kind fallback is downloaded only at runtime into `.cks-state/bin/`.
