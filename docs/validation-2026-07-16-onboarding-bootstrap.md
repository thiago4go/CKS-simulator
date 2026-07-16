# Public onboarding and bootstrap validation — 2026-07-16

## Outcome

The public full-tier path now starts before Python is available, installs the
software prerequisites the project can safely own, documents the remaining
physical constraints, and shows the real candidate workflow in the README.

## Evidence

- A clean temporary tools root downloaded the pinned standalone Python archive,
  verified its committed SHA-256, launched Python 3.13.14, and replayed without
  another download.
- `./setup.sh --memory-profile low` reused or installed Python, installed the
  project-local Lima 2.1.4 release, and passed all 11 host preflight checks.
- Fresh lab `cks-docs-ui-5`, UUID
  `d4646b2f-5be7-4b57-b055-e626de4764de`, reached the combined 17-task ExamUI
  from the final guest provisioning bundle at 8 guest vCPUs and 5 GiB RAM.
- Ubuntu package sources were converted to the official HTTPS ports endpoint
  before the first guest `apt-get update`; candidate desktop convergence passed.
- Browser validation exercised the real loopback ExamUI and embedded noVNC
  desktop. The browser recorded zero console errors. The reviewed captures are
  `docs/images/examui-overview.png` and `docs/images/examui-task-detail.png`.
- Forced exam teardown restored the combined baseline in reverse order.
  Ordinary exact-handle deletion then left zero Lima instances.
- The offline suite passed 405/405 tests. Python compilation, shell syntax,
  generated-manifest checks, image integrity checks, and `git diff --check`
  also passed.

## Remaining host boundary

Automatic installation cannot supply Apple Silicon hardware, CPU, RAM, or free
disk. The low profile still requires 8 logical CPUs, 12 GiB host RAM, and 80
GiB free disk. This validation host has 18 logical CPUs; the previously recorded
physical eight-CPU-host evidence gap remains unchanged.
