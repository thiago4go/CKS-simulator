# Provider and state boundary validation — 2026-07-14

## Result

U3 separates provider-neutral ownership, state, process execution, and tier
routing from the existing quick simulator. The accepted implementation fails
closed unless the immutable host inventory, exact provider discovery, and
root-owned guest identity agree. Destructive provider operations are available
only through the state coordinator for UUID-derived exact handles; concrete
providers expose no public delete API.

The omitted `--tier` value remains byte-for-byte equivalent to `--tier quick`.
Every full-tier route is present but fails before provider mutation until the U4
production lifecycle is integrated.

## Verification

The final U3 gate records:

- 127/127 tests in the complete offline unit suite, including adversarial identifier, state,
  lock, provider, process-output, environment, symlink, FIFO, ownership-authority,
  and JSON-contract cases;
- Python compilation, Bash syntax, version-manifest parsing, diff whitespace,
  and secret-pattern review;
- a live disposable quick-tier Kind run with 15/15 gates and a score of 100;
- independent confirmation that no matching Kind cluster or Docker node
  container remained after cleanup.

Accepted live command:

```sh
CKS_KIND_USE_GLOBAL=0 ./bin/cks-simulator e2e --tier quick --json
```

## Review-driven hardening

Two independent final reviewers identified concrete failure scenarios before
the unit was accepted:

- public authority dataclasses could be forged in-process;
- break-glass inventory was not tied deterministically to the lab UUID;
- a successful Lima delete could be misreported when the preceding stop failed;
- quick mutators advertised JSON without producing a JSON-only response;
- ambient `PATH`, provider-routing variables, and unbounded subprocess output
  could compromise discovery or cleanup;
- quick state writes could follow symlinks and mutable metadata could be forged;
- pathname check/use races could redirect or block state reads.

The final implementation removes transferable grants and centralizes deletion
behind state/provider/guest reconciliation, adds UUID-derived handle checks,
trusted absolute provider executables, anonymous verified provider-input
descriptors inherited only by their exact provider child, trusted absolute
quick-tier tools, a minimal process environment, bounded streaming output with
terminal sanitization,
descriptor-based state reads/writes, fail-closed quick ownership evidence, and
regression tests for every reported scenario.

## Scope

This receipt validates the U3 ownership and lifecycle boundary. It does not
claim that the four-VM production lifecycle is integrated; provisioning the
candidate plus three kubeadm nodes is U4.
