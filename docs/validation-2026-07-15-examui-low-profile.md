# ExamUI low-profile validation receipt

Date: 2026-07-15 (Australia/Melbourne)

## Scope

This receipt covers the exam-like candidate workflow on Apple Silicon using
the `low` profile: four Ubuntu VMs with 8 guest vCPUs and 5 GiB guest RAM total.
The host had 18 logical CPUs and 48 GiB RAM; a physical eight-logical-CPU host
remains the only resource-evidence gap.

## Final clean-IaC run

Build J was provisioned from repository IaC with no post-creation guest file
replacement. Its immutable lab UUID was
`5701bf89-bd46-42ed-a336-aff2aedd3e4d`.

The integrated combined-exam gate returned:

```json
{
  "duration_seconds": 971.4,
  "error": null,
  "passed": true,
  "reference_passes": 17,
  "restored": true,
  "score": 100.0,
  "started": true,
  "submitted": true,
  "tasks_scored": 17,
  "untouched_failures": 17
}
```

After teardown, all three Kubernetes nodes were Ready, `/readyz` returned
`ok`, raw etcd Secret bytes contained no `k8s:enc:` residue, task 12/14/17
apiserver artifacts were absent, the task 13 metadata Pod was absent, every VM
had swap disabled, and no kernel OOM event was found. Ordinary deletion reached
`destroyed`; no Build J Lima instance remained.

## Browser and desktop evidence

The clean Build H browser run exercised the three-panel ExamUI, authoritative
timer, all 17 weighted tasks, flag/complete/navigation state across reload,
practice `FAIL 0`, and final 17-task `100/100`. The embedded noVNC desktop
accepted terminal input through a displayed task-qualified SSH alias. noVNC's
`package.json` returned HTTP 200 and the browser recorded zero console errors.

Build I proved that the desktop forward is a dedicated SSH child with
`ControlMaster=no`, `ControlPath=none`, and `ControlPersist=no`. Submission
returned `desktop_url: null`, terminated the listener, and made its HTTP port
unreachable before the final result was read. Its canonical 17-task browser
receipt digest was
`997258b855316a6e3614a92cd1dee99dd5e31665dd7facf7989a96d64ea200de`.

## Faults found and closed

- kube-apiserver temporary manifests were moved outside kubelet's watched
  directory and repeated restores became idempotent.
- Encryption restore rewrites Secrets through an identity-first provider before
  removing the encryption configuration, with raw-etcd residue verification.
- AppArmor restore waits for profile unload and for selected task Pods to be
  deleted before exact observation.
- The metadata probe receives a bounded, exact-object force-delete fallback
  only after graceful deletion times out.
- The desktop tunnel no longer attaches forwarding state to Lima's persistent
  SSH multiplex master.

## Offline gate

`python3 -m unittest discover -s tests -p 'test_*.py'` passed 401/401 tests
after the final implementation changes.
