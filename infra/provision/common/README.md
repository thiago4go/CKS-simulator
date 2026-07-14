# Common guest provisioning contract

The host installs this directory into
`/var/lib/cks-simulator/provision/common/` through the Lima provider's
root-file stdin API. Install `install.sh` and `check.sh` with mode `0700`; install
`lib.sh` and `versions.env` with mode `0644`. The host then executes a fixed
absolute entrypoint with these nine positional arguments:

```text
MANIFEST ROLE LAB_ID HANDLE NODE_NAME NODE_IP POD_CIDR SERVICE_CIDR REQUIRED_PORTS
```

`ROLE` is exactly one of `candidate`, `control-plane`, `worker1`, or `worker2`.
`HANDLE` and `NODE_NAME` must both be the deterministic provider handle derived
from `LAB_ID` and `ROLE`. The root-owned Lima identity marker must agree with
those values.

Candidate invocations pass `- - -` for the final three values. Kubernetes node
invocations use non-overlapping IPv4 pod and service CIDRs and these exact TCP
preflight lists:

- `control-plane`: `6443,2379,2380,10250,10257,10259`
- `worker1` / `worker2`: `10250,10256`

Before kubeadm ownership files exist, both convergence and check mode reject a
listener on any required port. Once the exact node is initialized, the cluster
reconciler owns listener and membership checks.

`versions.env` is generated; update it only with:

```sh
python3 infra/provision/common/render_versions.py --write \
  --source infra/versions.json \
  --output infra/provision/common/versions.env
```
