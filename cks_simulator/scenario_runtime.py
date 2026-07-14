"""Concrete U7 VM scenario runtime with capability-separated grading.

Only :class:`ObservationBroker` owns read transport.  Graders are stateless
pure evaluators over :class:`~cks_simulator.scenarios.GradeSnapshot`; mutation
transport is held by a separate object used for prepare/reference/restore.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Mapping, Protocol, Sequence, Tuple

from .live_grading import (
    CriterionEvidence,
    ExpectedCriterion,
    LabSignals,
    TrustSource,
)
from .providers.base import GuestIdentity, ProcessResult, ProviderHandle, bounded_redacted
from .scenarios import (
    FullScenarioDefinition,
    GradeContext,
    GradeInputs,
    GradeSnapshot,
    HandlerRegistry,
    ReferenceSolutionRegistry,
    ScenarioContext,
    ScenarioContractError,
    ScenarioLifecycleError,
    scenario_state_fingerprint,
)
from .state import LabState


_GUEST_ROOT = "/opt/cks-simulator/provision"
_MUTATE_PATH = f"{_GUEST_ROOT}/scenarios/mutate.sh"
_OBSERVE_PATH = f"{_GUEST_ROOT}/scenarios/observe.sh"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_OBSERVATION_BYTES = 128 * 1024
_OBSERVATION_ROLES: Mapping[str, Tuple[str, ...]] = {
    "01": ("candidate",),
    "02": ("candidate",),
    "03": ("control-plane",),
    "04": ("control-plane",),
    "05": ("control-plane", "worker1"),
    "06": ("control-plane",),
    "07": ("control-plane", "worker1"),
    "08": ("worker2",),
}
_MUTATION_ROLES: Mapping[str, Tuple[str, ...]] = {
    **_OBSERVATION_ROLES,
    "04": ("control-plane", "worker1"),
    "06": ("control-plane", "worker2"),
    "07": ("control-plane", "worker1"),
}
_CROSS_SOURCE = frozenset(
    {
        ("01", "contexts-exact"),
        ("01", "certificate-pem"),
        ("01", "certificate-match"),
        ("02", "scan-output-exact"),
        ("02", "forbidden-cves-absent"),
        ("07", "warning-recorded"),
    }
)
_CHECKS: Mapping[str, Tuple[Tuple[str, str, float], ...]] = {
    "01": (
        ("contexts-exact", "all kubeconfig contexts are recorded exactly", 2),
        ("certificate-pem", "decoded certificate is valid PEM", 1),
        ("certificate-match", "certificate matches the pinned restricted user", 2),
    ),
    "02": (
        ("scan-output-exact", "good-images contains exactly the clean image", 2),
        ("forbidden-cves-absent", "reported images exclude both named CVEs", 1),
    ),
    "03": (
        ("service-clusterip", "the kubernetes Service is ClusterIP", 2),
        ("nodeport-absent", "NodePort 31000 is absent", 2),
    ),
    "04": (
        ("service-account", "workload uses the required ServiceAccount", 1),
        ("automount-disabled", "default ServiceAccount token automount is disabled", 1),
        ("projected-token", "custom projected token is configured", 2),
        ("expiration-1200", "projected token expiration is 1200 seconds", 2),
        ("readonly-mount", "custom token mount is read-only", 1),
    ),
    "05": (
        ("profiling-disabled", "controller-manager profiling is disabled", 1),
        ("etcd-owner", "etcd data ownership is etcd:etcd", 1),
        ("kubelet-mode", "worker kubelet configuration is mode 0600", 1),
        ("client-ca", "worker kubelet client CA is configured", 1),
    ),
    "06": (
        ("readonly-root", "container root filesystem is read-only", 2),
        ("tmp-emptydir", "only /tmp is backed by emptyDir", 2),
    ),
    "07": (
        ("audit-baseline", "namespace audit policy is baseline", 1),
        ("warn-restricted", "namespace warning policy is restricted", 1),
        ("bad-pod-admitted", "the supplied non-compliant Pod was admitted unchanged", 1),
        ("warning-recorded", "admission warning evidence was recorded", 1),
    ),
    "08": (
        ("icc-disabled", "Docker inter-container communication is disabled", 2),
        ("container1", "container1 is running the pinned image with restart always", 1),
        ("container2", "container2 is running the pinned image with restart always", 1),
        ("containers-isolated", "the two default-bridge containers cannot communicate", 2),
    ),
}


class ScenarioProvider(Protocol):
    name: str

    def observe_machine(self, handle: ProviderHandle): ...

    def execute_verified(
        self,
        expected: GuestIdentity,
        argv: Sequence[str],
        *,
        stdin: bytes | None = None,
        as_root: bool = False,
        timeout_seconds: float = 120.0,
        output_limit: int = 4096,
        secrets: Sequence[str] = (),
    ) -> ProcessResult: ...


def _criterion_keys(scenario_id: str) -> Tuple[str, ...]:
    try:
        return tuple(item[0] for item in _CHECKS[scenario_id])
    except KeyError as error:
        raise ScenarioContractError("scenario is outside the U7 runtime") from error


def _contract_sha(
    scenario_id: str, lifecycle: str, checks: Mapping[str, bool]
) -> str:
    payload = {
        "checks": {key: checks[key] for key in sorted(checks)},
        "lifecycle": lifecycle,
        "scenario_id": scenario_id,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _expected_contract_sha(scenario_id: str, lifecycle: str) -> str:
    checks = {key: False for key in _criterion_keys(scenario_id)}
    if lifecycle == "restored" and scenario_id == "03":
        checks.update({"service-clusterip": True, "nodeport-absent": True})
    if lifecycle == "restored" and scenario_id == "05":
        checks.update(
            {
                "kubelet-mode": True,
                "client-ca": True,
            }
        )
    return _contract_sha(
        scenario_id,
        lifecycle,
        checks,
    )


class _VerifiedTransport:
    def __init__(self, provider: ScenarioProvider, root: Path) -> None:
        self._provider = provider
        root = Path(root).resolve(strict=True)
        self._digests = {
            _MUTATE_PATH: hashlib.sha256(
                (root / "infra/provision/scenarios/mutate.sh").read_bytes()
            ).hexdigest(),
            _OBSERVE_PATH: hashlib.sha256(
                (root / "infra/provision/scenarios/observe.sh").read_bytes()
            ).hexdigest(),
        }

    @staticmethod
    def _machine(state: LabState, role: str):
        matches = tuple(item for item in state.inventory if item.role == role)
        if len(matches) != 1:
            raise ScenarioLifecycleError("scenario role has no exact owned machine")
        return matches[0]

    def _identity(self, state: LabState, role: str) -> GuestIdentity:
        if state.identity.provider != "lima" or self._provider.name != "lima":
            raise ScenarioLifecycleError("U7 scenario runtime requires the Lima provider")
        machine = self._machine(state, role)
        return GuestIdentity(
            state.identity.lab_id,
            machine.machine_id,
            machine.role,
            machine.handle,
        )

    @staticmethod
    def _require_ok(result: ProcessResult, context: str) -> ProcessResult:
        if not result.ok:
            raise ScenarioLifecycleError(
                f"{context}: {bounded_redacted(result.diagnostic(limit=1024), limit=1024)}"
            )
        return result

    def _verify_script(self, state: LabState, role: str, path: str) -> GuestIdentity:
        expected = self._identity(state, role)
        result = self._require_ok(
            self._provider.execute_verified(
                expected,
                ("/usr/bin/sha256sum", path),
                as_root=True,
                timeout_seconds=30,
                output_limit=256,
            ),
            "scenario helper integrity check failed",
        )
        fields = result.stdout.strip().split()
        if len(fields) != 2 or fields[0] != self._digests[path] or fields[1] != path:
            raise ScenarioLifecycleError("scenario helper integrity mismatch")
        return expected

    def mutate(self, state: LabState, scenario_id: str, action: str) -> None:
        if action not in {"prepare", "reference", "restore"}:
            raise ScenarioContractError("scenario mutation action is invalid")
        try:
            roles = _MUTATION_ROLES[scenario_id]
        except KeyError as error:
            raise ScenarioContractError("scenario is outside the U7 runtime") from error
        for role in roles:
            expected = self._verify_script(state, role, _MUTATE_PATH)
            self._require_ok(
                self._provider.execute_verified(
                    expected,
                    (_MUTATE_PATH, scenario_id, action),
                    as_root=True,
                    timeout_seconds=600,
                    output_limit=4096,
                ),
                f"scenario {scenario_id} {action} failed on {role}",
            )

    def observe_role(
        self, state: LabState, scenario_id: str, role: str
    ) -> Mapping[str, object]:
        if role not in _OBSERVATION_ROLES.get(scenario_id, ()):
            raise ScenarioContractError("scenario observation role is not reviewed")
        expected = self._verify_script(state, role, _OBSERVE_PATH)
        result = self._require_ok(
            self._provider.execute_verified(
                expected,
                (_OBSERVE_PATH, scenario_id),
                as_root=True,
                timeout_seconds=120,
                output_limit=_MAX_OBSERVATION_BYTES,
            ),
            f"scenario {scenario_id} observation failed on {role}",
        )
        if len(result.stdout.encode("utf-8")) > _MAX_OBSERVATION_BYTES:
            raise ScenarioLifecycleError("scenario observation exceeds its byte limit")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ScenarioLifecycleError("scenario observation is not JSON") from error
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "scenario_id",
            "role",
            "lifecycle",
            "checks",
            "state_sha256",
        }:
            raise ScenarioLifecycleError("scenario observation schema is invalid")
        if (
            value["schema"] != 1
            or value["scenario_id"] != scenario_id
            or value["role"] != role
            or value["lifecycle"] not in {"prepared", "reference", "restored"}
            or not isinstance(value["checks"], Mapping)
            or _SHA256.fullmatch(str(value["state_sha256"])) is None
        ):
            raise ScenarioLifecycleError("scenario observation identity is invalid")
        checks = value["checks"]
        if any(not isinstance(key, str) or not isinstance(item, bool) for key, item in checks.items()):
            raise ScenarioLifecycleError("scenario observation checks are invalid")
        return value


class ObservationBroker:
    """The sole U7 read transport; concrete evaluators never receive it."""

    def __init__(self, transport: _VerifiedTransport) -> None:
        self._transport = transport

    def collect_state(self, state: LabState, scenario_id: str) -> GradeSnapshot:
        observations = tuple(
            self._transport.observe_role(state, scenario_id, role)
            for role in _OBSERVATION_ROLES[scenario_id]
        )
        lifecycles = {str(item["lifecycle"]) for item in observations}
        if len(lifecycles) != 1:
            raise ScenarioLifecycleError("scenario roles disagree on lifecycle state")
        checks: dict[str, bool] = {}
        role_hashes: dict[str, str] = {}
        for item in observations:
            role = str(item["role"])
            role_hashes[role] = str(item["state_sha256"])
            for key, passed in item["checks"].items():
                if key in checks:
                    raise ScenarioLifecycleError("scenario observation check is duplicated")
                checks[str(key)] = bool(passed)
        if set(checks) != set(_criterion_keys(scenario_id)):
            raise ScenarioLifecycleError("scenario observation check set is incomplete")
        lifecycle = lifecycles.pop()
        return GradeSnapshot.from_mapping(
            scenario_id,
            {
                "checks": checks,
                "lifecycle": lifecycle,
                "normalized_state_sha256": _contract_sha(scenario_id, lifecycle, checks),
                "role_state_sha256s": role_hashes,
            },
        )

    def collect(
        self,
        context: GradeContext,
        definition: FullScenarioDefinition,
        state: LabState,
    ) -> GradeSnapshot:
        if (
            state.identity.lab_name != context.lab_name
            or state.identity.lab_id != context.lab_id
            or definition.scenario_id != context.scenario_id
        ):
            raise ScenarioLifecycleError("observation broker attempt identity mismatch")
        return self.collect_state(state, definition.scenario_id)


class U7ScenarioMutator:
    def __init__(self, transport: _VerifiedTransport, broker: ObservationBroker) -> None:
        self._transport = transport
        self._broker = broker

    def _apply(
        self,
        context: ScenarioContext,
        definition: FullScenarioDefinition,
        action: str,
        lifecycle: str,
        stage: str,
    ) -> str:
        self._transport.mutate(context.state, definition.scenario_id, action)
        snapshot = self._broker.collect_state(context.state, definition.scenario_id)
        payload = snapshot.payload()
        expected = _expected_contract_sha(definition.scenario_id, lifecycle)
        if payload.get("normalized_state_sha256") != expected:
            raise ScenarioLifecycleError(
                f"scenario {definition.scenario_id} {action} did not reach its exact contract"
            )
        return scenario_state_fingerprint(
            context,
            definition,
            stage=stage,
            observed_state_sha256=expected,
        )

    def prepare(
        self, context: ScenarioContext, definition: FullScenarioDefinition
    ) -> str:
        return self._apply(context, definition, "prepare", "prepared", "prepared")

    def restore(
        self, context: ScenarioContext, definition: FullScenarioDefinition
    ) -> str:
        return self._apply(context, definition, "restore", "restored", "restored")

    def reference(self, context: ScenarioContext, timeout_seconds: float) -> None:
        del timeout_seconds
        scenario_id = context.state.active_scenario.scenario_id
        self._transport.mutate(context.state, scenario_id, "reference")
        snapshot = self._broker.collect_state(context.state, scenario_id)
        payload = snapshot.payload()
        checks = payload.get("checks")
        if payload.get("lifecycle") != "reference" or not isinstance(checks, Mapping) or not all(
            checks.values()
        ):
            raise ScenarioLifecycleError("reference solution did not satisfy every criterion")


class U7SnapshotEvaluator:
    """Stateless pure evaluator.  Registration rejects instance state."""

    __slots__ = ()

    def evaluate(
        self, snapshot: GradeSnapshot, definition: FullScenarioDefinition
    ) -> GradeInputs:
        if snapshot.scenario_id != definition.scenario_id:
            raise ScenarioLifecycleError("snapshot and scenario definition disagree")
        payload = snapshot.payload()
        checks = payload.get("checks")
        if not isinstance(checks, Mapping):
            raise ScenarioLifecycleError("snapshot checks are missing")
        declarations = tuple(
            ExpectedCriterion(key, label, weight)
            for key, label, weight in _CHECKS[definition.scenario_id]
        )
        evidence = tuple(
            CriterionEvidence(
                key,
                label,
                weight,
                bool(checks[key]),
                (
                    TrustSource.CROSS_SOURCE
                    if (definition.scenario_id, key) in _CROSS_SOURCE
                    else TrustSource.OPERATOR
                ),
                "trusted fixed observation passed" if checks[key] else "required state not observed",
            )
            for key, label, weight in _CHECKS[definition.scenario_id]
        )
        return GradeInputs(declarations, evidence, LabSignals())


def _expected_fingerprint(stage: str):
    lifecycle = "prepared" if stage == "prepared" else "restored"

    def expected(
        context: ScenarioContext,
        definition: FullScenarioDefinition,
        attempt_id: str,
    ) -> str:
        return scenario_state_fingerprint(
            context,
            definition,
            stage=stage,
            observed_state_sha256=_expected_contract_sha(
                definition.scenario_id, lifecycle
            ),
            attempt_id=attempt_id,
        )

    return expected


def build_u7_registries(
    provider: ScenarioProvider, root: Path
) -> tuple[HandlerRegistry, ReferenceSolutionRegistry, ObservationBroker]:
    transport = _VerifiedTransport(provider, root)
    broker = ObservationBroker(transport)
    mutator = U7ScenarioMutator(transport, broker)
    evaluator = U7SnapshotEvaluator()
    handlers = HandlerRegistry()
    references = ReferenceSolutionRegistry()
    for scenario_id in _OBSERVATION_ROLES:
        identity = f"full.s{scenario_id}.v1"
        handlers.register_snapshot(
            identity,
            mutator,
            broker,
            evaluator,
            expected_prepared=_expected_fingerprint("prepared"),
            expected_restored=_expected_fingerprint("restored"),
        )
        references.register(identity, mutator.reference, lambda _context, _timeout: None)
    return handlers, references, broker


def build_health_attestor(provider: ScenarioProvider):
    def attest(context: ScenarioContext) -> str:
        state = context.state
        machines = {item.role: item for item in state.inventory}
        observations = {item.role: item for item in state.observations}
        if set(machines) != {"candidate", "control-plane", "worker1", "worker2"}:
            raise ScenarioLifecycleError("health attestation inventory is incomplete")
        if set(observations) != set(machines):
            raise ScenarioLifecycleError("health attestation observations are incomplete")
        current_machines = []
        for role in sorted(machines):
            machine = machines[role]
            expected = GuestIdentity(
                state.identity.lab_id,
                machine.machine_id,
                machine.role,
                machine.handle,
            )
            identity_probe = provider.execute_verified(
                expected,
                ("/usr/bin/true",),
                as_root=False,
                timeout_seconds=30,
                output_limit=64,
            )
            if not identity_probe.ok:
                raise ScenarioLifecycleError("health attestation identity probe failed")
            current = provider.observe_machine(machine.handle)
            durable = observations[role]
            if (
                current.ipv4 != durable.ipv4
                or current.mac != durable.mac_address
                or current.product_uuid != durable.product_uuid
            ):
                raise ScenarioLifecycleError("health attestation machine facts drifted")
            current_machines.append(
                {
                    "handle": machine.handle.value,
                    "ipv4": current.ipv4,
                    "mac": current.mac,
                    "machine_id": machine.machine_id,
                    "product_uuid": current.product_uuid,
                    "role": role,
                }
            )
        argv = ["/usr/bin/env"]
        for role, prefix in (
            ("control-plane", "CONTROL_PLANE"),
            ("worker1", "WORKER1"),
            ("worker2", "WORKER2"),
        ):
            argv.extend(
                (
                    f"{prefix}_NAME={machines[role].handle.value}",
                    f"{prefix}_IP={observations[role].ipv4}",
                )
            )
        argv.append(f"{_GUEST_ROOT}/control-plane/health.sh")
        control_plane = machines["control-plane"]
        expected_control_plane = GuestIdentity(
            state.identity.lab_id,
            control_plane.machine_id,
            control_plane.role,
            control_plane.handle,
        )
        result = provider.execute_verified(
            expected_control_plane,
            tuple(argv),
            as_root=True,
            timeout_seconds=900,
            output_limit=2048,
        )
        if not result.ok:
            raise ScenarioLifecycleError(
                "live cluster health attestation failed: "
                + bounded_redacted(result.diagnostic(limit=1024), limit=1024)
            )
        payload = {
            "contract": "cks-simulator/u7-health/v1",
            "machines": current_machines,
            "lab_id": state.identity.lab_id,
            "provisioning_spec_sha256": state.provisioning_spec_sha256,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    return attest


__all__ = [
    "ObservationBroker",
    "U7ScenarioMutator",
    "U7SnapshotEvaluator",
    "build_health_attestor",
    "build_u7_registries",
]
