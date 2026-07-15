"""Concrete full VM scenario runtime with capability-separated grading.

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
_MUTATE_U8_PATH = f"{_GUEST_ROOT}/scenarios/mutate-u8.sh"
_OBSERVE_U8_PATH = f"{_GUEST_ROOT}/scenarios/observe-u8.sh"
_EXAM_APISERVER_PATH = f"{_GUEST_ROOT}/scenarios/exam-apiserver.sh"
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
    "09": ("control-plane", "worker1"),
    "10": ("control-plane", "worker1"),
    "11": ("control-plane",),
    "12": ("control-plane",),
    "13": ("control-plane", "worker2"),
    "14": ("control-plane",),
    "15": ("control-plane",),
    "16": ("control-plane", "worker1"),
    "17": ("control-plane",),
}
_MUTATION_ROLES: Mapping[str, Tuple[str, ...]] = {
    **_OBSERVATION_ROLES,
    "04": ("control-plane", "worker1"),
    "06": ("control-plane", "worker2"),
    "07": ("control-plane", "worker1"),
    "09": ("control-plane", "worker1"),
    "10": ("control-plane", "worker1"),
    "11": ("control-plane",),
    "12": ("control-plane",),
    "13": ("control-plane", "worker1", "worker2"),
    "14": ("control-plane",),
    "15": ("control-plane", "worker2"),
    "16": ("control-plane", "worker1"),
    "17": ("control-plane", "worker1"),
}
_CROSS_SOURCE = frozenset(
    {
        ("01", "contexts-exact"),
        ("01", "certificate-pem"),
        ("01", "certificate-match"),
        ("02", "scan-output-exact"),
        ("02", "forbidden-cves-absent"),
        ("07", "warning-recorded"),
        ("09", "logs-recorded"),
        ("10", "dmesg-evidence"),
        ("14", "password-decoded"),
        ("15", "certificate-match"),
        ("16", "logs-recorded"),
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
    "09": (
        ("profile-loaded", "the supplied AppArmor profile is loaded in enforce mode", 2),
        ("node-label", "worker1 carries the AppArmor scheduling label", 1),
        ("deployment-profile", "only c1 uses the localhost AppArmor profile", 2),
        ("pod-denied", "the live workload demonstrates profile denial", 2),
        ("logs-recorded", "the denial logs are recorded for handoff", 1),
    ),
    "10": (
        ("runtimeclass-handler", "RuntimeClass gvisor selects the runsc handler", 2),
        ("pod-runtime", "the live Pod uses RuntimeClass gvisor", 2),
        ("pod-worker1", "the sandboxed Pod is pinned to worker1", 1),
        ("dmesg-evidence", "guest-kernel evidence is recorded", 2),
        ("runtime-process", "a live runsc shim backs the workload", 2),
    ),
    "11": (
        ("password-updated", "db-con contains the required password", 2),
        ("user-data-moved", "user-data exists only in the destination namespace", 1),
        ("app-data-secret", "app-data is represented as a Secret", 1),
        ("configmap-removed", "the original app-data ConfigMap is absent", 1),
        ("consumers-updated", "both workload templates consume Secrets", 2),
        ("consumers-ready", "both updated consumers are Ready on worker2", 2),
    ),
    "12": (
        ("admission-config", "the apiserver mounts the admission configuration", 2),
        ("apiserver-enabled", "ImagePolicyWebhook is enabled", 2),
        ("webhook-backend", "the reviewed HTTPS backend is healthy", 1),
        ("dangerous-denied", "danger-danger images are denied through admission", 3),
        ("safe-allowed", "the backend allows a safe image review", 1),
    ),
    "13": (
        ("policy-cidr-allow", "general egress is allowed", 1),
        ("same-namespace-allow", "same-namespace endpoints are allowed", 1),
        ("kube-system-allow", "kube-system endpoints are allowed", 1),
        ("metadata-deny-rule", "metadata port 9055 has an explicit deny", 2),
        ("metadata-denied-live", "a live Pod cannot reach metadata", 3),
        ("peers-allowed-live", "peer and DNS connectivity remain live", 2),
        ("metadata-endpoint-live", "the metadata endpoint remains healthy out of band", 1),
    ),
    "14": (
        ("password-decoded", "the non-encoded AES-GCM key is recorded", 1),
        ("apiserver-configured", "the apiserver mounts and uses the encryption config", 2),
        ("secret-api-readable", "the encrypted Secret remains API-readable", 1),
        ("etcd-encrypted-prefix", "raw etcd bytes use the AES-GCM envelope", 3),
        ("plaintext-absent", "raw etcd bytes exclude the Secret plaintext", 2),
    ),
    "15": (
        ("ingress-tls", "Ingress secure references the supplied TLS Secret", 2),
        ("certificate-match", "the served certificate is for secure-ingress.test", 2),
        ("https-app", "HTTPS /app is live", 1),
        ("https-api", "HTTPS /api is live", 1),
        ("backend-routing", "both paths route to their declared Services", 2),
    ),
    "16": (
        ("custom-rule1", "Custom Rule 1 has the required warning contract", 1),
        ("custom-rule2", "Custom Rule 2 has the required info contract", 1),
        ("falco-rules-loaded", "all Falco agents are Ready with the rules", 2),
        ("rule1-event", "Falco captured a host-config access event", 2),
        ("rule2-event", "Falco captured a kill syscall event", 2),
        ("logs-recorded", "both fresh events are recorded for handoff", 1),
    ),
    "17": (
        ("maxbackup-one", "the audit backend retains one backup", 1),
        ("policy-secret-metadata", "Secret events use Metadata level", 2),
        ("policy-nodes-requestresponse", "system:nodes events use RequestResponse", 2),
        ("policy-default-none", "all other events are disabled", 1),
        ("secret-audit-event", "a fresh Secret audit event is present", 2),
        ("node-audit-event", "a fresh system:nodes audit event is present", 2),
        ("audit-exclusive", "the fresh audit log contains only declared classes", 2),
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


class ExamApiserverComposer:
    """Apply the reviewed task 12/14/17 reference fragments as one manifest."""

    def __init__(self, provider: ScenarioProvider, root: Path) -> None:
        self._provider = provider
        source = Path(root).resolve(strict=True) / "infra/provision/scenarios/exam-apiserver.sh"
        self._digest = hashlib.sha256(source.read_bytes()).hexdigest()

    @staticmethod
    def _control_plane(state: LabState):
        matches = tuple(item for item in state.inventory if item.role == "control-plane")
        if len(matches) != 1:
            raise ScenarioLifecycleError("exam apiserver composer has no exact control plane")
        return matches[0]

    def apply_reference(self, state: LabState) -> None:
        machine = self._control_plane(state)
        expected = GuestIdentity(
            state.identity.lab_id,
            machine.machine_id,
            machine.role,
            machine.handle,
        )
        digest = self._provider.execute_verified(
            expected,
            ("/usr/bin/sha256sum", _EXAM_APISERVER_PATH),
            as_root=True,
            timeout_seconds=30,
            output_limit=256,
        )
        fields = digest.stdout.strip().split() if digest.ok else ()
        if len(fields) != 2 or fields[0] != self._digest or fields[1] != _EXAM_APISERVER_PATH:
            raise ScenarioLifecycleError("exam apiserver helper integrity mismatch")
        result = self._provider.execute_verified(
            expected,
            (_EXAM_APISERVER_PATH, "reference"),
            as_root=True,
            timeout_seconds=600,
            output_limit=2048,
        )
        if not result.ok:
            raise ScenarioLifecycleError(
                "combined exam apiserver reference failed: "
                + bounded_redacted(result.diagnostic(limit=1024), limit=1024)
            )


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
            _MUTATE_U8_PATH: hashlib.sha256(
                (root / "infra/provision/scenarios/mutate-u8.sh").read_bytes()
            ).hexdigest(),
            _OBSERVE_U8_PATH: hashlib.sha256(
                (root / "infra/provision/scenarios/observe-u8.sh").read_bytes()
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
            path = _MUTATE_PATH if int(scenario_id) <= 8 else _MUTATE_U8_PATH
            expected = self._verify_script(state, role, path)
            self._require_ok(
                self._provider.execute_verified(
                    expected,
                    (path, scenario_id, action),
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
        path = _OBSERVE_PATH if int(scenario_id) <= 8 else _OBSERVE_U8_PATH
        expected = self._verify_script(state, role, path)
        result = self._require_ok(
            self._provider.execute_verified(
                expected,
                (path, scenario_id),
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


def build_full_registries(
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


def build_u7_registries(
    provider: ScenarioProvider, root: Path
) -> tuple[HandlerRegistry, ReferenceSolutionRegistry, ObservationBroker]:
    """Compatibility alias for callers introduced with scenarios 01–08."""

    return build_full_registries(provider, root)


def build_exam_apiserver_composer(
    provider: ScenarioProvider, root: Path
) -> ExamApiserverComposer:
    return ExamApiserverComposer(provider, root)


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
    "ExamApiserverComposer",
    "U7ScenarioMutator",
    "U7SnapshotEvaluator",
    "build_health_attestor",
    "build_full_registries",
    "build_exam_apiserver_composer",
    "build_u7_registries",
]
