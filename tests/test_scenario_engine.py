from __future__ import annotations

import hashlib
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from cks_simulator.live_grading import (
    CriterionEvidence,
    ExpectedCriterion,
    GradeStatus,
    TrustSource,
)
from cks_simulator.providers.base import ProviderMachine, derive_provider_handle
from cks_simulator.scenarios import (
    EXPECTED_SCENARIO_IDS,
    FullScenarioDefinition,
    GradeContext,
    GradeInputs,
    GradeSnapshot,
    HandlerRegistry,
    ReferenceSolutionRegistry,
    RecoveryMode,
    RecoverySignals,
    ScenarioCatalog,
    ScenarioContext,
    ScenarioContractError,
    ScenarioEngine,
    ScenarioLifecycleError,
    load_full_catalog,
    preparation_claim_fingerprint,
    scenario_state_fingerprint,
    select_recovery_mode,
)
from cks_simulator.state import (
    LabPhase,
    LabStateStore,
    MachineObservation,
    StateValidationError,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "scenarios" / "catalog.json"
BASELINE_BYTES = b"operator-owned healthy lab baseline\n"
UNSOLVED_BYTES = b"prepared unsolved scenario\n"
SOLVED_BYTES = b"learner solved scenario\n"


def content_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def expected_prepared_fingerprint(
    context: ScenarioContext,
    definition: FullScenarioDefinition,
    attempt_id: str,
) -> str:
    return scenario_state_fingerprint(
        context,
        definition,
        stage="prepared",
        observed_state_sha256=content_sha256(UNSOLVED_BYTES),
        attempt_id=attempt_id,
    )


def expected_restored_fingerprint(
    context: ScenarioContext,
    definition: FullScenarioDefinition,
    attempt_id: str,
) -> str:
    return scenario_state_fingerprint(
        context,
        definition,
        stage="restored",
        observed_state_sha256=content_sha256(BASELINE_BYTES),
        attempt_id=attempt_id,
    )

EXPECTED_FULL_METADATA = (
    (
        "01",
        "Contexts",
        "supported",
        "candidate",
        ("multi-context-kubeconfig", "restricted-client-certificate"),
        "candidate-files",
        "full.s01.v1",
        "full.s01.unsolved.v1",
        "candidate.context-fixture.v1",
    ),
    (
        "02",
        "Image Vulnerability Scanning",
        "supported",
        "candidate",
        ("trivy-scanner", "vulnerability-database", "pinned-scan-images"),
        "candidate-files",
        "full.s02.v1",
        "full.s02.unsolved.v1",
        "candidate.image-scan-fixture.v1",
    ),
    (
        "03",
        "Apiserver Security",
        "supported",
        "control-plane",
        ("apiserver-nodeport-baseline", "kubeadm-static-pod", "operator-transport"),
        "control-plane",
        "full.s03.v1",
        "full.s03.unsolved.v1",
        "control-plane.apiserver-service.v1",
    ),
    (
        "04",
        "ServiceAccount Token Expiration",
        "supported",
        "worker1",
        ("scenario-namespace", "service-account", "unsolved-deployment"),
        "kubernetes-api",
        "full.s04.v1",
        "full.s04.unsolved.v1",
        "kubernetes-api.service-account-token.v1",
    ),
    (
        "05",
        "CIS Benchmark",
        "supported",
        "control-plane",
        ("kube-bench", "reviewed-node-files", "kubelet-service"),
        "node-cis",
        "full.s05.v1",
        "full.s05.unsolved.v1",
        "node-cis.control-plane.v1",
    ),
    (
        "06",
        "Immutable Root FileSystem",
        "supported",
        "worker2",
        ("scenario-namespace", "unsolved-deployment"),
        "kubernetes-api",
        "full.s06.v1",
        "full.s06.unsolved.v1",
        "kubernetes-api.immutable-filesystem.v1",
    ),
    (
        "07",
        "Pod Security Standard and Admission",
        "supported",
        "worker1",
        ("pod-security-admission", "scenario-namespace", "privileged-pod-source"),
        "kubernetes-api",
        "full.s07.v1",
        "full.s07.unsolved.v1",
        "kubernetes-api.pod-security-admission.v1",
    ),
    (
        "08",
        "Docker Configuration and Usage",
        "supported",
        "worker2",
        ("docker-engine", "isolated-docker-daemon", "pinned-nginx-image"),
        "docker",
        "full.s08.v1",
        "full.s08.unsolved.v1",
        "docker.daemon-containers.v1",
    ),
    (
        "09",
        "AppArmor Profile",
        "supported",
        "worker1",
        ("apparmor", "apparmor-profile-source", "kubernetes-api"),
        "apparmor",
        "full.s09.v1",
        "full.s09.unsolved.v1",
        "apparmor.profile-workload.v1",
    ),
    (
        "10",
        "Container Runtime Sandbox gVisor",
        "supported",
        "worker1",
        ("runsc-systrap", "containerd", "kubernetes-api"),
        "gvisor",
        "full.s10.v1",
        "full.s10.unsolved.v1",
        "gvisor.runtime-workload.v1",
    ),
    (
        "11",
        "Secret Management",
        "supported",
        "worker2",
        (
            "scenario-namespaces",
            "kubernetes-secrets",
            "kubernetes-configmap",
            "consuming-workload",
        ),
        "kubernetes-api",
        "full.s11.v1",
        "full.s11.unsolved.v1",
        "kubernetes-api.secret-management.v1",
    ),
    (
        "12",
        "ImagePolicyWebhook",
        "supported",
        "control-plane",
        (
            "webhook-backend",
            "admission-configuration",
            "kubeadm-static-pod",
            "operator-transport",
        ),
        "control-plane",
        "full.s12.v1",
        "full.s12.unsolved.v1",
        "control-plane.image-policy-webhook.v1",
    ),
    (
        "13",
        "CiliumNetworkPolicy Metadata Server",
        "supported",
        "control-plane",
        ("cilium", "metadata-endpoint", "test-workloads"),
        "kubernetes-api",
        "full.s13.v1",
        "full.s13.unsolved.v1",
        "kubernetes-api.cilium-metadata-policy.v1",
    ),
    (
        "14",
        "ETCD Secret Encryption",
        "supported",
        "control-plane",
        (
            "etcd",
            "encryption-config-source",
            "kubeadm-static-pod",
            "operator-transport",
        ),
        "control-plane",
        "full.s14.v1",
        "full.s14.unsolved.v1",
        "control-plane.etcd-encryption.v1",
    ),
    (
        "15",
        "Configure TLS on Ingress",
        "supported",
        "worker2",
        ("ingress-controller", "generated-tls-keypair"),
        "kubernetes-api",
        "full.s15.v1",
        "full.s15.unsolved.v1",
        "kubernetes-api.ingress-tls.v1",
    ),
    (
        "16",
        "Runtime Security with Falco",
        "supported",
        "worker1",
        ("falco-modern-ebpf", "falco-rule-source", "event-generators"),
        "falco",
        "full.s16.v1",
        "full.s16.unsolved.v1",
        "falco.rules-service.v1",
    ),
    (
        "17",
        "Audit Log Policy",
        "supported",
        "control-plane",
        (
            "audit-policy-source",
            "audit-log-path",
            "kubeadm-static-pod",
            "operator-transport",
        ),
        "control-plane",
        "full.s17.v1",
        "full.s17.unsolved.v1",
        "control-plane.audit-policy.v1",
    ),
)


def candidate_ready(store: LabStateStore, lab_name: str):
    state = store.claim(lab_name, provider="lima")
    state = store.bind_provisioning_spec(lab_name, state.identity.lab_id, "a" * 64)
    machines = tuple(
        ProviderMachine(
            role=role,
            machine_id=str(uuid.uuid4()),
            handle=derive_provider_handle("lima", state.identity.lab_id, role),
        )
        for role in ("candidate", "control-plane", "worker1", "worker2")
    )
    state = store.declare_inventory(lab_name, state.identity.lab_id, machines)
    observations = tuple(
        MachineObservation(
            role=machine.role,
            machine_id=machine.machine_id,
            handle=machine.handle,
            ipv4=f"192.0.2.{20 + index}",
            mac_address=f"02:00:00:00:00:{index + 1:02x}",
            product_uuid=str(uuid.uuid4()),
            provisioning_bundle_sha256="b" * 64,
            provisioning_spec_sha256="a" * 64,
        )
        for index, machine in enumerate(machines)
    )
    state = store.record_machine_observations(
        lab_name, state.identity.lab_id, observations
    )
    for phase in (
        LabPhase.VMS_CREATED,
        LabPhase.OS_READY,
        LabPhase.CLUSTER_READY,
        LabPhase.ADDONS_READY,
        LabPhase.CANDIDATE_READY,
    ):
        state = store.advance(lab_name, state.identity.lab_id, phase)
    return state


def catalog_with_supported(*scenario_ids: str) -> ScenarioCatalog:
    supported = frozenset(scenario_ids)
    catalog = load_full_catalog(CATALOG_PATH)
    return ScenarioCatalog(
        replace(
            definition,
            support="supported" if definition.scenario_id in supported else "planned",
        )
        for definition in catalog.definitions
    )


class FakeHealthAttestor:
    def __init__(self, host: dict[str, bytes]) -> None:
        self.host = host
        self.calls: list[LabPhase] = []

    def __call__(self, context: ScenarioContext) -> str:
        self.calls.append(context.state.phase)
        return hashlib.sha256(self.host["bytes"]).hexdigest()


class FakeScenarioGrader:
    def __init__(self, host: dict[str, bytes], events: list[str]) -> None:
        self.host = host
        self.events = events
        self.grade_mutates = False
        self.grade_raises = False
        self.state_mutator: LabStateStore | None = None
        self.claim_during_grade: str | None = None

    def grade(
        self, context: GradeContext, definition: FullScenarioDefinition
    ) -> GradeInputs:
        self.events.append(f"grade:{context.scenario_id}:{definition.scenario_id}")
        if self.grade_mutates:
            self.host["bytes"] = b"grade illegally mutated the lab\n"
        if self.state_mutator is not None:
            if self.claim_during_grade is not None:
                self.state_mutator.claim(self.claim_during_grade, provider="lima")
            else:
                self.state_mutator.advance(
                    context.lab_name, context.lab_id, LabPhase.CLEANUP_PENDING
                )
        if self.grade_raises:
            raise RuntimeError("grade failed after probe")
        criterion = ExpectedCriterion(
            "scenario-solved", "operator observes the solved state", 1.0
        )
        passed = self.host["bytes"] == SOLVED_BYTES
        evidence = CriterionEvidence(
            criterion_id=criterion.criterion_id,
            label=criterion.label,
            weight=criterion.weight,
            passed=passed,
            trust_source=TrustSource.OPERATOR,
            detail="fake operator probe",
        )
        return GradeInputs((criterion,), (evidence,))


class FakeScenarioHandler:
    def __init__(
        self,
        host: dict[str, bytes],
        *,
        prepare_outcome: str = "exact",
        restore_outcome: str = "exact",
        grade_mutates: bool = False,
        grade_raises: bool = False,
        state_mutator: LabStateStore | None = None,
        claim_during_grade: str | None = None,
    ) -> None:
        self.host = host
        self.prepare_outcome = prepare_outcome
        self.restore_outcome = restore_outcome
        self.events: list[str] = []
        self.claims: list[str] = []
        self.grader = FakeScenarioGrader(host, self.events)
        self.grader.grade_mutates = grade_mutates
        self.grader.grade_raises = grade_raises
        self.grader.state_mutator = state_mutator
        self.grader.claim_during_grade = claim_during_grade

    def prepare(
        self,
        context: ScenarioContext,
        definition: FullScenarioDefinition,
    ) -> str:
        self.events.append(f"prepare:{context.state.phase.value}:{definition.scenario_id}")
        if self.prepare_outcome != "noop":
            self.host["bytes"] = UNSOLVED_BYTES
        if self.prepare_outcome == "raise":
            raise RuntimeError("fake prepare failed after mutation")
        if self.prepare_outcome == "mismatch":
            return "f" * 64
        observed = scenario_state_fingerprint(
            context,
            definition,
            stage="prepared",
            observed_state_sha256=content_sha256(self.host["bytes"]),
        )
        self.claims.append(observed)
        return observed

    def restore(
        self, context: ScenarioContext, definition: FullScenarioDefinition
    ) -> str:
        self.events.append(f"restore:{context.state.phase.value}:{definition.scenario_id}")
        if self.restore_outcome == "raise":
            raise RuntimeError("fake restore failed")
        self.host["bytes"] = (
            BASELINE_BYTES
            if self.restore_outcome in {"exact", "residue"}
            else b"restored with health drift\n"
        )
        observed_bytes = (
            b"scenario residue remains\n"
            if self.restore_outcome == "residue"
            else self.host["bytes"]
        )
        return scenario_state_fingerprint(
            context,
            definition,
            stage="restored",
            observed_state_sha256=content_sha256(observed_bytes),
        )


class CatalogContractTests(unittest.TestCase):
    def test_catalog_has_exact_17_full_tier_metadata_contracts(self) -> None:
        catalog = load_full_catalog(CATALOG_PATH)

        actual = tuple(
            (
                item.scenario_id,
                item.title,
                item.support,
                item.target_role,
                item.prerequisites,
                item.recovery_class,
                item.handler_identity,
                item.untouched_baseline,
                item.restore_fingerprint,
            )
            for item in catalog.definitions
        )
        self.assertEqual(
            EXPECTED_SCENARIO_IDS,
            tuple(f"{value:02d}" for value in range(1, 18)),
        )
        self.assertEqual(actual, EXPECTED_FULL_METADATA)
        self.assertEqual(
            tuple(item.scenario_id for item in catalog.definitions),
            EXPECTED_SCENARIO_IDS,
        )

    def test_recovery_ladder_uses_api_fallback_and_requires_rebuild_on_identity_loss(self) -> None:
        catalog = load_full_catalog(CATALOG_PATH)
        api_scenario = catalog.require("04")
        control_plane = catalog.require("03")

        self.assertIs(
            select_recovery_mode(api_scenario, RecoverySignals()),
            RecoveryMode.TARGETED,
        )
        self.assertIs(
            select_recovery_mode(
                api_scenario, RecoverySignals(api_available=False)
            ),
            RecoveryMode.OPERATOR_TRANSPORT,
        )
        self.assertIs(
            select_recovery_mode(control_plane, RecoverySignals()),
            RecoveryMode.OPERATOR_TRANSPORT,
        )
        for signals in (
            RecoverySignals(operator_transport_available=False),
            RecoverySignals(guest_identity_intact=False),
            RecoverySignals(
                api_available=False,
                operator_transport_available=False,
                guest_identity_intact=False,
            ),
        ):
            with self.subTest(signals=signals):
                self.assertIs(
                    select_recovery_mode(api_scenario, signals),
                    RecoveryMode.REBUILD_REQUIRED,
                )


class RegistrySafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_full_catalog(CATALOG_PATH)
        self.host = {"bytes": BASELINE_BYTES}

    def test_handler_registry_rejects_invalid_incomplete_duplicate_and_missing_entries(
        self,
    ) -> None:
        valid_handler = FakeScenarioHandler(self.host)
        for identity in (
            "",
            "full.s1.v1",
            "full.s18.v1",
            "full.s01.v0",
            "../../full.s01.v1",
        ):
            with self.subTest(identity=identity), self.assertRaises(
                ScenarioContractError
            ):
                HandlerRegistry().register(
                    identity,
                    valid_handler,
                    valid_handler.grader,
                    expected_prepared=expected_prepared_fingerprint,
                    expected_restored=expected_restored_fingerprint,
                )

        mutator_methods = {
            "prepare": lambda *args: None,
            "restore": lambda *args: None,
        }
        for missing in mutator_methods:
            incomplete = SimpleNamespace(
                **{
                    name: method
                    for name, method in mutator_methods.items()
                    if name != missing
                }
            )
            with self.subTest(missing=missing), self.assertRaisesRegex(
                ScenarioContractError, rf"missing {missing}\(\)"
            ):
                HandlerRegistry().register(
                    "full.s01.v1",
                    incomplete,
                    valid_handler.grader,
                    expected_prepared=expected_prepared_fingerprint,
                    expected_restored=expected_restored_fingerprint,
                )
        with self.assertRaisesRegex(ScenarioContractError, r"missing grade\(\)"):
            HandlerRegistry().register(
                "full.s01.v1",
                valid_handler,
                SimpleNamespace(),
                expected_prepared=expected_prepared_fingerprint,
                expected_restored=expected_restored_fingerprint,
            )
        with self.assertRaisesRegex(ScenarioContractError, "structurally read-only"):
            combined = SimpleNamespace(
                prepare=lambda *args: None,
                restore=lambda *args: None,
                grade=lambda *args: None,
            )
            HandlerRegistry().register(
                "full.s01.v1",
                combined,
                combined,
                expected_prepared=expected_prepared_fingerprint,
                expected_restored=expected_restored_fingerprint,
            )

        registry = HandlerRegistry()
        registry.register(
            "full.s01.v1",
            valid_handler,
            valid_handler.grader,
            expected_prepared=expected_prepared_fingerprint,
            expected_restored=expected_restored_fingerprint,
        )
        with self.assertRaisesRegex(ScenarioContractError, "already registered"):
            duplicate = FakeScenarioHandler(self.host)
            registry.register(
                "full.s01.v1",
                duplicate,
                duplicate.grader,
                expected_prepared=expected_prepared_fingerprint,
                expected_restored=expected_restored_fingerprint,
            )
        self.assertIs(registry.resolve(self.catalog.require("01")).mutator, valid_handler)
        with self.assertRaisesRegex(ScenarioLifecycleError, "is not installed"):
            registry.resolve(self.catalog.require("02"))

    def test_reference_registry_is_static_validated_unique_and_fail_closed(self) -> None:
        action = lambda context, timeout: None
        cleanup = lambda context, timeout: None
        for identity, candidate, cleanup_candidate in (
            ("", action, cleanup),
            ("full.s18.v1", action, cleanup),
            ("../../full.s01.v1", action, cleanup),
            ("full.s01.v1", None, cleanup),
            ("full.s01.v1", action, None),
        ):
            with self.subTest(identity=identity), self.assertRaises(
                ScenarioContractError
            ):
                ReferenceSolutionRegistry().register(
                    identity, candidate, cleanup_candidate
                )  # type: ignore[arg-type]

        registry = ReferenceSolutionRegistry()
        registry.register("full.s01.v1", action, cleanup)
        with self.assertRaisesRegex(ScenarioContractError, "already registered"):
            registry.register("full.s01.v1", action, cleanup)
        self.assertEqual(
            registry.resolve(self.catalog.require("01")), (action, cleanup)
        )
        with self.assertRaisesRegex(ScenarioLifecycleError, "is unavailable"):
            registry.resolve(self.catalog.require("02"))

    def test_snapshot_registration_keeps_evaluator_stateless_and_capability_free(self) -> None:
        mutator = FakeScenarioHandler(self.host)
        collector = SimpleNamespace(collect=lambda *_args: None)

        class PureEvaluator:
            __slots__ = ()

            def evaluate(self, snapshot, definition):
                self.assert_snapshot = snapshot  # pragma: no cover
                return definition

        registry = HandlerRegistry()
        registry.register_snapshot(
            "full.s01.v1",
            mutator,
            collector,
            PureEvaluator(),
            expected_prepared=expected_prepared_fingerprint,
            expected_restored=expected_restored_fingerprint,
        )
        registration = registry.resolve(self.catalog.require("01"))
        self.assertIsNone(registration.grader)
        self.assertIs(registration.snapshot_collector, collector)

        class StatefulEvaluator:
            def __init__(self) -> None:
                self.provider = object()

            def evaluate(self, snapshot, definition):
                return snapshot, definition

        with self.assertRaisesRegex(ScenarioContractError, "must be stateless"):
            HandlerRegistry().register_snapshot(
                "full.s02.v1",
                mutator,
                collector,
                StatefulEvaluator(),
                expected_prepared=expected_prepared_fingerprint,
                expected_restored=expected_restored_fingerprint,
            )

        snapshot = GradeSnapshot.from_mapping(
            "01", {"checks": {"one": False}, "lifecycle": "prepared"}
        )
        self.assertEqual(snapshot.payload()["scenario_id"], "01")

        with self.assertRaisesRegex(ScenarioContractError, "not valid JSON"):
            GradeSnapshot("01", '{"scenario_id":"01","schema":1,"value":NaN}')
        with self.assertRaises(ValueError):
            GradeSnapshot.from_mapping("01", {"value": float("inf")})

    def test_reference_execution_is_bounded_and_cleans_up_after_failure(self) -> None:
        events: list[tuple[str, float]] = []

        def action(_context: ScenarioContext, timeout: float) -> None:
            events.append(("action", timeout))
            raise RuntimeError("reference failed")

        def cleanup(_context: ScenarioContext, timeout: float) -> None:
            events.append(("cleanup", timeout))

        with tempfile.TemporaryDirectory() as temporary:
            store = LabStateStore(Path(temporary), namespace="full")
            state = candidate_ready(store, "reference-lab")
            context = ScenarioContext("reference-lab", state)
            registry = ReferenceSolutionRegistry()
            registry.register("full.s01.v1", action, cleanup)
            with self.assertRaisesRegex(RuntimeError, "reference failed"):
                registry.execute(
                    self.catalog.require("01"),
                    context,
                    timeout_seconds=30,
                )
        self.assertEqual(events, [("action", 30.0), ("cleanup", 30.0)])
        with self.assertRaises(ScenarioContractError):
            registry.execute(
                self.catalog.require("01"), context, timeout_seconds=0
            )


class ScenarioEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def make_lab(self, lab_name: str = "scenario-engine-lab"):
        store = LabStateStore(self.root / lab_name, namespace="full")
        state = candidate_ready(store, lab_name)
        host = {"bytes": BASELINE_BYTES}
        attestor = FakeHealthAttestor(host)
        return store, state, host, attestor

    @staticmethod
    def make_engine(
        store: LabStateStore,
        attestor: FakeHealthAttestor,
        handlers_by_id: dict[str, FakeScenarioHandler],
    ) -> ScenarioEngine:
        registry = HandlerRegistry()
        for scenario_id, handler in handlers_by_id.items():
            registry.register(
                f"full.s{scenario_id}.v1",
                handler,
                handler.grader,
                expected_prepared=expected_prepared_fingerprint,
                expected_restored=expected_restored_fingerprint,
            )
        return ScenarioEngine(
            store=store,
            catalog=catalog_with_supported(*handlers_by_id),
            handlers=registry,
            attest_health=attestor,
        )

    def test_planned_scenario_is_refused_before_health_or_state_mutation(self) -> None:
        store, _, host, attestor = self.make_lab("planned-refusal")
        handler = FakeScenarioHandler(host)
        registry = HandlerRegistry()
        registry.register(
            "full.s01.v1",
            handler,
            handler.grader,
            expected_prepared=expected_prepared_fingerprint,
            expected_restored=expected_restored_fingerprint,
        )
        engine = ScenarioEngine(
            store=store,
            catalog=ScenarioCatalog(
                replace(item, support="planned") if item.scenario_id == "09" else item
                for item in load_full_catalog(CATALOG_PATH).definitions
            ),
            handlers=registry,
            attest_health=attestor,
        )
        before = store.state_path("planned-refusal").read_bytes()

        with self.assertRaisesRegex(ScenarioLifecycleError, "planned but not implemented"):
            engine.prepare("planned-refusal", "09")

        self.assertEqual(store.state_path("planned-refusal").read_bytes(), before)
        self.assertEqual(host["bytes"], BASELINE_BYTES)
        self.assertEqual(attestor.calls, [])
        self.assertEqual(handler.events, [])

    def test_supported_lifecycle_validates_prepares_grades_read_only_and_restores_exactly(self) -> None:
        lab_name = "complete-lifecycle"
        store, candidate, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host)
        engine = self.make_engine(store, attestor, {"01": handler})
        baseline_state_bytes = store.state_path(lab_name).read_bytes()
        baseline_health = hashlib.sha256(BASELINE_BYTES).hexdigest()

        prepared = engine.prepare(lab_name, "1")

        self.assertIs(candidate.phase, LabPhase.CANDIDATE_READY)
        self.assertNotEqual(store.state_path(lab_name).read_bytes(), baseline_state_bytes)
        self.assertIs(prepared.phase, LabPhase.SCENARIO_PREPARED)
        self.assertEqual(
            [entry.phase for entry in prepared.journal[-2:]],
            [LabPhase.VALIDATED, LabPhase.SCENARIO_PREPARED],
        )
        self.assertEqual(prepared.health_fingerprint, baseline_health)
        self.assertEqual(prepared.active_scenario.baseline_fingerprint, baseline_health)
        self.assertEqual(prepared.active_scenario.prepared_fingerprint, handler.claims[0])
        self.assertEqual(
            attestor.calls,
            [
                LabPhase.CANDIDATE_READY,
                LabPhase.SCENARIO_PREPARED,
                LabPhase.SCENARIO_PREPARED,
            ],
        )
        self.assertEqual(
            handler.events,
            ["prepare:scenario-prepared:01", "grade:01:01"],
        )

        before_untouched_grade = store.state_path(lab_name).read_bytes()
        untouched = engine.grade(lab_name, "01")
        self.assertIs(untouched.status, GradeStatus.FAIL)
        self.assertEqual(untouched.score, 0.0)
        self.assertEqual(store.state_path(lab_name).read_bytes(), before_untouched_grade)

        host["bytes"] = SOLVED_BYTES
        before_solved_grade = store.state_path(lab_name).read_bytes()
        solved = engine.grade(lab_name, "01")
        self.assertIs(solved.status, GradeStatus.PASS)
        self.assertEqual(solved.score, 100.0)
        self.assertEqual(store.state_path(lab_name).read_bytes(), before_solved_grade)

        active_attempt = prepared.active_scenario.attempt_id
        restored = engine.restore(lab_name, "01")
        persisted = store.load(lab_name)
        self.assertEqual(host["bytes"], BASELINE_BYTES)
        self.assertIs(restored.phase, LabPhase.VALIDATED)
        self.assertEqual(restored, persisted)
        self.assertIsNone(restored.active_scenario)
        self.assertEqual(restored.health_fingerprint, baseline_health)
        self.assertEqual(restored.journal[-1].phase, LabPhase.VALIDATED)
        self.assertEqual(attestor.calls[-1], LabPhase.SCENARIO_PREPARED)
        self.assertIn("restore:scenario-prepared:01", handler.events)
        self.assertNotIn(active_attempt, store.state_path(lab_name).read_text())

    def test_second_active_scenario_is_rejected_without_state_mutation(self) -> None:
        lab_name = "one-active"
        store, _, host, attestor = self.make_lab(lab_name)
        first = FakeScenarioHandler(host)
        second = FakeScenarioHandler(host)
        engine = self.make_engine(store, attestor, {"01": first, "02": second})
        prepared = engine.prepare(lab_name, "01")
        before = store.state_path(lab_name).read_bytes()

        with self.assertRaisesRegex(ScenarioLifecycleError, "does not match"):
            preparation_claim_fingerprint(
                ScenarioContext(lab_name, prepared),
                catalog_with_supported("01", "02").require("02"),
            )
        with self.assertRaisesRegex(ScenarioLifecycleError, "requires validated lab"):
            engine.prepare(lab_name, "02")

        persisted = store.load(lab_name)
        self.assertEqual(store.state_path(lab_name).read_bytes(), before)
        self.assertEqual(persisted.active_scenario, prepared.active_scenario)
        self.assertEqual(second.events, [])

    def test_preparation_fingerprint_is_attempt_bound_and_contract_complete(self) -> None:
        lab_name = "attempt-bound"
        store, candidate, host, attestor = self.make_lab(lab_name)
        baseline = attestor(ScenarioContext(lab_name, candidate))
        validated = store.attest_validated(
            lab_name, candidate.identity.lab_id, baseline
        )
        definition = catalog_with_supported("01").require("01")
        context = ScenarioContext(lab_name, validated)
        first_attempt = str(uuid.uuid4())
        second_attempt = str(uuid.uuid4())

        first = preparation_claim_fingerprint(
            context, definition, attempt_id=first_attempt
        )
        second = preparation_claim_fingerprint(
            context, definition, attempt_id=second_attempt
        )

        self.assertNotEqual(first, second)
        with self.assertRaisesRegex(ScenarioLifecycleError, "requires an attempt ID"):
            preparation_claim_fingerprint(context, definition)

    def test_prepare_mismatch_or_failure_degrades_and_retains_write_ahead_claim(self) -> None:
        cases = (
            ("mismatch", ScenarioLifecycleError, "differs from the write-ahead claim"),
            ("raise", RuntimeError, "fake prepare failed after mutation"),
        )
        for outcome, error_type, message in cases:
            with self.subTest(outcome=outcome):
                lab_name = f"prepare-{outcome}"
                store, _, host, attestor = self.make_lab(lab_name)
                handler = FakeScenarioHandler(host, prepare_outcome=outcome)
                engine = self.make_engine(store, attestor, {"01": handler})

                with self.assertRaisesRegex(error_type, message):
                    engine.prepare(lab_name, "01")

                degraded = store.load(lab_name)
                self.assertIs(degraded.phase, LabPhase.DEGRADED)
                self.assertIsNotNone(degraded.active_scenario)
                self.assertEqual(degraded.active_scenario.scenario_id, "01")
                self.assertRegex(
                    degraded.active_scenario.prepared_fingerprint, r"^[0-9a-f]{64}$"
                )
                self.assertEqual(
                    [entry.phase for entry in degraded.journal[-2:]],
                    [LabPhase.SCENARIO_PREPARED, LabPhase.DEGRADED],
                )
                self.assertEqual(host["bytes"], UNSOLVED_BYTES)

                handler.prepare_outcome = "exact"
                recovered = engine.restore(lab_name, "01")
                self.assertIs(recovered.phase, LabPhase.VALIDATED)
                self.assertIsNone(recovered.active_scenario)
                self.assertEqual(host["bytes"], BASELINE_BYTES)

    def test_prepare_noop_cannot_echo_metadata_claim_as_live_attestation(self) -> None:
        lab_name = "prepare-noop"
        store, _, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host, prepare_outcome="noop")
        engine = self.make_engine(store, attestor, {"01": handler})

        with self.assertRaisesRegex(
            ScenarioLifecycleError, "differs from the write-ahead claim"
        ):
            engine.prepare(lab_name, "01")

        degraded = store.load(lab_name)
        self.assertIs(degraded.phase, LabPhase.DEGRADED)
        self.assertEqual(host["bytes"], BASELINE_BYTES)

    def test_restore_health_mismatch_degrades_and_retains_active_claim(self) -> None:
        lab_name = "restore-health-mismatch"
        store, _, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host, restore_outcome="mismatch")
        engine = self.make_engine(store, attestor, {"01": handler})
        prepared = engine.prepare(lab_name, "01")
        active = prepared.active_scenario

        with self.assertRaisesRegex(
            ScenarioLifecycleError, "differs from recovery contract"
        ):
            engine.restore(lab_name, "01")

        degraded = store.load(lab_name)
        self.assertIs(degraded.phase, LabPhase.DEGRADED)
        self.assertEqual(degraded.active_scenario, active)
        self.assertEqual(degraded.health_fingerprint, active.baseline_fingerprint)
        self.assertNotEqual(host["bytes"], BASELINE_BYTES)
        self.assertEqual(degraded.journal[-1].phase, LabPhase.DEGRADED)

        handler.restore_outcome = "exact"
        recovered = engine.restore(lab_name, "01")
        self.assertIs(recovered.phase, LabPhase.VALIDATED)
        self.assertIsNone(recovered.active_scenario)
        self.assertEqual(host["bytes"], BASELINE_BYTES)

    def test_scenario_residue_blocks_restore_even_when_generic_health_matches(self) -> None:
        lab_name = "restore-residue"
        store, _, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host, restore_outcome="residue")
        engine = self.make_engine(store, attestor, {"01": handler})
        engine.prepare(lab_name, "01")

        with self.assertRaisesRegex(
            ScenarioLifecycleError, "differs from recovery contract"
        ):
            engine.restore(lab_name, "01")

        degraded = store.load(lab_name)
        self.assertIs(degraded.phase, LabPhase.DEGRADED)
        self.assertEqual(host["bytes"], BASELINE_BYTES)

    def test_grade_receives_minimal_context_and_detects_live_mutation(self) -> None:
        lab_name = "read-only-grade"
        store, _, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host)
        engine = self.make_engine(store, attestor, {"01": handler})
        engine.prepare(lab_name, "01")
        handler.grader.grade_mutates = True

        with self.assertRaisesRegex(ScenarioLifecycleError, "changed live lab state"):
            engine.grade(lab_name, "01")

        degraded = store.load(lab_name)
        self.assertIs(degraded.phase, LabPhase.DEGRADED)
        self.assertIsNotNone(degraded.active_scenario)
        self.assertNotEqual(host["bytes"], UNSOLVED_BYTES)
        with self.assertRaisesRegex(ScenarioLifecycleError, "not the active prepared"):
            engine.grade(lab_name, "01")

    def test_grade_exception_still_runs_post_probe_integrity_attestation(self) -> None:
        lab_name = "grade-exception-integrity"
        store, _, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host)
        engine = self.make_engine(store, attestor, {"01": handler})
        engine.prepare(lab_name, "01")
        handler.grader.grade_mutates = True
        handler.grader.grade_raises = True

        with self.assertRaisesRegex(ScenarioLifecycleError, "changed live lab state"):
            engine.grade(lab_name, "01")

        self.assertEqual(attestor.calls[-2:], [LabPhase.SCENARIO_PREPARED] * 2)

    def test_grade_cannot_use_a_retained_state_store_to_mutate_then_rollback(self) -> None:
        lab_name = "grade-state-capability"
        store, _, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host)
        engine = self.make_engine(store, attestor, {"01": handler})
        engine.prepare(lab_name, "01")
        handler.grader.state_mutator = store

        with self.assertRaisesRegex(
            StateValidationError, "mutation is prohibited during grading"
        ):
            engine.grade(lab_name, "01")

        degraded = store.load(lab_name)
        self.assertIs(degraded.phase, LabPhase.DEGRADED)
        self.assertNotIn(
            LabPhase.CLEANUP_PENDING,
            [entry.phase for entry in degraded.journal],
        )

    def test_grade_cannot_create_persistent_state_for_another_lab(self) -> None:
        lab_name = "grade-state-create"
        store, _, host, attestor = self.make_lab(lab_name)
        handler = FakeScenarioHandler(host)
        engine = self.make_engine(store, attestor, {"01": handler})
        engine.prepare(lab_name, "01")
        handler.grader.state_mutator = store
        handler.grader.claim_during_grade = "forged-lab"

        with self.assertRaisesRegex(
            StateValidationError, "mutation is prohibited during grading"
        ):
            engine.grade(lab_name, "01")

        self.assertFalse(store.state_path("forged-lab").exists())
        self.assertFalse((store.root / "full" / "forged-lab").exists())
        self.assertIs(store.load(lab_name).phase, LabPhase.DEGRADED)


if __name__ == "__main__":
    unittest.main()
