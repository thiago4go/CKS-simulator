from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "infra" / "provision" / "render_u5_manifests.py"
SOURCE = ROOT / "infra" / "versions.json"
TOOLS = ROOT / "infra" / "provision" / "tools" / "versions.env"
CANDIDATE = ROOT / "infra" / "provision" / "candidate" / "tools.env"


def parse_manifest(path: Path) -> dict[str, str]:
    return {
        key: value
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
        for key, value in (line.split("=", 1),)
    }


class U5ManifestRendererTests(unittest.TestCase):
    def run_renderer(
        self, operation: str, source: Path, tools: Path, candidate: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(RENDERER),
                operation,
                "--source",
                str(source),
                "--tools-output",
                str(tools),
                "--candidate-output",
                str(candidate),
            ],
            text=True,
            capture_output=True,
        )

    def test_write_round_trip_check_and_exact_source_mapping(self) -> None:
        source = json.loads(SOURCE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools.env"
            candidate = root / "candidate.env"
            written = self.run_renderer("--write", SOURCE, tools, candidate)
            self.assertEqual(written.returncode, 0, written.stderr)
            self.assertEqual(tools.read_bytes(), TOOLS.read_bytes())
            self.assertEqual(candidate.read_bytes(), CANDIDATE.read_bytes())
            checked = self.run_renderer("--check", SOURCE, tools, candidate)
            self.assertEqual(checked.returncode, 0, checked.stderr)

            expected_tools = {
                "KUBERNETES_VERSION": source["kubernetes"]["version"],
                "HELM_VERSION": source["helm"]["version"],
                "HELM_URL": source["helm"]["url"],
                "HELM_SHA256": source["helm"]["sha256"],
                "HELM_INSTALLED_SHA256": source["helm"]["installed_sha256"],
                "CILIUM_VERSION": source["cilium"]["version"],
                "CILIUM_CLI_VERSION": source["cilium"]["cli_version"],
                "CILIUM_CLI_URL": source["cilium"]["cli_url"],
                "CILIUM_CLI_SHA256": source["cilium"]["cli_sha256"],
                "CILIUM_CLI_INSTALLED_SHA256": source["cilium"]["cli_installed_sha256"],
                "ETCDCTL_VERSION": source["etcdctl"]["version"],
                "ETCDCTL_URL": source["etcdctl"]["url"],
                "ETCDCTL_SHA256": source["etcdctl"]["sha256"],
                "ETCDCTL_INSTALLED_SHA256": source["etcdctl"]["installed_sha256"],
                "KUBE_BENCH_VERSION": source["kube_bench"]["version"],
                "KUBE_BENCH_MODE": source["kube_bench"]["mode"],
                "KUBE_BENCH_URL": source["kube_bench"]["url"],
                "KUBE_BENCH_SHA256": source["kube_bench"]["sha256"],
                "KUBE_BENCH_BINARY_INSTALLED_SHA256": source["kube_bench"]["binary_installed_sha256"],
                "KUBE_BENCH_CONFIG_INSTALLED_SHA256": source["kube_bench"]["config_installed_sha256"],
                "GVISOR_VERSION": source["gvisor"]["version"],
                "GVISOR_PLATFORM": source["gvisor"]["platform"],
                "GVISOR_RUNSC_URL": source["gvisor"]["runsc_url"],
                "GVISOR_RUNSC_SHA512": source["gvisor"]["runsc_sha512"],
                "GVISOR_RUNSC_INSTALLED_SHA256": source["gvisor"]["runsc_installed_sha256"],
                "GVISOR_SHIM_URL": source["gvisor"]["shim_url"],
                "GVISOR_SHIM_SHA512": source["gvisor"]["shim_sha512"],
                "GVISOR_SHIM_INSTALLED_SHA256": source["gvisor"]["shim_installed_sha256"],
                "DOCKER_VERSION": source["docker"]["version"],
                "DOCKER_URL": source["docker"]["url"],
                "DOCKER_SHA256": source["docker"]["sha256"],
                "DOCKER_INSTALLED_SHA256": source["docker"]["installed_sha256"],
                "FALCO_VERSION": source["falco"]["version"],
                "FALCO_CHART_VERSION": source["falco"]["chart_version"],
                "FALCO_IMAGE": source["falco"]["image"],
                "FALCO_CHART_URL": source["falco"]["chart_url"],
                "FALCO_CHART_SHA256": source["falco"]["chart_sha256"],
                "FALCO_CHART_INSTALLED_SHA256": source["falco"]["chart_installed_sha256"],
                "INGRESS_NGINX_VERSION": source["ingress_nginx"]["version"],
                "INGRESS_NGINX_CHART_VERSION": source["ingress_nginx"]["chart_version"],
                "INGRESS_NGINX_CHART_URL": source["ingress_nginx"]["chart_url"],
                "INGRESS_NGINX_CHART_SHA256": source["ingress_nginx"]["chart_sha256"],
                "INGRESS_NGINX_CHART_INSTALLED_SHA256": source["ingress_nginx"]["chart_installed_sha256"],
                "BUSYBOX_IMAGE": source["workload_images"]["busybox"],
                "AGNHOST_IMAGE": source["workload_images"]["agnhost"],
            }
            expected_candidate = {
                "KUBECTL_VERSION": source["kubernetes"]["version"],
                "KUBECTL_URL": source["kubernetes"]["kubectl_url"],
                "KUBECTL_SHA256": source["kubernetes"]["kubectl_sha256"],
                "TRIVY_VERSION": source["trivy"]["version"],
                "TRIVY_URL": source["trivy"]["url"],
                "TRIVY_SHA256": source["trivy"]["sha256"],
                "TRIVY_DB_IMAGE": source["trivy"]["db_image"],
                "YQ_VERSION": source["yq"]["version"],
                "YQ_URL": source["yq"]["url"],
                "YQ_SHA256": source["yq"]["sha256"],
            }
            digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
            observed_tools = parse_manifest(tools)
            observed_candidate = parse_manifest(candidate)
            self.assertEqual(observed_tools.pop("SOURCE_SHA256"), digest)
            self.assertEqual(observed_candidate.pop("SOURCE_SHA256"), digest)
            self.assertEqual(observed_tools, expected_tools)
            self.assertEqual(observed_candidate, expected_candidate)

    def test_check_reports_each_stale_or_missing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools.env"
            candidate = root / "candidate.env"
            self.assertEqual(
                self.run_renderer("--write", SOURCE, tools, candidate).returncode, 0
            )
            tools.write_text(tools.read_text(encoding="utf-8") + "STALE=1\n", encoding="utf-8")
            stale = self.run_renderer("--check", SOURCE, tools, candidate)
            self.assertEqual(stale.returncode, 1)
            self.assertIn(str(tools), stale.stderr)
            self.assertNotIn(str(candidate), stale.stderr)

            self.assertEqual(
                self.run_renderer("--write", SOURCE, tools, candidate).returncode, 0
            )
            candidate.unlink()
            missing = self.run_renderer("--check", SOURCE, tools, candidate)
            self.assertEqual(missing.returncode, 1)
            self.assertIn(str(candidate), missing.stderr)

    def test_invalid_schema_and_checksum_fail_closed(self) -> None:
        original = json.loads(SOURCE.read_text(encoding="utf-8"))
        for mutation, diagnostic in (
            (lambda value: value.update(schema=2), "unsupported"),
            (
                lambda value: value["trivy"].update(sha256="not-a-checksum"),
                "invalid",
            ),
        ):
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "versions.json"
                value = json.loads(json.dumps(original))
                mutation(value)
                source.write_text(json.dumps(value), encoding="utf-8")
                result = self.run_renderer(
                    "--write", source, root / "tools.env", root / "candidate.env"
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(diagnostic, result.stderr)

    def test_every_malformed_source_guard_fails_without_outputs(self) -> None:
        original = json.loads(SOURCE.read_text(encoding="utf-8"))

        def encoded(mutation) -> bytes:
            value = json.loads(json.dumps(original))
            mutation(value)
            return json.dumps(value).encode("utf-8")

        cases = (
            ("invalid-utf8", b"\xff\xfe", "UTF-8 JSON"),
            ("invalid-json", b'{"schema": 1', "UTF-8 JSON"),
            ("non-object-section", encoded(lambda value: value.update(helm=[])), "helm must be an object"),
            ("missing-field", encoded(lambda value: value["helm"].pop("url")), "helm.url"),
            ("empty-field", encoded(lambda value: value["helm"].update(url="")), "helm.url"),
            ("multiline-field", encoded(lambda value: value["helm"].update(url="a\nb")), "helm.url"),
            (
                "invalid-sha512",
                encoded(lambda value: value["gvisor"].update(runsc_sha512="not-a-sha512")),
                "gvisor.runsc_sha512",
            ),
        )
        for label, payload, diagnostic in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "versions.json"
                tools = root / "tools.env"
                candidate = root / "candidate.env"
                source.write_bytes(payload)
                result = self.run_renderer("--write", source, tools, candidate)
                self.assertEqual(result.returncode, 2)
                self.assertIn(diagnostic, result.stderr)
                self.assertLessEqual(len(result.stderr), 300)
                self.assertFalse(tools.exists())
                self.assertFalse(candidate.exists())


if __name__ == "__main__":
    unittest.main()
