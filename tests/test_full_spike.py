import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOST_PATH = ROOT / "infra" / "spike" / "host.py"


def load_host_module():
    spec = importlib.util.spec_from_file_location("cks_full_spike_host", HOST_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load full-spike host module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FullSpikeContractTests(unittest.TestCase):
    def test_version_manifest_freezes_release_inputs(self):
        manifest = json.loads((ROOT / "infra" / "versions.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["lima"]["version"], "2.1.4")
        self.assertEqual(manifest["kubernetes"]["version"], "1.35.6")
        self.assertEqual(manifest["cilium"]["version"], "1.19.5")
        self.assertEqual(manifest["ubuntu"]["release"], "release-20260615")
        self.assertEqual(
            manifest["ubuntu"]["image_digest"],
            "sha256:cafa1a965b591b7c4184b484ffd8e625981a79d48f9b4ae8a4adf7b4c5ade927",
        )

    def test_every_role_has_a_zero_mount_vz_template(self):
        for role in ("candidate", "control-plane", "worker1", "worker2"):
            with self.subTest(role=role):
                contents = (ROOT / "infra" / "spike" / "lima" / f"{role}.yaml").read_text(encoding="utf-8")
                self.assertIn("vmType: vz", contents)
                self.assertIn("arch: aarch64", contents)
                self.assertIn("mounts: []", contents)
                self.assertIn("user-v2", contents)
                self.assertNotIn("hostSocket", contents)

    def test_lab_ids_and_claims_are_fail_closed(self):
        host = load_host_module()
        for invalid in ("", "-leading", "has space", "has\nnewline", "a" * 49):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                host.validate_lab_id(invalid)
        self.assertEqual(host.validate_lab_id("cks-spike-a1b2c3"), "cks-spike-a1b2c3")

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "claim.json"
            expected = host.instance_names("cks-spike-test")
            claim = host.new_claim("cks-spike-test", expected)
            host.write_claim_exclusive(path, claim)
            with self.assertRaises(FileExistsError):
                host.write_claim_exclusive(path, claim)
            loaded = host.load_owned_claim(path, "cks-spike-test")
            self.assertEqual(loaded["instances"], expected)
            path.write_text('{"managed_by":"other"}\n', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                host.load_owned_claim(path, "cks-spike-test")

    def test_destroy_uses_only_claimed_exact_handles(self):
        host = load_host_module()
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return host.CommandResult(0, "", "")

        claim = host.new_claim("cks-spike-test", host.instance_names("cks-spike-test"))
        claim["created_instances"] = claim["instances"][:2]
        host.destroy_instances(claim, runner=runner)
        self.assertEqual(
            calls,
            [
                ["limactl", "stop", "--force", "cks-spike-test-control-plane"],
                ["limactl", "delete", "--force", "cks-spike-test-control-plane"],
                ["limactl", "stop", "--force", "cks-spike-test-candidate"],
                ["limactl", "delete", "--force", "cks-spike-test-candidate"],
            ],
        )

    def test_diagnostics_are_redacted_and_control_sanitized(self):
        host = load_host_module()
        value = "token=abcdef.0123456789abcdef\x1b[31m\x00"
        sanitized = host.redact(value)
        self.assertNotIn("0123456789abcdef", sanitized)
        self.assertNotIn("\x1b", sanitized)
        self.assertNotIn("\x00", sanitized)


if __name__ == "__main__":
    unittest.main()
