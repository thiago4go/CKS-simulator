import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROL_PLANE = ROOT / "infra" / "provision" / "control-plane"
WORKER = ROOT / "infra" / "provision" / "worker"


def script(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class ClusterProvisionContractTests(unittest.TestCase):
    def run_control_plane_library(self, body: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'source "{CONTROL_PLANE / "lib.sh"}"; {body}',
            ],
            text=True,
            capture_output=True,
        )

    def test_all_cluster_operations_are_static_strict_shell(self):
        paths = (
            CONTROL_PLANE / "bootstrap.sh",
            CONTROL_PLANE / "join-material.sh",
            CONTROL_PLANE / "revoke-token.sh",
            CONTROL_PLANE / "health.sh",
            WORKER / "join.sh",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(path.is_file())
                contents = script(path)
                self.assertTrue(contents.startswith("#!/usr/bin/env bash\n"))
                self.assertIn("set -Eeuo pipefail", contents)
                self.assertIn("IFS=$'\\n\\t'", contents)
                self.assertIn("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", contents)
                self.assertNotIn("eval ", contents)
                subprocess.run(["/bin/bash", "-n", str(path)], check=True)

    def test_control_plane_init_is_pinned_explicit_and_replay_verifies_reality(self):
        contents = script(CONTROL_PLANE / "bootstrap.sh")
        self.assertIn('readonly REQUIRED_KUBERNETES_VERSION="v1.35.6"', contents)
        for configuration in (
            'kubernetesVersion: "${KUBERNETES_VERSION}"',
            'advertiseAddress: "${NODE_IP}"',
            'controlPlaneEndpoint: "${CONTROL_PLANE_ENDPOINT}"',
            'podSubnet: "${POD_CIDR}"',
            'serviceSubnet: "${SERVICE_CIDR}"',
            'criSocket: "${CRI_SOCKET}"',
            'name: "${NODE_NAME}"',
        ):
            self.assertIn(configuration, contents)
        self.assertIn("kubeadm init --config /dev/stdin --skip-token-print", contents)
        self.assertIn("bootstrapTokens:", contents)
        self.assertIn('ttl: "15m"', contents)
        self.assertIn("trap cleanup_initial_token_on_exit EXIT", contents)
        self.assertIn('kubeadm token delete "$token_id"', contents)
        self.assertNotIn("--token", contents)
        self.assertIn('validate_control_plane_endpoint "$NODE_NAME"', contents)
        self.assertIn('validate_networks "$NODE_IP" "$POD_CIDR" "$SERVICE_CIDR"', contents)
        self.assertIn("verify_existing_control_plane", contents)
        self.assertIn("-L /etc/kubernetes/admin.conf", contents)
        self.assertIn("kubeadm certs check-expiration", contents)
        self.assertIn("existing API server endpoint mismatch", contents)
        self.assertIn("existing control-plane network configuration mismatch", contents)
        self.assertIn('f"--cluster-cidr={sys.argv[2]}"', contents)
        self.assertIn('f"--service-cluster-ip-range={sys.argv[3]}"', contents)
        self.assertNotIn("existing kubeadm control plane detected; skipping init", contents)
        verify_body = contents.split("verify_existing_control_plane() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertLess(verify_body.index("wait_for_readyz"), verify_body.index("kubectl get node"))

    def test_endpoint_and_cidrs_fail_closed_offline(self):
        valid = self.run_control_plane_library(
            'CONTROL_PLANE_ENDPOINT=cks-0123456789abcdef-control-plane:6443; '
            'validate_control_plane_endpoint cks-0123456789abcdef-control-plane; '
            'validate_networks 192.168.105.10 10.244.0.0/16 10.96.0.0/12'
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)

        wrong_endpoint = self.run_control_plane_library(
            'CONTROL_PLANE_ENDPOINT=other:6443; '
            'validate_control_plane_endpoint cks-0123456789abcdef-control-plane'
        )
        self.assertNotEqual(wrong_endpoint.returncode, 0)
        self.assertIn("exact stable hostname", wrong_endpoint.stderr)

        overlap = self.run_control_plane_library(
            "validate_networks 192.168.105.10 10.96.0.0/12 10.96.0.0/16"
        )
        self.assertNotEqual(overlap.returncode, 0)
        self.assertIn("overlapping", overlap.stderr)

    def test_cilium_uses_only_the_verified_pinned_local_chart(self):
        contents = script(CONTROL_PLANE / "bootstrap.sh")
        self.assertIn('readonly REQUIRED_CILIUM_VERSION="1.19.5"', contents)
        self.assertIn('readonly REQUIRED_CILIUM_CLI_VERSION="v0.19.5"', contents)
        self.assertIn('readonly REQUIRED_CILIUM_CLI_SHA256="5498defa', contents)
        self.assertIn("install_verified_cilium_cli", contents)
        self.assertIn('mv -fT -- "$temporary" /usr/local/bin/cilium', contents)
        self.assertIn('download_verified_chart "$CILIUM_CHART_URL" "$CILIUM_CHART_SHA256"', contents)
        self.assertIn('sha256sum --check --status', contents)
        self.assertIn('--chart-directory "$chart_dir"', contents)
        self.assertIn("cilium upgrade", contents)
        self.assertIn("-l owner=helm,name=cilium", contents)
        self.assertIn("Cilium resources exist without an owned Helm release", contents)
        self.assertIn("sh\\.helm\\.release\\.v1\\.cilium\\.v", contents)
        self.assertIn('if [[ ! -s "$release_records" ]]', contents)
        self.assertIn("Cilium Helm release history contains an unexpected record", contents)
        self.assertNotRegex(contents, r"cilium install(?:.|\n)*--repository")
        self.assertIn("assert_exactly_one_cni", contents)
        self.assertIn("rollout status daemonset/cilium --timeout=10m", contents)
        self.assertIn("rollout status daemonset/cilium-envoy --timeout=10m", contents)
        self.assertIn("cilium status --wait --wait-duration 10m", contents)
        self.assertIn("Cilium IPAM mode does not match", contents)
        self.assertIn("revoke_all_bootstrap_tokens", contents)
        self.assertIn('eq .type "bootstrap.kubernetes.io/token"', contents)
        # CoreDNS normally cannot schedule until a worker joins because the
        # sole control-plane node is tainted. Its rollout belongs in the final
        # three-node health gate, not the pre-join bootstrap gate.
        self.assertNotIn("rollout status deployment/coredns --timeout=10m", contents)
        self.assertIn(
            "rollout status deployment/coredns --timeout=10m",
            script(CONTROL_PLANE / "health.sh"),
        )

    def test_join_material_is_ephemeral_bounded_and_deterministic(self):
        contents = script(CONTROL_PLANE / "join-material.sh")
        self.assertIn("kubeadm token create --ttl 15m", contents)
        self.assertIn("DISCOVERY_TOKEN_CA_CERT_HASH=sha256:", contents)
        self.assertIn("readonly CRI_SOCKET='unix:///run/containerd/containerd.sock'", contents)
        self.assertIn('"CRI_SOCKET=${CRI_SOCKET}"', contents)
        self.assertIn("CONTROL_PLANE_ENDPOINT=", contents)
        self.assertIn("join material exceeded", contents)
        self.assertNotIn("JOIN_MANIFEST_PATH", contents)
        self.assertNotIn("install -D", contents)

    def test_token_revocation_is_a_separate_bounded_stdin_operation(self):
        contents = script(CONTROL_PLANE / "revoke-token.sh")
        self.assertIn("sys.stdin.buffer.read(65)", contents)
        self.assertIn("one exact newline-terminated token", contents)
        self.assertIn('re.fullmatch(rb"[a-z0-9]{6}\\.[a-z0-9]{16}\\n", payload)', contents)
        self.assertIn('token_id=${token%%.*}', contents)
        self.assertIn("unset token", contents)
        self.assertIn('kubeadm token delete "$token_id"', contents)
        self.assertNotIn('kubeadm token delete "$token"', contents)
        self.assertNotIn("$1", contents)

    def test_worker_existing_kubelet_config_is_verified_not_blindly_skipped(self):
        contents = script(WORKER / "join.sh")
        self.assertIn("verify_existing_membership", contents)
        self.assertIn("existing kubelet API endpoint mismatch", contents)
        self.assertIn("existing kubelet cluster CA hash mismatch", contents)
        self.assertIn("existing kubelet node identity mismatch", contents)
        self.assertIn("existing kubelet client certificate path mismatch", contents)
        self.assertIn("kubelet-client-current.pem", contents)
        self.assertIn("subject=CN=system:node:${NODE_NAME},O=system:nodes", contents)
        self.assertNotIn("contexts[0].context.user", contents)
        self.assertIn("existing API node IP mismatch", contents)
        self.assertIn("get node \"$NODE_NAME\"", contents)
        self.assertIn("-L /etc/kubernetes/kubelet.conf", contents)
        self.assertIn("if (verify_existing_membership)", contents)
        self.assertNotIn("skipping join", contents)
        self.assertIn("sys.stdin.buffer.read(513)", contents)
        self.assertIn("kubeadm join --config /dev/stdin", contents)
        self.assertIn("apiVersion: kubeadm.k8s.io/v1beta4", contents)
        self.assertIn('token: "${BOOTSTRAP_TOKEN}"', contents)
        self.assertIn('- "${DISCOVERY_TOKEN_CA_CERT_HASH}"', contents)
        self.assertIn('criSocket: "${CRI_SOCKET}"', contents)
        self.assertIn('name: "${NODE_NAME}"', contents)
        self.assertNotIn('--token "$BOOTSTRAP_TOKEN"', contents)
        self.assertNotIn('--discovery-token-ca-cert-hash', contents)
        self.assertNotIn("export BOOTSTRAP_TOKEN", contents)
        self.assertNotIn("export DISCOVERY_TOKEN_CA_CERT_HASH", contents)
        self.assertIn("unset BOOTSTRAP_TOKEN", contents)

    @staticmethod
    def _write_executable(path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def test_worker_join_behavior_keeps_secrets_only_in_kubeadm_config_stdin(self):
        token = "abcdef.0123456789abcdef"
        ca_hash = f"sha256:{'a' * 64}"
        endpoint = "cks-0123456789abcdef-control-plane:6443"
        node_name = "cks-0123456789abcdef-worker1"
        node_ip = "192.0.2.21"
        material = (
            f"CONTROL_PLANE_ENDPOINT={endpoint}\n"
            f"BOOTSTRAP_TOKEN={token}\n"
            f"DISCOVERY_TOKEN_CA_CERT_HASH={ca_hash}\n"
            "CRI_SOCKET=unix:///run/containerd/containerd.sock\n"
        ).encode("ascii")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            argv_capture = root / "argv"
            env_capture = root / "environment"
            stdin_capture = root / "stdin"
            self._write_executable(fake_bin / "hostname", f"#!/bin/sh\nprintf '%s\\n' '{node_name}'\n")
            self._write_executable(
                fake_bin / "ip",
                f"#!/bin/sh\nprintf '%s\\n' '2: eth0 inet {node_ip}/24 scope global eth0'\n",
            )
            self._write_executable(
                fake_bin / "kubeadm",
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" >\"$CAPTURE_ARGV\"\n"
                "env >\"$CAPTURE_ENV\"\n"
                "cat >\"$CAPTURE_STDIN\"\n"
                "exit 42\n",
            )
            worker = root / "join.sh"
            contents = script(WORKER / "join.sh")
            contents = contents.replace(
                "[[ ${EUID} -eq 0 ]] || die \"must run as root\"",
                ": # root requirement exercised by production",
            )
            contents = contents.replace(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                f"PATH={fake_bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            contents = contents.replace("/etc/kubernetes/kubelet.conf", str(root / "kubelet.conf"))
            self._write_executable(worker, contents)
            environment = {
                **os.environ,
                "NODE_NAME": node_name,
                "NODE_IP": node_ip,
                "BOOTSTRAP_TOKEN": "inherited.must-be-cleared",
                "DISCOVERY_TOKEN_CA_CERT_HASH": "inherited-must-be-cleared",
                "CAPTURE_ARGV": str(argv_capture),
                "CAPTURE_ENV": str(env_capture),
                "CAPTURE_STDIN": str(stdin_capture),
            }
            completed = subprocess.run(
                ["/bin/bash", str(worker)],
                input=material,
                capture_output=True,
                env=environment,
            )

            self.assertNotEqual(completed.returncode, 0)
            argv = argv_capture.read_text(encoding="utf-8")
            child_environment = env_capture.read_text(encoding="utf-8")
            config = stdin_capture.read_text(encoding="utf-8")
            self.assertEqual(argv.splitlines(), ["join", "--config", "/dev/stdin"])
            self.assertNotIn(token, argv)
            self.assertNotIn(ca_hash, argv)
            self.assertNotIn(token, child_environment)
            self.assertNotIn(ca_hash, child_environment)
            self.assertIn("apiVersion: kubeadm.k8s.io/v1beta4", config)
            self.assertIn(f'token: "{token}"', config)
            self.assertIn(f'- "{ca_hash}"', config)

    def test_worker_join_rejects_extra_or_trailing_records_before_kubeadm(self):
        valid = (
            "CONTROL_PLANE_ENDPOINT=cks-0123456789abcdef-control-plane:6443\n"
            "BOOTSTRAP_TOKEN=abcdef.0123456789abcdef\n"
            f"DISCOVERY_TOKEN_CA_CERT_HASH=sha256:{'a' * 64}\n"
            "CRI_SOCKET=unix:///run/containerd/containerd.sock\n"
        )
        invalid_payloads = (
            valid + "EXTRA=value\n",
            valid + "\nignored",
            valid.rstrip("\n"),
            valid.replace("\n", "\r\n"),
            valid.encode("ascii") + b"\x00",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            kubeadm_marker = root / "kubeadm-called"
            self._write_executable(
                fake_bin / "kubeadm",
                "#!/bin/sh\nprintf called >\"$KUBEADM_MARKER\"\n",
            )
            worker = root / "join.sh"
            contents = script(WORKER / "join.sh")
            contents = contents.replace(
                "[[ ${EUID} -eq 0 ]] || die \"must run as root\"",
                ": # root requirement exercised by production",
            )
            contents = contents.replace(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                f"PATH={fake_bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            self._write_executable(worker, contents)
            environment = {
                **os.environ,
                "NODE_NAME": "worker1",
                "NODE_IP": "192.0.2.21",
                "KUBEADM_MARKER": str(kubeadm_marker),
            }
            for payload in invalid_payloads:
                with self.subTest(payload=repr(payload)[-80:]):
                    kubeadm_marker.unlink(missing_ok=True)
                    completed = subprocess.run(
                        ["/bin/bash", str(worker)],
                        input=payload.encode("ascii") if isinstance(payload, str) else payload,
                        capture_output=True,
                        env=environment,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertFalse(kubeadm_marker.exists())

    def test_revoke_token_behavior_rejects_every_trailing_byte_or_line(self):
        token = "abcdef.0123456789abcdef"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            scripts = root / "control-plane"
            fake_bin.mkdir()
            scripts.mkdir()
            capture = root / "argv"
            self._write_executable(
                fake_bin / "kubeadm",
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$CAPTURE_ARGV\"\n",
            )
            (scripts / "lib.sh").write_bytes((CONTROL_PLANE / "lib.sh").read_bytes())
            contents = script(CONTROL_PLANE / "revoke-token.sh")
            contents = contents.replace("require_root", ": # root requirement exercised by production", 1)
            contents = contents.replace(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                f"PATH={fake_bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            revoke = scripts / "revoke-token.sh"
            self._write_executable(revoke, contents)
            environment = {**os.environ, "CAPTURE_ARGV": str(capture)}

            accepted = subprocess.run(
                ["/bin/bash", str(revoke)],
                input=f"{token}\n".encode("ascii"),
                capture_output=True,
                env=environment,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
            revoke_argv = capture.read_text(encoding="utf-8")
            self.assertEqual(revoke_argv.splitlines(), ["token", "delete", "abcdef"])
            self.assertNotIn(token, revoke_argv)

            for payload in (
                f"{token}\n\nignored",
                f"{token}\nignored",
                token,
                f"{token}\r\n",
                f"{token}\nX",
            ):
                with self.subTest(payload=repr(payload)):
                    capture.unlink(missing_ok=True)
                    rejected = subprocess.run(
                        ["/bin/bash", str(revoke)],
                        input=payload.encode("ascii"),
                        capture_output=True,
                        env=environment,
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse(capture.exists())

    def test_health_gate_requires_exact_nodes_ips_cilium_envoy_and_coredns(self):
        contents = script(CONTROL_PLANE / "health.sh")
        for name in (
            "CONTROL_PLANE_NAME",
            "CONTROL_PLANE_IP",
            "WORKER1_NAME",
            "WORKER1_IP",
            "WORKER2_NAME",
            "WORKER2_IP",
        ):
            self.assertIn(name, contents)
        self.assertIn("kubectl wait", contents)
        self.assertIn('"node/${CONTROL_PLANE_NAME}"', contents)
        self.assertIn('"node/${WORKER1_NAME}"', contents)
        self.assertIn('"node/${WORKER2_NAME}"', contents)
        self.assertIn("--timeout=10m", contents)
        self.assertIn("exactly three expected nodes", contents)
        self.assertIn('condition.get("type") == "Ready"', contents)
        self.assertIn('address.get("type") == "InternalIP"', contents)
        self.assertIn("rollout status daemonset/cilium --timeout=10m", contents)
        self.assertIn("rollout status daemonset/cilium-envoy --timeout=10m", contents)
        self.assertIn("rollout status deployment/coredns --timeout=10m", contents)
        self.assertIn("assert_exactly_one_cni", contents)

    def test_cluster_scripts_exclude_candidate_and_later_capability_tools(self):
        combined = "\n".join(
            script(path)
            for path in (*CONTROL_PLANE.glob("*.sh"), *WORKER.glob("*.sh"))
        ).lower()
        for excluded in ("falco", "trivy", "kube-bench", "runsc", "gvisor", "docker install"):
            self.assertNotIn(excluded, combined)


if __name__ == "__main__":
    unittest.main()
