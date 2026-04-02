import os
import subprocess
import tempfile
import unittest
from unittest import mock

from agent_jail.reqwest_tls_probe import (
    SYSTEM_ROOT_PEM_NAME,
    build_cargo_env,
    export_system_roots_pem,
    prepare_cert_env,
    render_cargo_toml,
    render_main_rs,
)


class ReqwestTLSProbeTests(unittest.TestCase):
    def test_render_cargo_toml_native_tls_features(self):
        manifest = render_cargo_toml("native-tls")
        self.assertIn('"native-tls"', manifest)
        self.assertIn('"blocking"', manifest)
        self.assertIn('default-features = false', manifest)

    def test_render_cargo_toml_rustls_native_roots_features(self):
        manifest = render_cargo_toml("rustls-native-roots")
        self.assertIn('"rustls-tls-native-roots"', manifest)
        self.assertIn('"blocking"', manifest)

    def test_render_main_rs_mentions_probe_env(self):
        source = render_main_rs()
        self.assertIn("REQWEST_TLS_PROBE_URL", source)
        self.assertIn("SSL_CERT_FILE", source)
        self.assertIn("serde_json", source)

    def test_export_system_roots_pem_writes_file(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            stderr="",
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "agent_jail.reqwest_tls_probe.subprocess.run", return_value=completed
        ):
            pem_path = export_system_roots_pem(tmp)
            self.assertEqual(pem_path, os.path.join(tmp, SYSTEM_ROOT_PEM_NAME))
            with open(pem_path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), completed.stdout)

    def test_prepare_cert_env_path_requires_argument(self):
        with self.assertRaises(ValueError):
            prepare_cert_env("path", None, "/tmp")

    def test_prepare_cert_env_system_roots_uses_export(self):
        with mock.patch(
            "agent_jail.reqwest_tls_probe.export_system_roots_pem",
            return_value="/tmp/system-roots.pem",
        ):
            env = prepare_cert_env("system-roots-pem", None, "/tmp")
        self.assertEqual(env, {"SSL_CERT_FILE": "/tmp/system-roots.pem"})

    def test_build_cargo_env_uses_temp_locations(self):
        env = build_cargo_env("/tmp/probe", "/tmp/probe/crate")
        self.assertEqual(env["CARGO_HOME"], "/tmp/probe/cargo-home")
        self.assertEqual(env["CARGO_TARGET_DIR"], "/tmp/probe/crate/target")


if __name__ == "__main__":
    unittest.main()
