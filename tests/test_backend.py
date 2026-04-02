import json
import os
import tempfile
import unittest
from unittest import mock

from agent_jail.backend import build_command, build_sandbox_exec_profile, choose_backend


class BackendTests(unittest.TestCase):
    def test_linux_prefers_bwrap_when_available(self):
        backend = choose_backend(
            "linux",
            have=lambda name: name == "bwrap",
        )
        self.assertEqual(backend["name"], "bubblewrap")

    def test_linux_falls_back_to_proot(self):
        backend = choose_backend(
            "linux",
            have=lambda name: name == "proot",
        )
        self.assertEqual(backend["name"], "proot")

    def test_explicit_backend_override_wins(self):
        backend = choose_backend("darwin", have=lambda name: False, preferred="host")
        self.assertEqual(backend["name"], "host")

    def test_macos_falls_back_to_host_mode(self):
        backend = choose_backend("darwin", have=lambda name: False)
        self.assertEqual(backend["name"], "host")

    def test_macos_prefers_sandbox_exec_when_available(self):
        backend = choose_backend("darwin", have=lambda name: name == "sandbox-exec")
        self.assertEqual(backend["name"], "sandbox-exec")

    def test_macos_falls_back_to_alcless_when_sandbox_exec_missing(self):
        backend = choose_backend("darwin", have=lambda name: name == "alcless")
        self.assertEqual(backend["name"], "alcless")

    def test_sandbox_exec_profile_includes_writable_paths(self):
        env = {
            "TMPDIR": "/private/tmp/test",
            "AGENT_JAIL_HOME": "/Users/example/.agent-jail",
            "AGENT_JAIL_SESSION_DIR": "/tmp/agent-jail-123",
            "AGENT_JAIL_DENY_READ_PATTERNS": json.dumps(["/Users/example/build/**/.env", "/Users/example/build/**/secrets/**"]),
            "AGENT_JAIL_TTY_PATHS": json.dumps(["/dev/tty", "/dev/ttys001", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd", "/dev/null"]),
            "AGENT_JAIL_MOUNTS": json.dumps(
                [
                    {"path": "/Users/example/project-ro", "mode": "ro"},
                    {"path": "/Users/example/project-rw", "mode": "rw"},
                ]
            ),
            "AGENT_JAIL_AUTH_MOUNTS": json.dumps(
                [{"source": "/Users/example/.codex", "target": "/Users/example/.agent-jail/.codex"}]
            ),
        }
        profile = build_sandbox_exec_profile("/Users/example/cwd", env)
        self.assertIn('(subpath "/Users/example/project-rw")', profile)
        self.assertNotIn('(subpath "/Users/example/project-ro")', profile)
        self.assertIn('(subpath "/Users/example/.codex")', profile)
        self.assertIn('(subpath "/private/tmp/test")', profile)
        self.assertIn('(subpath "/dev/tty")', profile)
        self.assertIn('(subpath "/dev/ttys001")', profile)
        self.assertIn('(subpath "/dev/stdin")', profile)
        self.assertIn('(subpath "/dev/stdout")', profile)
        self.assertIn('(subpath "/dev/stderr")', profile)
        self.assertIn('(subpath "/dev/fd")', profile)
        self.assertIn('(subpath "/dev/null")', profile)
        self.assertIn("(allow network*)", profile)
        self.assertIn('(deny file-read*', profile)
        self.assertIn('/Users/example/build/.*/', profile)
        self.assertIn('.env', profile)
        self.assertIn('/Users/example/build/', profile)
        self.assertIn('/secrets/', profile)
        self.assertIn('(allow file-ioctl', profile)
        self.assertIn('(regex #"^/dev/tty.*")', profile)
        self.assertIn('(literal "/usr/bin/ssh")', profile)
        self.assertIn('(global-name "com.apple.SystemConfiguration.configd")', profile)
        self.assertIn('(global-name "com.apple.notifyd")', profile)
        self.assertIn('(global-name "com.apple.SecurityServer")', profile)

    @mock.patch("agent_jail.backend.platform.system", return_value="Darwin")
    @mock.patch("agent_jail.backend.os.path.realpath")
    def test_sandbox_exec_profile_includes_darwin_realpath_aliases(self, mock_realpath, _mock_system):
        aliases = {
            "/tmp": "/private/tmp",
            "/var/folders/example/T": "/private/var/folders/example/T",
            "/var/folders/example/C": "/private/var/folders/example/C",
            "/Users/example/cwd": "/Users/example/cwd",
        }
        mock_realpath.side_effect = lambda path: aliases.get(path, path)
        env = {
            "TMPDIR": "/var/folders/example/T",
            "AGENT_JAIL_SESSION_DIR": "/var/folders/example/C",
            "AGENT_JAIL_MOUNTS": "[]",
            "AGENT_JAIL_AUTH_MOUNTS": "[]",
        }

        profile = build_sandbox_exec_profile("/Users/example/cwd", env)

        self.assertIn('(subpath "/tmp")', profile)
        self.assertIn('(subpath "/private/tmp")', profile)
        self.assertIn('(subpath "/var/folders/example/T")', profile)
        self.assertIn('(subpath "/private/var/folders/example/T")', profile)
        self.assertIn('(subpath "/var/folders/example/C")', profile)
        self.assertIn('(subpath "/private/var/folders/example/C")', profile)

    @mock.patch("agent_jail.backend.platform.system", return_value="Darwin")
    @mock.patch("agent_jail.backend.os.path.realpath", side_effect=lambda path: path)
    def test_sandbox_exec_profile_includes_darwin_cache_dir_for_tmp_paths(self, _mock_realpath, _mock_system):
        env = {
            "TMPDIR": "/var/folders/aa/bb/T",
            "AGENT_JAIL_SESSION_DIR": "/var/folders/aa/bb/T/agent-jail-123",
            "AGENT_JAIL_MOUNTS": "[]",
            "AGENT_JAIL_AUTH_MOUNTS": "[]",
        }

        profile = build_sandbox_exec_profile("/Users/example/cwd", env)

        self.assertIn('(subpath "/var/folders/aa/bb/C")', profile)

    def test_build_command_writes_sandbox_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "AGENT_JAIL_SESSION_DIR": tmp,
                "AGENT_JAIL_HOME": os.path.join(tmp, "home"),
                "AGENT_JAIL_MOUNTS": "[]",
                "AGENT_JAIL_AUTH_MOUNTS": "[]",
            }
            cmd = build_command({"name": "sandbox-exec"}, ["/bin/echo", "ok"], tmp, env)
            self.assertEqual(cmd[:2], ["sandbox-exec", "-f"])
            self.assertTrue(os.path.exists(cmd[2]))
