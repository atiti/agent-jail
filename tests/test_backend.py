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
                [
                    {"source": "/Users/example/.codex", "target": "/Users/example/.agent-jail/.codex"},
                    {
                        "source": "/Users/example/Library/Preferences/com.apple.security.KCN.plist",
                        "target": "/Users/example/.agent-jail/Library/Preferences/com.apple.security.KCN.plist",
                    },
                ]
            ),
        }
        with mock.patch("agent_jail.backend.os.path.exists", return_value=True), mock.patch(
            "agent_jail.backend.os.path.isdir",
            side_effect=lambda path: not path.endswith(".plist"),
        ):
            profile = build_sandbox_exec_profile("/Users/example/cwd", env)
        read_section, _, write_section = profile.partition("(allow file-write*")
        self.assertIn('(subpath "/Users/example/project-rw")', read_section)
        self.assertIn('(subpath "/Users/example/project-ro")', read_section)
        self.assertIn('(subpath "/Users/example/.codex")', read_section)
        self.assertIn('(literal "/Users/example/Library/Preferences/com.apple.security.KCN.plist")', read_section)
        self.assertNotIn('(subpath "/Users/example/Library/Preferences")', read_section)
        self.assertIn('(subpath "/private/tmp/test")', read_section)
        self.assertIn('(subpath "/dev/tty")', write_section)
        self.assertIn('(subpath "/dev/ttys001")', write_section)
        self.assertIn('(subpath "/dev/stdin")', write_section)
        self.assertIn('(subpath "/dev/stdout")', write_section)
        self.assertIn('(subpath "/dev/stderr")', write_section)
        self.assertIn('(subpath "/dev/fd")', write_section)
        self.assertIn('(subpath "/dev/null")', write_section)
        self.assertIn('(subpath "/Users/example/project-rw")', write_section)
        self.assertIn('(literal "/Users/example/Library/Preferences/com.apple.security.KCN.plist")', write_section)
        self.assertNotIn('(subpath "/Users/example/Library/Preferences")', write_section)
        self.assertNotIn('(subpath "/Users/example/project-ro")', write_section)
        self.assertNotIn("(allow network*)", profile)
        self.assertIn('(allow network* (local ip "localhost:*"))', profile)
        self.assertIn('(allow network* (remote ip "localhost:*"))', profile)
        self.assertIn("(allow network-outbound (to unix-socket))", profile)
        self.assertIn('(literal "/private/var/run/ldapi")', profile)
        self.assertIn('(literal "/var/run/ldapi")', profile)
        self.assertIn('(allow ipc-posix-shm-read*', profile)
        self.assertIn('(ipc-posix-name "apple.shm.cfprefsd.daemon")', profile)
        self.assertIn('(ipc-posix-name-prefix "apple.shm.cfprefsd.")', profile)
        self.assertIn('(allow user-preference-read', profile)
        self.assertIn('(preference-domain "kCFPreferencesAnyApplication")', profile)
        self.assertIn('(preference-domain "com.apple.security")', profile)
        self.assertIn('(preference-domain "com.apple.security_common")', profile)
        self.assertIn('(preference-domain "com.apple.security.smartcard")', profile)
        self.assertIn('(preference-domain "securityd")', profile)
        self.assertIn('(allow file-read-metadata', profile)
        self.assertIn('(literal "/Users")', profile)
        self.assertIn('(literal "/Users/example/Library/Preferences")', profile)
        self.assertIn('(literal "/Users/example/.agent-jail/Library/Preferences")', profile)
        self.assertIn('(literal "/private/var/db/mds/system/mdsObject.db")', profile)
        self.assertIn('(deny file-read*', profile)
        self.assertIn('/Users/example/build/.*/', profile)
        self.assertIn('.env', profile)
        self.assertIn('/Users/example/build/', profile)
        self.assertIn('/secrets/', profile)
        self.assertIn("(allow file-map-executable)", profile)
        self.assertIn('(allow file-ioctl', profile)
        self.assertIn('(regex #"^/dev/tty.*")', profile)
        self.assertIn('(literal "/usr/bin/ssh")', profile)
        self.assertIn('(global-name "com.apple.SystemConfiguration.configd")', profile)
        self.assertIn('(global-name "com.apple.notifyd")', profile)
        self.assertIn('(global-name "com.apple.security")', profile)
        self.assertIn('(global-name "com.apple.securityd")', profile)
        self.assertIn('(global-name "com.apple.SecurityServer")', profile)
        self.assertIn('(global-name "com.apple.security.smartcard")', profile)
        self.assertIn('(global-name "com.apple.TrustEvaluationAgent")', profile)
        self.assertIn('(global-name "com.apple.system.opendirectoryd.api")', profile)
        self.assertIn('(import "com.apple.corefoundation.sb")', profile)
        self.assertIn('(corefoundation)', profile)
        self.assertIn("(allow process-exec)", profile)
        self.assertIn('(subpath "/bin")', read_section)
        self.assertIn('(subpath "/usr")', read_section)
        self.assertIn('(subpath "/System")', read_section)
        self.assertIn('(subpath "/private/var/db/mds")', read_section)

    def test_sandbox_exec_profile_does_not_promote_file_mounts_to_home_subpaths(self):
        env = {
            "AGENT_JAIL_HOME": "/tmp/agent-jail/home",
            "AGENT_JAIL_SESSION_DIR": "/tmp/agent-jail",
            "AGENT_JAIL_MOUNTS": "[]",
            "AGENT_JAIL_AUTH_MOUNTS": json.dumps(
                [
                    {
                        "source": "/Users/example/.claude.json",
                        "target": "/tmp/agent-jail/home/.claude.json",
                    }
                ]
            ),
        }

        with mock.patch("agent_jail.backend.os.path.exists", return_value=True), mock.patch(
            "agent_jail.backend.os.path.isdir",
            side_effect=lambda path: not path.endswith(".json"),
        ), mock.patch(
            "agent_jail.backend.os.path.realpath",
            side_effect=lambda path: "/Users/example/.claude.json" if path == "/tmp/agent-jail/home/.claude.json" else path,
        ):
            profile = build_sandbox_exec_profile("/Users/example/cwd", env)

        read_section, _, write_section = profile.partition("(allow file-write*")
        self.assertIn('(literal "/Users/example/.claude.json")', read_section)
        self.assertNotIn('(subpath "/Users/example")', read_section)
        self.assertIn('(literal "/Users/example")', profile)
        self.assertIn('(literal "/tmp/agent-jail/home")', profile)
        self.assertIn('(literal "/Users/example/.claude.json")', write_section)
        self.assertNotIn('(subpath "/Users/example")', write_section)

    def test_sandbox_exec_profile_allows_ssh_exec_when_git_ssh_hosts_are_configured(self):
        env = {
            "AGENT_JAIL_GIT_SSH_HOSTS": json.dumps(["github.com"]),
            "AGENT_JAIL_MOUNTS": "[]",
            "AGENT_JAIL_AUTH_MOUNTS": "[]",
        }

        profile = build_sandbox_exec_profile("/Users/example/cwd", env)

        self.assertNotIn('(literal "/usr/bin/ssh")', profile)

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
