import json
import os
import tempfile
import unittest

from agent_jail.config import load_config


class ConfigTests(unittest.TestCase):
    def test_load_config_defaults_run_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(os.path.join(tmp, "missing.json"))
        self.assertEqual(
            config["defaults"]["run"],
            {
                "read_only_roots": [],
                "write_roots": [],
                "home_mounts": [".overwatchr"],
                "git_ssh_hosts": [],
                "proxy": True,
                "allow_ops": False,
                "allow_delegates": [],
                "project_mode": "",
            },
        )

    def test_load_config_normalizes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "filesystem": {
                            "read_only_roots": ["~/build", "", 1],
                            "write_roots": ["~/workspace"],
                            "deny_read_patterns": ["~/build/**/.env", None],
                        }
                    },
                    handle,
                )
            config = load_config(config_path)
        self.assertEqual(
            config["filesystem"]["read_only_roots"],
            [os.path.abspath(os.path.expanduser("~/build"))],
        )
        self.assertEqual(
            config["filesystem"]["write_roots"],
            [os.path.abspath(os.path.expanduser("~/workspace"))],
        )
        self.assertEqual(
            config["filesystem"]["deny_read_patterns"],
            [os.path.expanduser("~/build/**/.env")],
        )

    def test_load_config_defaults_filesystem_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(os.path.join(tmp, "missing.json"))
        self.assertEqual(
            config["filesystem"],
            {"read_only_roots": [], "write_roots": [], "deny_read_patterns": []},
        )
        self.assertEqual(config["llm_policy"]["provider"], "")
        self.assertEqual(config["llm_policy"]["endpoint_env"], "AZURE_OPENAI_ENDPOINT")
        self.assertEqual(config["llm_policy"]["api_key_env"], "AZURE_OPENAI_API_KEY")
        self.assertEqual(config["llm_policy"]["deployment_env"], "AZURE_OPENAI_DEPLOYMENT")
        self.assertFalse(config["llm_policy"]["jit_enabled"])
        self.assertEqual(config["llm_policy"]["jit_timeout_ms"], 800)

    def test_load_config_normalizes_llm_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "llm_policy": {
                            "provider": "azure_openai",
                            "model": "gpt-test",
                            "api_version": "2024-10-21",
                            "auto_promote_min_count": 4,
                            "confidence_threshold": 0.9,
                        }
                    },
                    handle,
                )
            config = load_config(config_path)
        self.assertEqual(config["llm_policy"]["provider"], "azure_openai")
        self.assertEqual(config["llm_policy"]["model"], "gpt-test")
        self.assertEqual(config["llm_policy"]["api_version"], "2024-10-21")
        self.assertEqual(config["llm_policy"]["auto_promote_min_count"], 4)
        self.assertEqual(config["llm_policy"]["confidence_threshold"], 0.9)
        self.assertFalse(config["llm_policy"]["jit_enabled"])

    def test_load_config_normalizes_run_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "defaults": {
                            "run": {
                                "read_only_roots": ["~/build", "", 1],
                                "write_roots": ["~/workspace"],
                                "home_mounts": [".config/opencode", "~/Library/Application Support/Pi", "", 1],
                                "git_ssh_hosts": ["github.com", "GitHub.com", "git@gitlab.example.com", "", 1],
                                "proxy": False,
                                "allow_ops": True,
                                "allow_delegates": ["local-secrets", "", 1],
                                "project_mode": "cwd",
                            }
                        }
                    },
                    handle,
                )
            config = load_config(config_path)
        self.assertEqual(
            config["defaults"]["run"]["read_only_roots"],
            [os.path.abspath(os.path.expanduser("~/build"))],
        )
        self.assertEqual(
            config["defaults"]["run"]["write_roots"],
            [os.path.abspath(os.path.expanduser("~/workspace"))],
        )
        self.assertEqual(
            config["defaults"]["run"]["home_mounts"],
            [".config/opencode", "Library/Application Support/Pi", ".overwatchr"],
        )
        self.assertEqual(
            config["defaults"]["run"]["git_ssh_hosts"],
            ["github.com", "gitlab.example.com"],
        )
        self.assertFalse(config["defaults"]["run"]["proxy"])
        self.assertTrue(config["defaults"]["run"]["allow_ops"])
        self.assertEqual(config["defaults"]["run"]["allow_delegates"], ["local-secrets"])
        self.assertEqual(config["defaults"]["run"]["project_mode"], "cwd")

    def test_load_config_normalizes_delegate_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "delegates": [
                            {
                                "name": "ops",
                                "set_env": {"AGE_KEY_FILE": "~/keys.txt", "COUNT": 1},
                            }
                        ]
                    },
                    handle,
                )
            config = load_config(config_path)
        self.assertEqual(config["delegates"][0]["set_env"]["AGE_KEY_FILE"], "~/keys.txt")
        self.assertEqual(config["delegates"][0]["set_env"]["COUNT"], "1")

    def test_load_config_normalizes_secret_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "secrets": {
                            "age_key_file": {
                                "env": {"AGE_KEY_FILE": "~/keys.txt", "COUNT": 1},
                            }
                        },
                        "delegates": [
                            {
                                "name": "ops",
                                "allowed_secrets": ["age_key_file", "", 1],
                            }
                        ],
                    },
                    handle,
                )
            config = load_config(config_path)
        self.assertEqual(
            config["secrets"]["age_key_file"]["env"],
            {"AGE_KEY_FILE": "~/keys.txt", "COUNT": "1"},
        )
        self.assertEqual(config["delegates"][0]["allowed_secrets"], ["age_key_file"])
