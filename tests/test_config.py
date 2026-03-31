import json
import os
import tempfile
import unittest

from agent_jail.config import load_config


class ConfigTests(unittest.TestCase):
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
