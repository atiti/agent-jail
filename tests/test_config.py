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
