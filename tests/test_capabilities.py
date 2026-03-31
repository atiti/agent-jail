import os
import tempfile
import unittest

from agent_jail.capabilities import resolve_session_capabilities


class CapabilityTests(unittest.TestCase):
    def test_session_projects_expand_to_explicit_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = os.path.join(tmp, "workspace")
            project = os.path.join(tmp, "build", "agent-jail")
            os.makedirs(workspace)
            os.makedirs(project)
            result = resolve_session_capabilities(
                projects=[workspace, project],
                allow_write=[project],
                skills_proxy=True,
                ops_exec=False,
                browser_automation=True,
            )
        self.assertEqual(result["mounts"][0]["path"], workspace)
        self.assertEqual(result["mounts"][0]["mode"], "ro")
        self.assertEqual(result["mounts"][1]["path"], project)
        self.assertEqual(result["mounts"][1]["mode"], "rw")

    def test_secret_bearing_skills_default_to_proxy_mode(self):
        result = resolve_session_capabilities(projects=[], allow_write=[])
        self.assertTrue(result["capabilities"]["skills_proxy"])
        self.assertFalse(result["capabilities"]["direct_secret_env"])
