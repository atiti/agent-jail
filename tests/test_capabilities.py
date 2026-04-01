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

    def test_configured_filesystem_roots_merge_with_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = os.path.join(tmp, "workspace")
            project = os.path.join(tmp, "build", "agent-jail")
            docs_root = os.path.join(tmp, "build")
            os.makedirs(workspace)
            os.makedirs(project)
            result = resolve_session_capabilities(
                projects=[project],
                allow_write=[project],
                read_only_roots=[docs_root],
                write_roots=[workspace],
            )
        mounts = {item["path"]: item["mode"] for item in result["mounts"]}
        self.assertEqual(mounts[project], "rw")
        self.assertEqual(mounts[docs_root], "ro")
        self.assertEqual(mounts[workspace], "rw")

    def test_configured_write_roots_make_matching_project_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = os.path.join(tmp, "workspace")
            os.makedirs(workspace)
            result = resolve_session_capabilities(
                projects=[workspace],
                allow_write=[],
                write_roots=[workspace],
            )
        self.assertEqual(result["mounts"][0]["mode"], "rw")

    def test_write_roots_are_mounted_even_without_project_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = os.path.join(tmp, "workspace")
            os.makedirs(workspace)
            result = resolve_session_capabilities(
                projects=[],
                allow_write=[],
                write_roots=[workspace],
            )
        self.assertEqual(result["mounts"], [{"path": workspace, "mode": "rw"}])
