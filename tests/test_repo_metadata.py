import os
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))


class RepoMetadataTests(unittest.TestCase):
    def test_open_source_metadata_files_exist(self):
        expected = [
            ".github/settings.yml",
            ".github/workflows/ci.yml",
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/feature_request.md",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/pull_request_template.md",
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
            "LICENSE",
            "SECURITY.md",
            "SUPPORT.md",
        ]
        for relpath in expected:
            self.assertTrue(os.path.exists(os.path.join(ROOT, relpath)), relpath)
