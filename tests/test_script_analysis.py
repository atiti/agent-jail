import os
import tempfile
import unittest

from agent_jail.script_analysis import analyze_invocation


class ScriptAnalysisTests(unittest.TestCase):
    def test_unwraps_sandbox_exec_python_c(self):
        result = analyze_invocation(
            [
                "sandbox-exec",
                "-f",
                "/tmp/jail.sb",
                "/opt/homebrew/bin/python3",
                "-c",
                "import subprocess; subprocess.run(['tree', '-L', '2'])",
            ],
            cwd=os.getcwd(),
        )
        self.assertEqual(os.path.basename(result["argv"][0]), "python3")
        self.assertEqual(result["template"], "python read-only subprocess script")
        self.assertEqual(result["risk"], "low")

    def test_analyzes_shell_script_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "inspect.sh")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("ls | head\n")
            result = analyze_invocation(["bash", path], cwd=tmp)
        self.assertEqual(result["template"], "shell read-only script")
        self.assertEqual(result["risk"], "low")
