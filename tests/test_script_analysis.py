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

    def test_tracks_python_variable_based_read_path(self):
        result = analyze_invocation(
            ["python3", "-c", 'p = "/etc/passwd"\nprint(open(p).read())'],
            cwd=os.getcwd(),
        )
        self.assertEqual(result["template"], "python local inspection script")
        self.assertIn("/etc/passwd", result["read_paths"])

    def test_tracks_python_pathlib_read_path(self):
        result = analyze_invocation(
            ["python3", "-c", 'from pathlib import Path\nprint(Path("/etc/passwd").read_text())'],
            cwd=os.getcwd(),
        )
        self.assertIn("/etc/passwd", result["read_paths"])

    def test_tracks_ruby_read_path(self):
        result = analyze_invocation(["ruby", "-e", 'puts File.read("/etc/passwd")'], cwd=os.getcwd())
        self.assertIn("/etc/passwd", result["read_paths"])

    def test_tracks_perl_read_path(self):
        result = analyze_invocation(
            ["perl", "-e", 'open my $f, "<", "/etc/passwd" or die $!; print <$f>'],
            cwd=os.getcwd(),
        )
        self.assertIn("/etc/passwd", result["read_paths"])
