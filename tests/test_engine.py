import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from sast.engine import analyze, scan, gate
from sast.cli import sarif

class EngineTests(unittest.TestCase):
    def rules(self, source):
        return {f["rule"] for f in analyze(source)}

    def test_demo_detects_four_types(self):
        source = Path("examples/vulnerable.py").read_text(encoding="utf-8")
        self.assertEqual(self.rules(source), {"S001", "S002", "S003", "S004"})

    def test_parameterized_sql_is_safe(self):
        self.assertEqual(analyze(Path("examples/safe.py").read_text(encoding="utf-8")), [])

    def test_comments_and_text_are_not_calls(self):
        self.assertEqual(analyze('# eval(user)\ntext = "os.system(user)"'), [])

    def test_aliases(self):
        self.assertIn("S003", self.rules('from os import system as run\nrun(input())'))

    def test_taint_trace(self):
        finding = analyze('x = input()\ny = x\ndb.execute(y)')[0]
        self.assertEqual(finding["rule"], "S004")
        self.assertTrue(any("variável y" in step for step in finding["trace"]))

    def test_overwrite_clears_taint(self):
        self.assertNotIn("S004", self.rules('x = input()\nx = "SELECT 1"\ndb.execute(x)'))

    def test_branch_union(self):
        self.assertIn("S004", self.rules('x = "SELECT 1"\nif flag:\n    x = input()\ndb.execute(x)'))

    def test_both_branches_clean(self):
        self.assertNotIn("S004", self.rules('x = input()\nif flag:\n    x = "SELECT 1"\nelse:\n    x = "SELECT 2"\ndb.execute(x)'))

    def test_augmented_assignment(self):
        self.assertIn("S004", self.rules('x = "SELECT "\nx += input()\ndb.execute(x)'))

    def test_loop_union(self):
        self.assertIn("S004", self.rules('x = "SELECT 1"\nfor item in values:\n    x = input()\ndb.execute(x)'))

    def test_numeric_conversion(self):
        self.assertNotIn("S004", self.rules('x = int(input())\ndb.execute(x)'))

    def test_shell_false(self):
        self.assertNotIn("S003", self.rules('import subprocess\nsubprocess.run(["echo", input()], shell=False)'))

    def test_function_scope(self):
        self.assertNotIn("S004", self.rules('def a():\n    x = input()\ndef b():\n    db.execute(x)'))

    def test_tls_and_pickle_and_hash(self):
        self.assertEqual(self.rules('import pickle, hashlib\npickle.loads(data)\nhashlib.md5(data)\nrequests.get(url, verify=False)'), {"S006", "S007", "S008"})

    def test_path(self):
        self.assertIn("S009", self.rules('open(input())'))

    def test_parse_error_fails_closed(self):
        result = scan({"bad.py": "def broken(:"})
        self.assertEqual(result["gate"], "ERROR")
        self.assertEqual(len(result["errors"]), 1)

    def test_gate_blocks(self):
        self.assertEqual(gate(analyze('eval("1")')), "BLOCKED")
        self.assertEqual(gate([]), "PASSED")

    def test_context_hides_literals(self):
        result = json.dumps(analyze('password = "NeverExposeThis123"'))
        self.assertNotIn("NeverExposeThis123", result)
        self.assertIn("context", result)

    def test_sarif_locations(self):
        report = sarif(scan({"a.py": 'eval("1")'}))
        self.assertEqual(report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_cli_exit_codes(self):
        for name, expected in [("examples/safe.py", 0), ("examples/vulnerable.py", 1), ("missing.py", 2)]:
            run = subprocess.run([sys.executable, "-m", "sast.cli", name], capture_output=True)
            self.assertEqual(run.returncode, expected, run.stderr)

if __name__ == "__main__":
    unittest.main()
