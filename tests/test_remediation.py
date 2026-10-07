import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from rivet.cli import main
from rivet.remediation import classify


class RemediationTests(unittest.TestCase):
    def test_classes(self):
        self.assertEqual("MANUAL_ONLY", classify("secret/github-token"))
        self.assertEqual("REVIEW_REQUIRED", classify("python/dynamic-sql"))
        self.assertEqual("SAFE_AUTOFIX", classify("hygiene/missing-gitignore"))

    def test_plan_does_not_modify_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            report.write_text(json.dumps({"findings": [{"rule": "secret/github-token", "fingerprint": "abc", "title": "token", "fix": "rotate"}]}))
            before = report.read_bytes()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(0, main(["plan-fix", str(report)]))
            self.assertEqual(before, report.read_bytes())
            plan = json.loads(out.getvalue())
            self.assertEqual("MANUAL_ONLY", plan["items"][0]["class"])

    def test_verify_fixed_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app.py"
            app.write_text("import os\nos.system('echo test')\n")
            old_dir = root / "old"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["scan", str(root), "--offline", "--out", str(old_dir)]))
            old_report = old_dir / "security-report.json"
            finding_id = json.loads(old_report.read_text())["findings"][0]["fingerprint"]
            app.write_text("print('safe')\n")
            new_dir = root / "new"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, main(["verify", str(root), "--against", str(old_report), "--finding", finding_id, "--out", str(new_dir)]))
            result = json.loads(output.getvalue())
            self.assertEqual("FIXED", result["status"])
            self.assertTrue((new_dir / "security-report.json").exists())


if __name__ == "__main__":
    unittest.main()
