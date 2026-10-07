import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rivet.adapters import _invoke, semgrep
from rivet.cli import main
from rivet.walk import safe_files
from rivet.report import validate_sarif


class SelfSecurityTests(unittest.TestCase):
    def test_shell_metacharacters_in_filename_are_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            name = "$(touch hacked).py"
            (root / name).write_text("import os\nos.system('echo ok')\n")
            out = root / "out"
            self.assertEqual(0, main(["scan", str(root), "--out", str(out)]))
            self.assertFalse((root / "hacked").exists())
            report = json.loads((out / "security-report.json").read_text())
            self.assertEqual(name, report["findings"][0]["path"])

    def test_control_characters_in_filename_not_emitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evil\x1b[31m\nname.py").write_text("import os\nos.system('echo ok')\n")
            out = root / "out"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, main(["scan", str(root), "--out", str(out)]))
            self.assertNotIn("\x1b", output.getvalue())
            self.assertNotIn("\x1b", (out / "security-report.md").read_text())

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            outside = Path(tmp) / "outside.py"
            outside.write_text("import os\nos.system('not scanned')\n")
            (root / "link.py").symlink_to(outside)
            self.assertEqual([], list(safe_files(root)))

    def test_deep_or_invalid_scanner_json_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for output in ("{bad", "[" * 3000 + "0" + "]" * 3000):
                with patch("rivet.adapters.subprocess.run") as run:
                    def fake_run(argv, **kwargs):
                        kwargs["stdout"].write(output.encode())
                        kwargs["stdout"].flush()
                        return type("Result", (), {"returncode": 0})()
                    run.side_effect = fake_run
                    data, error = _invoke(["semgrep"], root)
                    self.assertIsNone(data)
                    self.assertTrue(error)

    def test_malicious_scanner_message_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = "ghp_" + "Z9qR" * 9
            data = {"results": [{"path": "app.py", "check_id": "x", "start": {"line": 1}, "extra": {"message": "<script>" + secret + "</script>", "severity": "WARNING"}}]}
            with patch("rivet.adapters._invoke", return_value=(data, "")):
                findings, check = semgrep(root, root / "rules.yml")
            self.assertEqual("CHECKED", check.status)
            self.assertEqual(1, len(findings))
            self.assertNotIn(secret, json.dumps(findings[0].data()))

    def test_invalid_deep_config_returns_code_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "rivet.json"
            config.write_text("[" * 3000 + "0" + "]" * 3000)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = main(["scan", str(root), "--config", str(config)])
            self.assertEqual(2, code)

    def test_file_budget_stops_oversized_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("a" * 20)
            (root / "b.txt").write_text("b" * 20)
            with patch("rivet.walk.MAX_TOTAL_BYTES", 30):
                with self.assertRaises(RuntimeError):
                    list(safe_files(root))

    def test_scanner_output_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("rivet.adapters.MAX_OUTPUT", 20), patch("rivet.adapters.subprocess.run") as run:
                def fake_run(argv, **kwargs):
                    kwargs["stdout"].write(b"{" + b" " * 100 + b"}")
                    return type("Result", (), {"returncode": 0})()
                run.side_effect = fake_run
                data, error = _invoke(["semgrep"], root)
                self.assertIsNone(data)
                self.assertIn("limit", error)

    def test_malformed_sarif_rejected(self):
        for value in ({}, {"version": "2.1.0", "runs": [{}]}, {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Rivet", "rules": []}}, "results": [{"ruleId": "missing", "level": "error"}]}]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_sarif(value)

    def test_fake_secret_never_appears_in_any_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            secret = "ghp_" + "A9bB" * 9
            (root / "config.py").write_text(f"api_key = '{secret}'\n")
            out = Path(tmp) / "reports"
            cli = io.StringIO()
            with contextlib.redirect_stdout(cli):
                self.assertEqual(0, main(["scan", str(root), "--out", str(out)]))
            self.assertNotIn(secret, cli.getvalue())
            for path in out.iterdir():
                with self.subTest(path=path.name):
                    self.assertNotIn(secret, path.read_text())

    def test_html_report_escapes_untrusted_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            # Slash characters are path separators, so use a payload-like filename.
            (root / "evil<script>.py").write_text("import os\nos.system('<svg onload=alert(1)>')\n")
            out = Path(tmp) / "reports"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["scan", str(root), "--out", str(out)]))
            html = (out / "security-report.html").read_text()
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertNotIn("<svg onload=alert(1)>", html)
            self.assertIn("&amp;lt;script&amp;gt;", html)


if __name__ == "__main__":
    unittest.main()
