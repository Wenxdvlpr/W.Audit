import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rivet.adapters import _safe_rel, _invoke, run_external, ADAPTERS, PLANNED, ScannerAdapter, semgrep, bandit, osv
from rivet.cli import main
from rivet.model import Check


class AdapterTests(unittest.TestCase):
    def test_registry_has_independent_adapters_and_planned_status(self):
        self.assertTrue({"semgrep", "bandit", "gitleaks", "osv-scanner"} <= {x.name for x in ADAPTERS})
        self.assertTrue({"gosec", "eslint-security", "cargo-audit"} <= {x.name for x in PLANNED})
        self.assertTrue(all(callable(x.runner) for x in ADAPTERS))

    def test_missing_scanners_do_not_fail_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("rivet.adapters.shutil.which", return_value=None):
                findings, checks = run_external(root, root / "rules.yml", True)
            self.assertEqual([], findings)
            self.assertTrue(any(c.status == "NOT_INSTALLED" for c in checks))
            self.assertTrue(any(c.status == "DISABLED" and c.tool == "osv-scanner" for c in checks))

    def test_disabled_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("rivet.adapters.shutil.which", return_value=None):
                _, checks = run_external(root, root / "rules.yml", False, {"bandit"})
            self.assertEqual("DISABLED", next(x.status for x in checks if x.tool == "bandit"))

    def test_optional_adapter_exception_is_recorded_and_does_not_stop_scan(self):
        def crash(_root, _rules):
            raise RuntimeError("synthetic adapter failure")
        def continue_ok(_root, _rules):
            return [], Check("Second", "CHECKED", "second")
        registry = (
            ScannerAdapter("first", "First", "test", "", False, crash),
            ScannerAdapter("second", "Second", "test", "", False, continue_ok),
        )
        with tempfile.TemporaryDirectory() as tmp, patch("rivet.adapters.ADAPTERS", registry), patch("rivet.adapters.shutil.which", return_value="/fake/tool"):
            findings, checks = run_external(Path(tmp), Path(tmp) / "rules.yml", False)
        self.assertEqual([], findings)
        self.assertEqual(["FAILED", "COMPLETED"], [item.status for item in checks])
        self.assertIn("remaining checks continued", checks[0].detail)

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            self.assertIsNone(_safe_rel(root, "../../outside.py"))
            self.assertEqual("app.py", _safe_rel(root, "app.py"))

    def test_doctor_reports_install_instructions(self):
        import contextlib
        import io
        output = io.StringIO()
        with patch("rivet.adapters.shutil.which", return_value=None), contextlib.redirect_stdout(output):
            self.assertEqual(0, main(["doctor"]))
        self.assertIn("NOT_INSTALLED", output.getvalue())
        self.assertIn("https://", output.getvalue())

    def test_unconfirmed_scanner_high_is_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = {"results": [{"path": "app.py", "check_id": "rule", "start": {"line": 2}, "extra": {"message": "possible issue", "severity": "ERROR"}}]}
            with patch("rivet.adapters._invoke", return_value=(data, "")):
                findings, _ = semgrep(root, root / "rules.yml")
            self.assertEqual("MEDIUM", findings[0].severity)
            self.assertEqual("NEEDS_MANUAL_REVIEW", findings[0].status)

    def test_malformed_output_and_timeout_are_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for adapter in (semgrep, bandit, osv):
                with self.subTest(adapter=adapter.__name__), patch("rivet.adapters._invoke", return_value=(None, "invalid JSON")):
                    check = adapter(root, root / "rules.yml")[1] if adapter is semgrep else adapter(root)[1]
                    self.assertEqual("FAILED", check.status)
                with self.subTest(adapter=adapter.__name__), patch("rivet.adapters._invoke", return_value=(None, "TIMEOUT: scanner exceeded 120 seconds")):
                    check = adapter(root, root / "rules.yml")[1] if adapter is semgrep else adapter(root)[1]
                    self.assertEqual("TIMEOUT", check.status)

    def test_nonzero_exit_is_not_silent_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("rivet.adapters.subprocess.run") as run:
                def fail(argv, **kwargs):
                    kwargs["stdout"].write(b'{"results": []}')
                    return type("Result", (), {"returncode": 42})()
                run.side_effect = fail
                data, error = _invoke(["scanner"], root)
                self.assertIsNone(data)
                self.assertIn("42", error)

    def test_scanner_declared_errors_do_not_count_as_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("rivet.adapters._invoke", return_value=({"results": [], "errors": [{"message": "sensitive raw error"}]}, "")):
                _, check = semgrep(root, root / "rules.yml")
            self.assertEqual("FAILED", check.status)
            self.assertNotIn("sensitive", check.detail)


if __name__ == "__main__":
    unittest.main()
