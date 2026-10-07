import json
from pathlib import Path
import tempfile
import unittest

from rivet.checks import scan_python, scan_secrets
from rivet.cli import main
from rivet.model import Finding, deduplicate
from rivet.walk import safe_files

FIXTURES = Path(__file__).parent / "fixtures"


class CoreTests(unittest.TestCase):
    def test_vulnerable_python(self):
        text = (FIXTURES / "python-vulnerable" / "app.py").read_text()
        rules = {f.rule for f in scan_python("app.py", text)}
        self.assertTrue({"python/os-shell", "python/subprocess-shell", "python/unsafe-deserialization"} <= rules)

    def test_secure_python(self):
        text = (FIXTURES / "secure-reference" / "app.py").read_text()
        self.assertEqual([], scan_python("app.py", text))

    def test_secret_redaction(self):
        secret = "ghp_" + "A" * 36
        found = scan_secrets("config.txt", secret)
        self.assertEqual(1, len(found))
        self.assertNotIn(secret, json.dumps(found[0].data()))
        malicious = Finding("x", secret, "LOW", "LOW", "test", "a", 1, secret, "", "", "", "test")
        self.assertNotIn(secret, json.dumps(malicious.data()))

    def test_cross_scanner_deduplication(self):
        first = Finding("rivet/shell", "Shell", "MEDIUM", "HIGH", "Command injection", "app.py", 9, "shell", "", "", "", "Rivet", "CWE-78")
        second = Finding("bandit/B605", "Shell", "LOW", "MEDIUM", "Python SAST", "app.py", 9, "shell", "", "", "", "Bandit", "CWE-78")
        result = deduplicate([first, second])
        self.assertEqual(1, len(result))
        self.assertEqual("MEDIUM", result[0].severity)

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "link").symlink_to(Path(tmp))
            self.assertEqual([], list(safe_files(root)))

    def test_exclude_tool_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / ".rivet-tool"
            tool.mkdir()
            (tool / "unsafe.py").write_text("import os\nos.system('x')\n")
            (root / "app.py").write_text("print('ok')\n")
            self.assertEqual(["app.py"], [rel for _, rel in safe_files(root, (".rivet-tool",))])

    def test_reports_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "reports"
            self.assertEqual(0, main(["scan", str(FIXTURES / "python-vulnerable"), "--offline", "--out", str(out)]))
            for extension in ("md", "json", "sarif", "html"):
                self.assertTrue((out / f"security-report.{extension}").is_file())
            data = json.loads((out / "security-report.json").read_text())
            self.assertGreaterEqual(len(data["findings"]), 3)
            baseline = Path(tmp) / "baseline.json"
            self.assertEqual(0, main(["baseline", "create", str(out / "security-report.json"), "--out", str(baseline)]))
            self.assertEqual(0, main(["baseline", "compare", str(out / "security-report.json"), str(baseline)]))

    def test_infrastructure_fixtures(self):
        from rivet.checks import scan_config
        docker = (FIXTURES / "docker-insecure" / "Dockerfile").read_text()
        terraform = (FIXTURES / "terraform-insecure" / "main.tf").read_text()
        self.assertEqual({"docker/latest", "docker/root"}, {f.rule for f in scan_config("Dockerfile", docker)})
        self.assertEqual({"terraform/open-cidr"}, {f.rule for f in scan_config("main.tf", terraform)})

    def test_html_escaping(self):
        from rivet.report import write_reports, make_data
        from rivet.model import Check
        with tempfile.TemporaryDirectory() as tmp:
            finding = Finding("x", "<script>alert(1)</script>", "LOW", "LOW", "test", "evil.md", 1, "<img src=x>", "", "", "", "test")
            output = Path(tmp)
            data = make_data(output, {"languages": [], "frameworks": [], "infrastructure": [], "databases": [], "security_areas": []}, [finding], [Check("test", "CHECKED", "test")], "auto")
            write_reports(output, data, [finding], [Check("test", "CHECKED", "test")])
            page = (output / "security-report.html").read_text()
            self.assertNotIn("<script>alert(1)</script>", page)
            self.assertNotIn("<img src=x>", page)


if __name__ == "__main__":
    unittest.main()
