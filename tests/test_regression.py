import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from rivet.cli import main
from rivet.discovery import discover
from rivet.checks import scan_secrets
from rivet.model import Finding, deduplicate
from rivet.report import sarif
from rivet.walk import safe_files


class ProjectCase(unittest.TestCase):
    def project(self, files):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = main(args)
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()


class CliTests(ProjectCase):
    def test_help_and_invalid_arguments(self):
        code, output, _ = self.invoke(["--help"])
        self.assertEqual(0, code)
        self.assertIn("scan", output)
        code, _, error = self.invoke(["scan", "--profile", "unreal"])
        self.assertEqual(2, code)
        self.assertIn("invalid choice", error)

    def test_missing_directory_and_threshold(self):
        root = self.project({"app.py": "import os\nos.system('echo test')\n"})
        code, _, _ = self.invoke(["scan", str(root / "missing")])
        self.assertEqual(2, code)
        code, _, _ = self.invoke(["scan", str(root), "--out", str(root / "out"), "--fail-on", "medium"])
        self.assertEqual(1, code)
        code, _, _ = self.invoke(["scan", str(root), "--out", str(root / "out"), "--fail-on", "high"])
        self.assertEqual(0, code)

    def test_profiles_and_offline(self):
        root = self.project({"app.py": "print('ok')\n"})
        for profile in ("quick", "standard", "full", "paranoid", "ci", "offline"):
            out = root / ("out-" + profile)
            code, _, _ = self.invoke(["scan", str(root), "--profile", profile, "--out", str(out)])
            self.assertEqual(0, code)
            report = json.loads((out / "security-report.json").read_text())
            self.assertEqual(profile, report["profile_name"])
            self.assertEqual([], report["findings"])
            external = [item for item in report["checks"] if item.get("category") == "External scanners"]
            self.assertEqual(1, len(external))
            self.assertEqual("SKIPPED", external[0]["status"])

    def test_invalid_config_and_config_controls(self):
        root = self.project({"app.py": "import os\nos.system('unsafe')\n", "ignored.py": "import os\nos.system('unsafe')\n"})
        config = root / "rivet.json"
        config.write_text("not json", encoding="utf-8")
        code, _, _ = self.invoke(["scan", str(root), "--config", str(config)])
        self.assertEqual(2, code)
        config.write_text(json.dumps({"include": ["*.py"], "exclude": ["ignored.py"], "profile": "quick", "disabled_scanners": ["bandit"], "fail_on": "medium", "offline": True}), encoding="utf-8")
        out = root / "out"
        code, _, _ = self.invoke(["scan", str(root), "--config", str(config), "--out", str(out)])
        self.assertEqual(1, code)
        report = json.loads((out / "security-report.json").read_text())
        self.assertEqual("quick", report["profile_name"])
        self.assertEqual(["app.py"], sorted({f["path"] for f in report["findings"]}))
        self.assertTrue(report["offline"])

    def test_filtered_scan_does_not_run_unfiltered_external_tools(self):
        root = self.project({"app.py": "print('ok')", "ignored.py": "print('ok')"})
        config = root / "rivet.json"
        config.write_text(json.dumps({"exclude": ["ignored.py"]}))
        out = root / "out"
        code, _, _ = self.invoke(["scan", str(root), "--config", str(config), "--external", "--out", str(out)])
        self.assertEqual(0, code)
        report = json.loads((out / "security-report.json").read_text())
        self.assertTrue(any(c["status"] == "SKIPPED" and c["category"] == "External scanners" for c in report["checks"]))


class DiscoveryTests(ProjectCase):
    def classify(self, files):
        root = self.project(files)
        entries = list(safe_files(root))
        return discover(entries, {rel: path.read_text() for path, rel in entries})

    def test_python_fastapi_postgres(self):
        profile = self.classify({"pyproject.toml": '[project]\ndependencies=["fastapi", "psycopg"]', "app.py": "print('ok')"})
        self.assertIn("Python", profile["languages"])
        self.assertIn("FastAPI", profile["frameworks"])

    def test_node_react_and_database(self):
        profile = self.classify({"package.json": '{"dependencies":{"react":"1","mongodb":"1"}}', "main.tsx": "const x=1"})
        self.assertIn("TypeScript", profile["languages"])
        self.assertIn("React", profile["frameworks"])
        self.assertIn("mongodb", profile["databases"])

    def test_mixed_docker_ci(self):
        profile = self.classify({"app.py": "print(1)", "main.js": "console.log(1)", "Dockerfile": "FROM alpine:3", ".github/workflows/ci.yml": "name: CI"})
        self.assertEqual(["JavaScript", "Python"], profile["languages"])
        self.assertIn("Docker", profile["infrastructure"])
        self.assertIn("GitHub Actions", profile["infrastructure"])


class SecretTests(ProjectCase):
    def test_fake_credential_types_and_redaction(self):
        token = "ghp_" + "Q7rM" * 9
        jwt = "JWT_SECRET=" + "zT8qR6vN4mP2sX9a" * 2
        db = "DATABASE_URL=postgresql://reader:An0therLongPass9@localhost:5432/app"
        key = "-----BEGIN PRIVATE KEY-----\n" + "c29tZS1ub3QtcmVhbC1rZXk=" * 3 + "\n-----END PRIVATE KEY-----"
        root = self.project({".env": f"API_KEY={token}\n{jwt}\n{db}\n", "docs/key.pem": key})
        out = root / "out"
        code, stdout, stderr = self.invoke(["scan", str(root), "--offline", "--out", str(out)])
        self.assertEqual(0, code)
        findings = json.loads((out / "security-report.json").read_text())["findings"]
        self.assertGreaterEqual(len(findings), 4)
        for value in (token, jwt.split("=", 1)[1], "An0therLongPass9", "c29tZS1ub3QtcmVhbC1rZXk="):
            for artifact in out.glob("security-report.*"):
                self.assertNotIn(value, artifact.read_text(), artifact.name)
            self.assertNotIn(value, stdout + stderr)
        self.assertIn("MEDIUM", {f["severity"] for f in findings})
        self.assertTrue(all(f["severity"] != "HIGH" for f in findings))

    def test_placeholders_and_low_entropy_not_reported(self):
        self.assertEqual([], scan_secrets(".env", "API_KEY=example\nPASSWORD=changeme\nTOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"))

    @unittest.skipUnless(shutil.which("git"), "git unavailable")
    def test_git_controlled_env_is_scanned_without_running_project(self):
        root = self.project({".env": "JWT_SECRET=Z9qR7vM2pL8nT4sX6bC1\n", "app.py": "print('safe')\n"})
        subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "add", ".env"], check=True, capture_output=True)
        out = root / "out"
        code, _, _ = self.invoke(["scan", str(root), "--offline", "--out", str(out)])
        self.assertEqual(0, code)
        report = json.loads((out / "security-report.json").read_text())
        self.assertTrue(any(f["path"] == ".env" and f["category"] == "Secrets" for f in report["findings"]))


class ResultTests(ProjectCase):
    def test_severity_confidence_exploitability_and_dedup(self):
        items = [Finding("a", "one", "MEDIUM", "HIGH", "Code", "a.py", 2, "pattern", "", "", "", "rivet", "CWE-78", "THEORETICAL"), Finding("b", "two", "LOW", "LOW", "Code", "a.py", 2, "pattern", "", "", "", "scanner", "CWE-78", "CONDITIONAL")]
        one = deduplicate(items)
        self.assertEqual(1, len(one))
        self.assertEqual(("MEDIUM", "HIGH", "THEORETICAL"), (one[0].severity, one[0].confidence, one[0].exploitability))
        self.assertEqual("warning", sarif(one)["runs"][0]["results"][0]["level"])

    def test_baseline_new_existing_fixed_regressed(self):
        root = self.project({"app.py": "print('ok')"})
        report = root / "report.json"
        baseline = root / "baseline.json"
        report.write_text(json.dumps({"findings": [{"fingerprint": "a"}, {"fingerprint": "b"}]}))
        baseline.write_text(json.dumps({"findings": [{"fingerprint": "a", "status": "OPEN"}, {"fingerprint": "b", "status": "FIXED"}, {"fingerprint": "c", "status": "OPEN"}]}))
        code, output, _ = self.invoke(["baseline", "compare", str(report), str(baseline)])
        self.assertEqual(0, code)
        states = json.loads(output)
        self.assertEqual(["a"], states["EXISTING"])
        self.assertEqual(["b"], states["REGRESSED"])
        self.assertEqual(["c"], states["FIXED"])
        self.assertEqual([], states["NEW"])

    def test_coverage_matrix_and_sarif_shape(self):
        root = self.project({"app.py": "print('safe')\n"})
        out = root / "out"
        code, _, _ = self.invoke(["scan", str(root), "--offline", "--out", str(out)])
        self.assertEqual(0, code)
        report = json.loads((out / "security-report.json").read_text())
        self.assertTrue(any(row["area"] == "Secrets" and row["status"] == "CHECKED" and row["result"] == "PASS" for row in report["coverage_matrix"]))
        self.assertTrue(any(row["area"] == "Dynamic API" and row["status"] == "SKIPPED" for row in report["coverage_matrix"]))
        sarif_data = json.loads((out / "security-report.sarif").read_text())
        self.assertEqual("2.1.0", sarif_data["version"])
        self.assertEqual("W.Audit", sarif_data["runs"][0]["tool"]["driver"]["name"])
        self.assertIn("runs", sarif_data)
        self.assertIn("tool", sarif_data["runs"][0])
        self.assertIn("results", sarif_data["runs"][0])


if __name__ == "__main__":
    unittest.main()
