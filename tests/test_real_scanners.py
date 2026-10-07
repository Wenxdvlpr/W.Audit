"""Optional integration tests against installed scanner executables."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from rivet.adapters import bandit, gitleaks, osv, semgrep
from rivet.model import deduplicate
from rivet.checks import scan_python


RULES = Path(__file__).resolve().parents[1] / "src/rivet/rules/semgrep.yml"
OSV_NPM_SKIP_REASON = "osv-scanner is not installed" if shutil.which("osv-scanner") is None else "Set RIVET_TEST_ONLINE_OSV=1 to enable the online npm OSV integration"


class RealScannerTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("semgrep"), "Semgrep not installed")
    def test_semgrep_real_positive_and_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text("import subprocess\nsubprocess.run('echo test', shell=True)\n")
            found, check = semgrep(root, RULES)
            self.assertEqual("CHECKED", check.status)
            self.assertEqual(1, len(found))
            self.assertEqual("CWE-78", found[0].cwe)
            (root / "app.py").write_text("print('safe')\n")
            found, check = semgrep(root, RULES)
            self.assertEqual(([], "CHECKED"), (found, check.status))

    @unittest.skipUnless(shutil.which("bandit"), "Bandit not installed")
    def test_bandit_real_findings_and_builtin_dedup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code = "import os\nos.system('echo test')\n"
            (root / "app.py").write_text(code)
            found, check = bandit(root)
            self.assertEqual("CHECKED", check.status)
            self.assertTrue(any(f.cwe == "CWE-78" for f in found))
            combined = deduplicate(scan_python("app.py", code) + found)
            self.assertEqual(1, len([f for f in combined if f.line == 2 and f.cwe == "CWE-78"]))

    @unittest.skipUnless(shutil.which("gitleaks") and shutil.which("git"), "Gitleaks or Git not installed")
    def test_gitleaks_real_git_history_and_clean_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual("SKIPPED", gitleaks(root)[1].status)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            (root / "test-key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBALr5h8fj6ZK4eN1i+N7aJ7tSBa4kkpUBAa3M6SlR9PZ0V02n\n-----END RSA PRIVATE KEY-----\n")
            subprocess.run(["git", "-C", str(root), "add", "test-key.pem"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
            found, check = gitleaks(root)
            self.assertEqual("CHECKED", check.status)
            self.assertTrue(any(f.path == "test-key.pem" for f in found))
            self.assertTrue(all("MIIBOg" not in str(f.data()) for f in found))

    @unittest.skipUnless(shutil.which("osv-scanner") and os.environ.get("RIVET_TEST_ONLINE_OSV") == "1", "Online OSV integration opt-in")
    def test_osv_real_vulnerability_and_clean_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "requirements.txt"
            manifest.write_text("requests==2.19.0\n")
            found, check = osv(root)
            self.assertEqual("CHECKED", check.status)
            self.assertTrue(any("requests 2.19.0" in f.title for f in found))
            manifest.write_text("packaging==25.0\n")
            found, check = osv(root)
            self.assertEqual(([], "CHECKED"), (found, check.status))

    @unittest.skipUnless(shutil.which("osv-scanner") and os.environ.get("RIVET_TEST_ONLINE_OSV") == "1", OSV_NPM_SKIP_REASON)
    def test_osv_real_npm_lock_vulnerable_and_clean(self):
        fixtures = Path(__file__).parent / "fixtures"
        vulnerable, check = osv(fixtures / "sca-npm-vulnerable")
        self.assertEqual("CHECKED", check.status)
        lodash = [f.dependency for f in vulnerable if f.dependency.get("package") == "lodash"]
        self.assertTrue(lodash, "OSV should report the vulnerable lodash lockfile entry")
        self.assertTrue(any(
            item.get("ecosystem", "").lower() == "npm"
            and item.get("installed_version") == "4.17.20"
            and item.get("advisory_id")
            and item.get("directness") == "DIRECT"
            and item.get("environment") == "RUNTIME"
            and item.get("reachability") == "UNKNOWN"
            and item.get("source_scanner") == "OSV-Scanner"
            for item in lodash
        ), "OSV result should preserve normalized npm advisory metadata")
        self.assertTrue(all("fixed_version" in item for item in lodash), "normalized findings should expose the fixed-version field")
        clean, check = osv(fixtures / "sca-npm-clean")
        self.assertEqual("CHECKED", check.status)
        self.assertEqual([], clean)


if __name__ == "__main__":
    unittest.main()
