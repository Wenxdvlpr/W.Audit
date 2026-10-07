import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from rivet.adapters import osv
from rivet.sca import dependency_context, from_osv


class ScaTests(unittest.TestCase):
    def test_osv_normalization_preserves_unknown_reachability(self):
        package = {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}
        vulnerability = {"id": "PYSEC-2018-28", "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"], "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}
        result = from_osv(package, vulnerability).data()
        self.assertEqual("2.20.0", result["fixed_version"])
        self.assertEqual("UNKNOWN", result["reachability"])
        self.assertEqual("CVE-2018-18074", result["cve"])
        self.assertEqual("GHSA-x84v-xcm2-53pg", result["ghsa"])
        self.assertEqual("UNKNOWN", result["directness"])
        self.assertEqual("OSV-Scanner", result["source_scanner"])

    def test_pinned_python_requirements_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual({"directness": "DIRECT", "environment": "RUNTIME"}, dependency_context(root, "requirements.txt", {"name": "requests"}))
            self.assertEqual({"directness": "DIRECT", "environment": "DEV"}, dependency_context(root, "requirements-dev.txt", {"name": "pytest"}))

    def test_npm_lockfile_context_and_osv_normalization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package-lock.json").write_text('''{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"1.0.0"}},"node_modules/left-pad":{"version":"1.0.0"},"node_modules/left-pad/node_modules/minimist":{"version":"0.0.8","dev":true}}}''')
            self.assertEqual({"directness": "DIRECT", "environment": "RUNTIME"}, dependency_context(root, "package-lock.json", {"name": "left-pad"}))
            self.assertEqual({"directness": "TRANSITIVE", "environment": "DEV"}, dependency_context(root, "package-lock.json", {"name": "minimist"}))
            vulnerability = {"id": "GHSA-test-1234-5678", "aliases": ["CVE-2024-12345"], "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}
            package = {"ecosystem": "npm", "name": "left-pad", "version": "1.0.0"}
            payload = {"results": [{"source": {"path": "package-lock.json"}, "packages": [{"package": package, "vulnerabilities": [vulnerability]}]}]}
            with patch("rivet.adapters._invoke", return_value=(payload, "")):
                findings, check = osv(root)
            self.assertEqual("CHECKED", check.status)
            self.assertEqual(1, len(findings))
            data = findings[0].dependency
            self.assertEqual(("npm", "left-pad", "1.0.0"), (data["ecosystem"], data["package"], data["installed_version"]))
            self.assertEqual(("DIRECT", "RUNTIME", "UNKNOWN", "OSV-Scanner"), (data["directness"], data["environment"], data["reachability"], data["source_scanner"]))

    def test_package_lock_fixtures_normalize_vulnerable_and_clean_results(self):
        fixtures = Path(__file__).parent / "fixtures"
        vulnerable_root = fixtures / "sca-npm-vulnerable"
        vulnerability = {"id": "GHSA-test-1234-5678", "aliases": ["CVE-2021-23337"], "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
        package = {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
        payload = {"results": [{"source": {"path": "package-lock.json"}, "packages": [{"package": package, "vulnerabilities": [vulnerability]}]}]}
        with patch("rivet.adapters._invoke", return_value=(payload, "")):
            vulnerable, check = osv(vulnerable_root)
        self.assertEqual("CHECKED", check.status)
        self.assertEqual(1, len(vulnerable))
        self.assertEqual("4.17.21", vulnerable[0].dependency["fixed_version"])
        self.assertEqual(("DIRECT", "RUNTIME", "UNKNOWN"), (vulnerable[0].dependency["directness"], vulnerable[0].dependency["environment"], vulnerable[0].dependency["reachability"]))
        clean_root = fixtures / "sca-npm-clean"
        clean_package = {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}
        clean_payload = {"results": [{"source": {"path": "package-lock.json"}, "packages": [{"package": clean_package, "vulnerabilities": []}]}]}
        with patch("rivet.adapters._invoke", return_value=(clean_payload, "")):
            clean, check = osv(clean_root)
        self.assertEqual("CHECKED", check.status)
        self.assertEqual([], clean)


if __name__ == "__main__":
    unittest.main()
