import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from rivet.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class FixtureScans(unittest.TestCase):
    def scan(self, name):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp)
            self.assertEqual(0, main(["scan", str(FIXTURES / name), "--offline", "--out", str(out)]))
            return json.loads((out / "security-report.json").read_text())

    def test_vulnerable_fixtures(self):
        expected = {"python-vulnerable": "python/os-shell", "python-interprocedural": "python/flow/sql-injection", "docker-insecure": "docker/root", "terraform-insecure": "terraform/open-cidr", "kubernetes-insecure": "k8s/privileged", "api-bola": "authz/bola-candidate", "ai-output": "ai/output-to-shell", "mcp-insecure": "mcp/shell-command", "ci-insecure": "ci/write-all"}
        for fixture, rule in expected.items():
            with self.subTest(fixture=fixture):
                report = self.scan(fixture)
                self.assertIn(rule, {item["rule"] for item in report["findings"]})

    def test_secure_fixture_is_clean(self):
        self.assertEqual([], self.scan("secure-reference")["findings"])


if __name__ == "__main__":
    unittest.main()
