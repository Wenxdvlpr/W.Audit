from pathlib import Path
import unittest

from rivet.taint import scan_python_project


class CrossFileFlowTests(unittest.TestCase):
    def test_sql_command_and_ssrf_flows_cross_imported_modules(self):
        for name, cwe in (("sql", "CWE-89"), ("command", "CWE-78"), ("ssrf", "CWE-918")):
            with self.subTest(name=name):
                root = Path(__file__).parent / "fixtures/python-cross-file" / name
                texts = {f"{name}/{p.name}": p.read_text() for p in root.glob("*.py")}
                findings, truncated = scan_python_project(texts)
                self.assertFalse(truncated)
                match = [finding for finding in findings if finding.cwe == cwe]
                self.assertEqual(1, len(match))
                self.assertEqual("REACHABLE_FLOW", match[0].flow_kind)
                self.assertEqual("NEEDS_MANUAL_REVIEW", match[0].status)

    def test_safe_sql_and_argument_vector_do_not_report(self):
        root = Path(__file__).parent / "fixtures/python-cross-file" / "safe"
        texts = {f"safe/{p.name}": p.read_text() for p in root.glob("*.py")}
        findings, truncated = scan_python_project(texts)
        self.assertFalse(truncated)
        self.assertEqual([], findings)

    def test_project_file_limit_is_reported(self):
        texts = {f"m{i}.py": "value = 1\n" for i in range(101)}
        _, truncated = scan_python_project(texts)
        self.assertTrue(truncated)


if __name__ == "__main__":
    unittest.main()
