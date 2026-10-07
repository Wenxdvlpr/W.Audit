from pathlib import Path
import unittest

from rivet.taint import scan_python_flows


class InterproceduralTests(unittest.TestCase):
    def test_route_service_repository_flow(self):
        source = (Path(__file__).parent / "fixtures/python-interprocedural/app.py").read_text()
        findings = scan_python_flows("app.py", source)
        self.assertEqual(1, len(findings))
        self.assertIn("route parameter q → service → alias → repository", findings[0].evidence)
        self.assertEqual("CWE-89", findings[0].cwe)

    def test_sanitized_local_value_does_not_reach_sink(self):
        source = "def service(value):\n    db.execute(f'{value}')\n@app.get('/')\ndef endpoint(q):\n    return service(int(q))\n"
        self.assertEqual([], scan_python_flows("app.py", source))

    def test_recursive_helper_is_bounded(self):
        source = "def recurse(value):\n    return recurse(value)\n@app.get('/')\ndef endpoint(q):\n    return recurse(q)\n"
        self.assertEqual([], scan_python_flows("app.py", source))


if __name__ == "__main__":
    unittest.main()
