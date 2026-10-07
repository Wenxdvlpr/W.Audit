import unittest

from rivet.taint import scan_python_flows
from rivet.model import deduplicate
from rivet.checks import scan_python


class PythonFlowTests(unittest.TestCase):
    def test_sql_command_file_template_redirect_ssrf(self):
        code = '''
from flask import request, redirect, render_template_string
import os, requests, subprocess

def handler():
    user = request.args.get("q")
    query = "SELECT * FROM users WHERE name='" + user + "'"
    db.execute(query)
    subprocess.run(user, shell=True)
    open(user)
    render_template_string(user)
    redirect(user)
    requests.get(user)
'''
        found = scan_python_flows("app.py", code)
        self.assertEqual({"SQL injection", "Command injection", "Path traversal", "Template injection", "Open redirect", "SSRF"}, {x.category for x in found})
        self.assertTrue(all(x.flow_kind == "REACHABLE_FLOW" for x in found))
        self.assertTrue(all(x.severity == "MEDIUM" for x in found))
        self.assertTrue(all("request.args.get" in x.evidence for x in found))

    def test_parameterized_sql_and_validated_path_not_reported(self):
        code = '''
from flask import request
import os
def handler():
    identifier = int(request.args.get("id"))
    db.execute("SELECT * FROM users WHERE id=?", (identifier,))
    filename = os.path.basename(request.args.get("name"))
    open(filename)
'''
        self.assertEqual([], scan_python_flows("app.py", code))

    def test_unrelated_constants_not_reported(self):
        code = '''
def handler():
    query = "SELECT 1"
    db.execute(query)
    requests.get("https://example.com")
'''
        self.assertEqual([], scan_python_flows("app.py", code))

    def test_flow_wins_over_pattern_at_same_line(self):
        code = '''
from flask import request
import subprocess
def handler():
    command = request.args.get("cmd")
    subprocess.run(command, shell=True)
'''
        found = deduplicate(scan_python("app.py", code) + scan_python_flows("app.py", code))
        self.assertEqual(1, len(found))
        self.assertEqual("REACHABLE_FLOW", found[0].flow_kind)


if __name__ == "__main__":
    unittest.main()
