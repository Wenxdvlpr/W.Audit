import unittest

from rivet.vibe import scan_vibe


class VibeTests(unittest.TestCase):
    def test_python_tls_and_debug(self):
        code = '''
import requests
app.debug = True
response = requests.get(url, verify=False)
'''
        self.assertEqual({"vibe/debug-enabled", "vibe/tls-verify-disabled"}, {f.rule for f in scan_vibe("app.py", code)})

    def test_frontend_role_and_service_key(self):
        code = '''
const role = localStorage.getItem("role");
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
'''
        rules = {f.rule for f in scan_vibe("src/App.tsx", code)}
        self.assertEqual({"vibe/frontend-role", "vibe/service-role-frontend"}, rules)

    def test_secure_controls_not_reported(self):
        code = '''
import requests
app.debug = False
response = requests.get(url, verify=True)
'''
        self.assertEqual([], scan_vibe("app.py", code))


if __name__ == "__main__":
    unittest.main()
