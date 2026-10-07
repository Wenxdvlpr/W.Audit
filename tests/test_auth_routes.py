import unittest
from pathlib import Path
import contextlib
import io
import json
import tempfile

from rivet.cli import main
from rivet.auth import scan_python_auth
from rivet.routes import analyze_python_routes, build_authorization_matrix


class AuthenticationTests(unittest.TestCase):
    def test_weak_password_hash_and_unsigned_jwt(self):
        code = '''
import hashlib, jwt
def login(password, token):
    digest = hashlib.md5(password.encode()).hexdigest()
    payload = jwt.decode(token, options={"verify_signature": False})
    return digest, payload
'''
        rules = {f.rule for f in scan_python_auth("app.py", code)}
        self.assertIn("auth/weak-password-hash", rules)
        self.assertIn("auth/jwt-no-signature", rules)

    def test_cookie_flags_and_predictable_reset_token(self):
        code = '''
import random
def reset(response):
    reset_token = random.randint(100000, 999999)
    response.set_cookie("session", reset_token, secure=False, httponly=False)
'''
        rules = {f.rule for f in scan_python_auth("app.py", code)}
        self.assertIn("auth/predictable-reset-token", rules)
        self.assertIn("auth/insecure-cookie", rules)

    def test_strong_hash_and_cookie_not_reported(self):
        code = '''
import secrets
from argon2 import PasswordHasher
def reset(response, password):
    reset_token = secrets.token_urlsafe(32)
    digest = PasswordHasher().hash(password)
    response.set_cookie("session", reset_token, secure=True, httponly=True, samesite="Lax")
    return digest
'''
        self.assertEqual([], scan_python_auth("app.py", code))


class RouteTests(unittest.TestCase):
    def test_bola_candidate_and_matrix(self):
        code = '''
from fastapi import FastAPI
app = FastAPI()
@app.get("/users/{id}")
def user(id: int):
    return db.get(id)
@app.delete("/users/{id}")
def delete_user(id: int):
    db.delete(id)
'''
        routes, findings = analyze_python_routes("app.py", code)
        self.assertEqual({"GET", "DELETE"}, {r["method"] for r in routes})
        self.assertEqual(2, len(findings))
        self.assertTrue(all(f.severity == "MEDIUM" and f.status == "NEEDS_MANUAL_REVIEW" for f in findings))
        self.assertTrue(all(f.flow_kind == "PATTERN_DETECTED" for f in findings))

    def test_explicit_authz_suppresses_bola_candidate(self):
        code = '''
@app.get("/users/{id}")
def user(id: int, current_user=Depends(get_current_user)):
    record = db.get(id)
    if record.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    return record
'''
        routes, findings = analyze_python_routes("app.py", code)
        self.assertEqual(1, len(routes))
        self.assertEqual("INFERRED", routes[0]["authorization"])
        self.assertEqual([], findings)

    def test_owner_field_reference_alone_does_not_prove_authorization(self):
        code = '''
@app.get("/users/{id}")
def user(id: int):
    record = db.get(id)
    audit_log(record.owner_id)
    return record
'''
        routes, findings = analyze_python_routes("app.py", code)
        self.assertEqual("UNKNOWN", routes[0]["authorization"])
        self.assertEqual("INFERRED", routes[0]["evidence_status"])
        self.assertEqual(1, len(findings))
        self.assertIn("LIKELY_BOLA", findings[0].evidence)

    def test_fastapi_dependency_model_and_role_matrix_are_inferred(self):
        code = '''
from fastapi import Depends
@app.get("/users/{user_id}")
def get_user(user_id: str, current_user=Depends(get_current_user), role=Depends(require_role("admin"))):
    return db.get(user_id)
@app.get("/health")
def health():
    return {"ok": True}
'''
        routes, findings = analyze_python_routes("routes.py", code)
        self.assertEqual("INFERRED", routes[0]["authentication"])
        self.assertEqual("INFERRED", routes[0]["authorization"])
        self.assertEqual("ADMIN", routes[0]["required_role"])
        matrix = build_authorization_matrix(routes)
        self.assertEqual({"INFERRED", "UNKNOWN"}, {cell["status"] for cell in matrix})
        self.assertTrue(all(cell["evidence_status"] == "INFERRED" for cell in matrix))
        self.assertEqual([], findings)

    def test_fastapi_secure_fixture_has_inferred_access_control_not_high(self):
        fixture = Path(__file__).parent / "fixtures/fastapi-secure/app.py"
        routes, findings = analyze_python_routes("app.py", fixture.read_text())
        self.assertEqual("INFERRED", routes[0]["authentication"])
        self.assertEqual("INFERRED", routes[0]["authorization"])
        self.assertNotIn("HIGH", [finding.severity for finding in findings])
        self.assertEqual([], findings)

    def test_fastapi_authorization_matrix_is_reported_in_json_and_markdown(self):
        fixture_root = Path(__file__).parent / "fixtures/fastapi-secure"
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["scan", str(fixture_root), "--offline", "--out", str(output)]))
            data = json.loads((output / "security-report.json").read_text())
            self.assertEqual("INFERRED", data["route_matrix"][0]["authentication"])
            self.assertIn({"role": "ADMIN", "endpoint": "/admin/users/{user_id}", "method": "GET", "status": "INFERRED", "evidence_status": "INFERRED"}, data["authorization_matrix"])
            self.assertIn("Role authorization matrix", (output / "security-report.md").read_text())

    def test_unscoped_returned_resource_is_likely_not_confirmed_bola(self):
        code = '''
@app.get("/users/{user_id}")
def get_user(user_id: str):
    record = db.get(user_id)
    return record
'''
        routes, findings = analyze_python_routes("routes.py", code)
        self.assertEqual("LIKELY_BOLA", routes[0]["bola_class"])
        self.assertIn("LIKELY_BOLA", findings[0].evidence)
        self.assertEqual("NEEDS_MANUAL_REVIEW", findings[0].status)


if __name__ == "__main__":
    unittest.main()
