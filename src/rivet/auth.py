from __future__ import annotations

import ast

from .model import Finding


def _name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _false_keyword(call: ast.Call, keys: set[str]) -> bool:
    return any(keyword.arg in keys and isinstance(keyword.value, ast.Constant) and keyword.value.value is False for keyword in call.keywords)


def _jwt_no_verify(call: ast.Call) -> bool:
    if _false_keyword(call, {"verify", "verify_signature"}):
        return True
    for keyword in call.keywords:
        if keyword.arg == "options" and isinstance(keyword.value, ast.Dict):
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if isinstance(key, ast.Constant) and key.value == "verify_signature" and isinstance(value, ast.Constant) and value.value is False:
                    return True
    return False


def scan_python_auth(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _name(node.func)
            line = getattr(node, "lineno", 1)
            if name in {"hashlib.md5", "hashlib.sha1", "hashlib.sha256"} and any(isinstance(child, ast.Name) and "password" in child.id.lower() for child in ast.walk(node)):
                findings.append(Finding("auth/weak-password-hash", "Weak or unsalted password hash", "MEDIUM", "HIGH", "Authentication", rel, line, f"{name} called with password-named data", "Fast hashes are unsuitable for password storage.", "Use Argon2id, scrypt or a suitably configured password KDF.", "Verify stored passwords use a password KDF with per-user salt.", "Rivet AST", "CWE-916", "LIKELY", "NEEDS_MANUAL_REVIEW"))
            if name in {"jwt.decode", "jose.jwt.decode", "pyjwt.decode"} and _jwt_no_verify(node):
                findings.append(Finding("auth/jwt-no-signature", "JWT signature verification disabled", "MEDIUM", "HIGH", "Authentication", rel, line, "decode call disables signature verification", "An attacker may forge claims if the decoded payload controls access.", "Verify signature, issuer, audience and expiry before trusting claims.", "Reject a token with a changed payload and invalid signature.", "Rivet AST", "CWE-347", "LIKELY", "NEEDS_MANUAL_REVIEW"))
            if name.endswith(".set_cookie") and _false_keyword(node, {"secure", "httponly"}):
                findings.append(Finding("auth/insecure-cookie", "Session cookie security flag disabled", "MEDIUM", "HIGH", "Authentication", rel, line, "set_cookie uses secure=False or httponly=False", "Session material may be exposed over HTTP or to browser scripts.", "Set Secure and HttpOnly for session cookies; choose an appropriate SameSite policy.", "Inspect the Set-Cookie header in a test environment.", "Rivet AST", "CWE-614", "LIKELY", "NEEDS_MANUAL_REVIEW"))
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not any(isinstance(target, ast.Name) and "reset" in target.id.lower() and "token" in target.id.lower() for target in targets):
                continue
            value = node.value
            if isinstance(value, ast.Call) and _name(value.func) in {"random.randint", "random.randrange", "random.random", "random.choice"}:
                findings.append(Finding("auth/predictable-reset-token", "Password reset token uses noncryptographic randomness", "MEDIUM", "HIGH", "Authentication", rel, getattr(node, "lineno", 1), f"{_name(value.func)} used for reset token", "A predictable reset token can enable account takeover.", "Use secrets.token_urlsafe or another CSPRNG with sufficient entropy.", "Check token unpredictability, expiration and one-time use.", "Rivet AST", "CWE-330", "LIKELY", "NEEDS_MANUAL_REVIEW"))
    return findings
