from __future__ import annotations

import ast
from pathlib import Path
import re

from .model import Finding


def _finding(rule: str, title: str, rel: str, line: int, evidence: str, simple: str, fix: str, cwe: str) -> Finding:
    return Finding(rule, title, "MEDIUM", "MEDIUM", "Vibe coding", rel, line, evidence, simple, fix, "Check the affected behavior in a test environment.", "Rivet vibe rules", cwe, "CONDITIONAL", "NEEDS_MANUAL_REVIEW", "PATTERN_DETECTED", evidence, simple)


def scan_vibe(rel: str, text: str) -> list[Finding]:
    findings = []
    suffix = Path(rel).suffix.lower()
    if suffix == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value is True and any(isinstance(target, ast.Attribute) and target.attr == "debug" for target in node.targets):
                findings.append(_finding("vibe/debug-enabled", "Application debug mode enabled", rel, node.lineno, "debug = True", "Режим отладки может показывать внутренние данные приложения.", "Disable debug in production configuration.", "CWE-489"))
            if isinstance(node, ast.Call) and any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords):
                findings.append(_finding("vibe/tls-verify-disabled", "TLS certificate verification disabled", rel, node.lineno, "verify=False", "Приложение может принять поддельный TLS-сертификат.", "Enable TLS verification and configure trusted certificates.", "CWE-295"))
    elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
        frontend = suffix in {".jsx", ".tsx"} or any(part in {"frontend", "client", "public"} for part in Path(rel).parts)
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(r"localStorage\.getItem\s*\(\s*['\"](?:role|isAdmin|permissions)['\"]", line):
                findings.append(_finding("vibe/frontend-role", "Frontend reads role from localStorage", rel, number, "Role-like value read from localStorage", "Пользователь может менять данные в localStorage; сервер должен проверять права сам.", "Enforce authorization on every sensitive server operation.", "CWE-285"))
            if frontend and "SUPABASE_SERVICE_ROLE_KEY" in line:
                findings.append(_finding("vibe/service-role-frontend", "Supabase service role key referenced in frontend", rel, number, "Service role variable referenced; value redacted", "Служебный ключ не должен попадать в браузерный код.", "Move privileged Supabase access to a backend with server-side authorization.", "CWE-798"))
    return findings
