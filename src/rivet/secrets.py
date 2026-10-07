from __future__ import annotations

import math
import re

from .model import Finding

TOKEN_PATTERNS = {
    "github-token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "openai-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b"),
    "stripe-live-key": re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
}
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
DB_URL = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^@\s/]+@[^\s'\"]+", re.I)
ASSIGNMENT = re.compile(r"(?i)\b(?P<name>[A-Z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z_]*)\s*[:=]\s*['\"]?(?P<value>[A-Za-z0-9+/_=.!@#$%^&*?-]{8,})")
PLACEHOLDER = re.compile(r"^(?:example|dummy|fixture|fake|placeholder|changeme|password|your[_-]?.*|test[_-]?.*|x+|0+|a+)$", re.I)


def _entropy(value: str) -> float:
    frequencies = {c: value.count(c) for c in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in frequencies.values())


def scan_secrets(rel: str, text: str) -> list[Finding]:
    found = []
    for line_no, line in enumerate(text.splitlines(), 1):
        kinds = set()
        if PRIVATE_KEY.search(line):
            kinds.add("private-key")
        for name, pattern in TOKEN_PATTERNS.items():
            if pattern.search(line):
                kinds.add(name)
        if DB_URL.search(line) and not re.search(r"://[^\s:@/]+:(?:example|dummy|password|changeme)@", line, re.I):
            kinds.add("database-url")
        for match in ASSIGNMENT.finditer(line):
            value = match.group("value").strip("'\"")
            if PLACEHOLDER.fullmatch(value):
                continue
            if len(value) >= 12 and (len(value) >= 20 and _entropy(value) >= 3.5 or "PASSWORD" in match.group("name").upper() or "SECRET" in match.group("name").upper()):
                kinds.add("config-secret")
        for kind in sorted(kinds):
            found.append(Finding("secret/" + kind, "Potential exposed credential", "MEDIUM", "HIGH" if kind == "private-key" else "MEDIUM", "Secrets", rel, line_no, f"{kind} matched; value redacted", "An active credential can be abused if exposed.", "Revoke or rotate it, remove it from code and inspect Git history.", "Confirm revocation and rerun source and history scans.", "Rivet", "CWE-798", "CONDITIONAL", "NEEDS_MANUAL_REVIEW"))
    return found
