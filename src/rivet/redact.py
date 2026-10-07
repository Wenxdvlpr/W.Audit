from __future__ import annotations

import re

TOKEN = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b|\bsk_live_[A-Za-z0-9]{20,}\b")
DATABASE_PASSWORD = re.compile(r"((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:@/]+:)[^@\s/]+(@)", re.I)
ASSIGNMENT = re.compile(r"(?i)\b((?:[A-Z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z_]*)\s*[:=]\s*['\"]?)[^\s'\"]{8,}")
PRIVATE_BLOCK = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def redact(value: object, limit: int = 2000) -> str:
    text = str(value)[:200_000]
    text = PRIVATE_BLOCK.sub("[REDACTED PRIVATE KEY]", text)
    text = DATABASE_PASSWORD.sub(r"\1[REDACTED]\2", text)
    text = ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = TOKEN.sub("[REDACTED]", text)
    text = CONTROL.sub(" ", text)
    return text[:limit]
