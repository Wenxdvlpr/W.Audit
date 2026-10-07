from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import re
from typing import Any

from .redact import redact

SEVERITIES = ("HIGH", "MEDIUM", "LOW")
SIMPLE = {"Secrets": "В файле может находиться ключ или пароль. Проверьте его и замените, если он действующий.", "SQL injection": "Данные пользователя могут изменить запрос к базе данных.", "Command injection": "Данные пользователя могут попасть в команду операционной системы.", "Authorization": "Проверьте, что сервер запрещает доступ к чужим объектам.", "Authentication": "Проверьте, что вход и сессии защищены от подделки.", "Container": "Настройки контейнера могут давать лишние права.", "Supply chain": "Внешний компонент сборки может измениться или выполнить нежелательный код."}


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    confidence: str
    category: str
    path: str
    line: int
    evidence: str
    impact: str
    fix: str
    verify: str
    scanner: str
    cwe: str = ""
    exploitability: str = "CONDITIONAL"
    status: str = "OPEN"
    flow_kind: str = "PATTERN_DETECTED"
    technical_explanation: str = ""
    simple_explanation: str = ""
    dependency: dict[str, str] = field(default_factory=dict)
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES or self.confidence not in SEVERITIES:
            raise ValueError("invalid severity or confidence")
        for name in ("rule", "title", "category", "path", "evidence", "impact", "fix", "verify", "scanner", "cwe", "technical_explanation", "simple_explanation"):
            setattr(self, name, redact(getattr(self, name)))
        if not self.technical_explanation:
            self.technical_explanation = self.impact
        if not self.simple_explanation:
            self.simple_explanation = SIMPLE.get(self.category, "Обнаружено место, которое требует проверки специалистом по безопасности.")
        self.dependency = {redact(str(key)): redact(str(value)) for key, value in self.dependency.items()}
        key = f"{self.rule}\0{self.path}\0{self.line}".encode("utf-8", "replace")
        self.fingerprint = hashlib.sha256(key).hexdigest()[:20]

    def data(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Check:
    category: str
    status: str
    tool: str
    detail: str = ""


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for finding in findings:
        if finding.cwe:
            key = f"{finding.path}\0{finding.line}\0{finding.cwe}"
            finding.fingerprint = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]
        previous = seen.get(finding.fingerprint)
        if previous is None or (SEVERITIES.index(finding.severity), finding.flow_kind != "REACHABLE_FLOW", SEVERITIES.index(finding.confidence)) < (SEVERITIES.index(previous.severity), previous.flow_kind != "REACHABLE_FLOW", SEVERITIES.index(previous.confidence)):
            seen[finding.fingerprint] = finding
    return sorted(seen.values(), key=lambda f: (SEVERITIES.index(f.severity), f.path, f.line, f.rule))


def stabilize_fingerprints(findings: list[Finding], texts: dict[str, str]) -> None:
    """Use source context when available so line movement does not churn baselines."""
    cache: dict[str, tuple[list[str], list[int]]] = {}
    for finding in findings:
        if finding.path not in cache:
            counts: dict[str, int] = {}
            normalized = []
            occurrences = []
            for raw in texts.get(finding.path, "").splitlines():
                line = re.sub(r"\s+", "", raw)[:500]
                normalized.append(line)
                counts[line] = counts.get(line, 0) + 1
                occurrences.append(counts[line])
            cache[finding.path] = normalized, occurrences
        lines, occurrences = cache[finding.path]
        if not 1 <= finding.line <= len(lines):
            continue
        line = lines[finding.line - 1]
        if not line:
            continue
        occurrence = occurrences[finding.line - 1]
        key = f"{finding.path}\0{finding.cwe or finding.rule}\0{line}\0{occurrence}"
        finding.fingerprint = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]
