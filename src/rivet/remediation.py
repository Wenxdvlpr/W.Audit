from __future__ import annotations

from .redact import redact


def classify(rule: str) -> str:
    if rule.startswith("secret/") or rule.startswith("terraform/") or rule.startswith("k8s/"):
        return "MANUAL_ONLY"
    if rule in {"hygiene/missing-gitignore", "http/missing-nosniff"}:
        return "SAFE_AUTOFIX"
    return "REVIEW_REQUIRED"


def plan(report: dict) -> dict:
    items = []
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue
        rule = str(finding.get("rule", ""))
        items.append({"fingerprint": redact(finding.get("fingerprint", ""), 100), "rule": redact(rule, 200), "title": redact(finding.get("title", ""), 300), "class": classify(rule), "recommended_fix": redact(finding.get("fix", ""), 1000)})
    return {"schema_version": "1.0", "modifies_files": False, "items": items}
