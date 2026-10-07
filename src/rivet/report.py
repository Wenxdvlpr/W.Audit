from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import html
import json
from pathlib import Path
import re

from .model import Finding, Check
from .redact import redact
from . import __version__


def clean(value: object) -> str:
    return redact(value)


def md(value: object) -> str:
    return clean(value).replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("<", "&lt;").replace(">", "&gt;")


def sarif(findings: list[Finding]) -> dict:
    rules = {f.rule: {"id": f.rule, "name": clean(f.title), "shortDescription": {"text": clean(f.title)}} for f in findings}
    results = []
    for f in findings:
        results.append({"ruleId": f.rule, "level": {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}[f.severity], "message": {"text": clean(f.title + ": " + f.evidence)}, "fingerprints": {"rivet/v1": f.fingerprint}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": f.line}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "W.Audit", "version": __version__, "rules": list(rules.values())}}, "results": results}]}


def validate_sarif(document: object) -> None:
    if not isinstance(document, dict) or document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list) or len(document["runs"]) != 1:
        raise ValueError("invalid SARIF envelope")
    run = document["runs"][0]
    if not isinstance(run, dict) or not isinstance(run.get("tool"), dict) or not isinstance(run["tool"].get("driver"), dict) or not isinstance(run.get("results"), list):
        raise ValueError("invalid SARIF run")
    driver = run["tool"]["driver"]
    if driver.get("name") not in {"W.Audit", "Rivet"} or not isinstance(driver.get("rules"), list):
        raise ValueError("invalid SARIF driver")
    ids = {item.get("id") for item in driver["rules"] if isinstance(item, dict)}
    for result in run["results"]:
        if not isinstance(result, dict) or result.get("ruleId") not in ids or result.get("level") not in {"error", "warning", "note"}:
            raise ValueError("invalid SARIF result")
        try:
            place = result["locations"][0]["physicalLocation"]
            uri = place["artifactLocation"]["uri"]
            line = place["region"]["startLine"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("invalid SARIF location") from exc
        if not isinstance(uri, str) or not uri or not isinstance(line, int) or line < 1:
            raise ValueError("invalid SARIF location")


def markdown(data: dict, findings: list[Finding], checks: list[Check]) -> str:
    counts = Counter(f.severity for f in findings)
    profile = data["profile"]
    lines = ["# W.Audit security audit", "", "No audit proves a project is fully secure. Findings apply only to the checks listed below.", "", "## Project security profile", ""]
    for key in ("languages", "frameworks", "infrastructure", "databases", "security_areas"):
        lines.append(f"- **{key.replace('_', ' ').title()}:** {md(', '.join(profile[key]) or 'not detected')}")
    lines += ["", "## Executive summary", "", f"HIGH: {counts['HIGH']} · MEDIUM: {counts['MEDIUM']} · LOW: {counts['LOW']}", "", "## Security coverage matrix", "", "| Area | Status | Scanner | Result |", "| --- | --- | --- | --- |"]
    for row in data["coverage_matrix"]:
        lines.append(f"| {md(row['area'])} | {md(row['status'])} | {md(row['scanner'])} | {md(row['result'])} |")
    routes = data.get("route_matrix", [])
    if routes:
        lines += ["", "## Route authorization matrix", "", "| Method | Endpoint | Authentication | Authorization |", "| --- | --- | --- | --- |"]
        for route in routes:
            lines.append(f"| {md(route['method'])} | {md(route['path'])} | {md(route['authentication'])} | {md(route['authorization'])} |")
    authorization_matrix = data.get("authorization_matrix", [])
    if authorization_matrix:
        lines += ["", "## Role authorization matrix", "", "Statuses are static inferences, not verified access-control behavior.", "", "| Role | Method | Endpoint | Status |", "| --- | --- | --- | --- |"]
        for cell in authorization_matrix:
            lines.append(f"| {md(cell['role'])} | {md(cell['method'])} | {md(cell['endpoint'])} | {md(cell['status'])} |")
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings from the checks performed.")
    for f in findings:
        lines += [f"### {md(f.severity)} · {md(f.title)}", "", f"- **ID:** `{f.fingerprint}`", f"- **Location:** `{md(f.path)}:{f.line}`", f"- **Confidence / exploitability:** {f.confidence} / {f.exploitability}", f"- **Analysis:** {f.flow_kind}", f"- **Category / CWE / scanner:** {md(f.category)} / {md(f.cwe or '—')} / {md(f.scanner)}", f"- **Evidence:** {md(f.evidence)}", f"- **Technical explanation:** {md(f.technical_explanation or f.impact)}", f"- **Simple explanation:** {md(f.simple_explanation or f.impact)}", f"- **Fix:** {md(f.fix)}", f"- **Verify:** {md(f.verify)}", ""]
    lines += ["## Limitations", ""]
    lines.extend(f"- {md(x)}" for x in data["limitations"])
    return "\n".join(lines) + "\n"


def write_reports(out: Path, data: dict, findings: list[Finding], checks: list[Check]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "security-report.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_text = markdown(data, findings, checks)
    (out / "security-report.md").write_text(markdown_text, encoding="utf-8")
    sarif_data = sarif(findings)
    validate_sarif(sarif_data)
    (out / "security-report.sarif").write_text(json.dumps(sarif_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "security-report.html").write_text("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>W.Audit security audit</title><style>body{font:16px system-ui;max-width:900px;margin:3rem auto;padding:1rem;line-height:1.5}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>W.Audit security audit</h1><pre>" + html.escape(markdown_text, quote=True) + "</pre></html>\n", encoding="utf-8")


def make_data(root: Path, profile: dict, findings: list[Finding], checks: list[Check], profile_name: str) -> dict:
    limitations = ["Built-in SAST covers selected Python and JS/TS patterns only; no complete interprocedural data-flow analysis.", "Credential validity and dependency reachability were not tested.", "Cloud accounts, mobile binaries and business logic require manual review."]
    if profile_name == "dynamic":
        limitations.append("Dynamic mode sends one HEAD request only; it does not test authentication, authorization or request bodies.")
    elif profile_name == "api-test":
        limitations.append("API probes use only documented GET/HEAD routes and OPTIONS preflight. They do not test write operations, do not follow redirects, and require manual review; OpenAPI declarations are untrusted hints.")
    else:
        limitations.append("No application code, dynamic tests or production endpoints were executed.")
    limitations += [f"{c.category}: {c.detail}" for c in checks if c.status not in {"CHECKED", "COMPLETED"}]
    def matches(check: Check, finding: Finding) -> bool:
        if check.category == "Secrets":
            return finding.category == "Secrets"
        if check.category == "Source SAST":
            return finding.category in {"SQL injection", "Command injection", "Path traversal", "Template injection", "Open redirect", "SSRF", "Deserialization", "Code execution", "XSS", "Authentication", "AI/LLM"}
        if check.category == "Infrastructure and CI":
            return finding.category in {"Container", "Supply chain", "Infrastructure", "Kubernetes", "CI supply chain", "CI injection", "Database"}
        if check.category == "Python routes and authorization":
            return finding.category == "Authorization"
        if check.category == "Vibe coding":
            return finding.category == "Vibe coding"
        return finding.scanner.lower() == check.tool.lower()

    matrix = []
    for check in checks:
        count = sum(matches(check, finding) for finding in findings)
        result = (str(count) + " findings") if count else "PASS" if check.status in {"CHECKED", "COMPLETED"} else check.detail or "Not run"
        matrix.append({"area": check.category, "status": check.status, "scanner": check.tool, "result": clean(result)})
    if profile_name != "dynamic":
        matrix.append({"area": "Dynamic API", "status": "SKIPPED", "scanner": "—", "result": "No test environment or dynamic request"})
    matrix.append({"area": "Android", "status": "N/A" if "Dart" not in profile["languages"] else "NOT IMPLEMENTED", "scanner": "—", "result": "No mobile binary analysis"})
    return {"schema_version": "1.1", "project": clean(root.name), "profile_name": profile_name, "profile": profile, "summary": dict(Counter(f.severity for f in findings)), "checks": [asdict(c) for c in checks], "coverage_matrix": matrix, "findings": [f.data() for f in findings], "limitations": limitations}
