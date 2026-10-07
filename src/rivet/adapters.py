from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Callable

from .checks import make
from .model import Check, Finding
from .sca import dependency_context, from_osv

MAX_OUTPUT = 10_000_000


def scanner_version(name: str) -> str:
    if shutil.which(name) is None:
        return "NOT_INSTALLED"
    argv = [name, "scan", "--version", "--disable-version-check"] if name == "semgrep" else [name, "--version"]
    try:
        completed = subprocess.run(argv, shell=False, capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "AVAILABLE (version unavailable)"
    if completed.returncode != 0:
        return "AVAILABLE (version unavailable)"
    output = (completed.stdout or completed.stderr)[:200].decode("utf-8", "replace").strip().splitlines()
    return "AVAILABLE " + (output[0][:80] if output else "(version unavailable)")


@dataclass(frozen=True)
class ScannerAdapter:
    name: str
    category: str
    purpose: str
    install_url: str
    network: bool
    runner: Callable[[Path, Path], tuple[list[Finding], Check]] | None


def _safe_rel(root: Path, value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    try:
        path = Path(value)
        resolved = (path if path.is_absolute() else root / path).resolve(strict=False)
        relative = resolved.relative_to(root.resolve()).as_posix()
        return relative if relative != "." else None
    except (ValueError, OSError, RuntimeError):
        return None


def _invoke(argv: list[str], root: Path, accepted_exits: tuple[int, ...] = (0, 1)) -> tuple[dict | None, str]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(argv, cwd=root, shell=False, stdout=stdout, stderr=stderr, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            return None, "TIMEOUT: scanner exceeded 120 seconds"
        except OSError:
            return None, "scanner could not start"
        if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
            return None, "scanner output limit exceeded"
        if completed.returncode == 128 and argv[0].endswith("osv-scanner"):
            stderr.seek(0)
            if b"No package sources found" in stderr.read(4096):
                return None, "NO_SOURCES"
        if completed.returncode not in accepted_exits:
            return None, f"scanner exit {completed.returncode}"
        stdout.seek(0)
        try:
            data = json.loads(stdout.read().decode("utf-8", "replace"))
        except (ValueError, UnicodeError, RecursionError):
            return None, f"invalid JSON or scanner exit {completed.returncode}"
        if not isinstance(data, dict):
            return None, "unexpected JSON root"
    if completed.returncode == 1 and data.get("results") == []:
        return None, "scanner exited with error and no findings"
    return data, ""


def _line(value: object) -> int:
    try:
        return max(1, min(int(str(value)[:10]), 1_000_000_000))
    except (ValueError, TypeError):
        return 1


def _cwe(value: object) -> str:
    if isinstance(value, dict):
        value = value.get("id")
    raw = str(value)
    return "CWE-" + raw if raw.isdigit() and len(raw) <= 5 else ""


def _check(category: str, tool: str, error: str) -> Check:
    return Check(category, "TIMEOUT" if error.startswith("TIMEOUT:") else "FAILED", tool, error)


def _sev(value: object) -> str:
    raw = str(value).upper()
    return "HIGH" if raw in {"HIGH", "CRITICAL", "ERROR"} else "MEDIUM" if raw in {"MEDIUM", "WARNING"} else "LOW"


def _unconfirmed_severity(value: object) -> str:
    severity = _sev(value)
    return "MEDIUM" if severity == "HIGH" else severity


def semgrep(root: Path, rules: Path) -> tuple[list[Finding], Check]:
    data, error = _invoke(["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check", "--config", str(rules), str(root)], root)
    if error:
        return [], _check("SAST", "Semgrep", error)
    if data.get("errors"):
        return [], _check("SAST", "Semgrep", "scanner reported scan errors")
    if not isinstance(data.get("results"), list):
        return [], _check("SAST", "Semgrep", "invalid results")
    findings = []
    for item in data.get("results", [])[:10000]:
        if not isinstance(item, dict):
            continue
        rel = _safe_rel(root, item.get("path"))
        if rel is None:
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        line = item.get("start", {}).get("line", 1) if isinstance(item.get("start"), dict) else 1
        rule = str(item.get("check_id", "semgrep/unknown"))[-200:]
        cwe = "CWE-78" if rule.endswith("rivet.python.subprocess-shell") else ""
        findings.append(make(rule, str(extra.get("message", "Semgrep finding"))[:300], _unconfirmed_severity(extra.get("severity")), "MEDIUM", "SAST", rel, _line(line), "Semgrep rule match; inspect source at location", "The matched code may cross a security boundary.", "Review Semgrep guidance and use a safe API.", "Confirm the data flow and rerun Semgrep.", scanner="Semgrep", cwe=cwe, exploitability="THEORETICAL"))
    return findings, Check("SAST", "CHECKED", "Semgrep")


def bandit(root: Path) -> tuple[list[Finding], Check]:
    data, error = _invoke(["bandit", "-r", "-f", "json", "-q", str(root)], root)
    if error:
        return [], _check("Python SAST", "Bandit", error)
    if data.get("errors"):
        return [], _check("Python SAST", "Bandit", "scanner reported scan errors")
    if not isinstance(data.get("results"), list):
        return [], _check("Python SAST", "Bandit", "invalid results")
    findings = []
    for item in data.get("results", [])[:10000]:
        if not isinstance(item, dict):
            continue
        rel = _safe_rel(root, item.get("filename"))
        if rel is None:
            continue
        findings.append(make("bandit/" + str(item.get("test_id", "unknown"))[:30], str(item.get("issue_text", "Bandit finding"))[:300], _unconfirmed_severity(item.get("issue_severity")), _sev(item.get("issue_confidence")), "Python SAST", rel, _line(item.get("line_number", 1)), "Bandit rule match; inspect source at location", "A security-sensitive pattern requires review.", "Follow the rule guidance and validate the data flow.", "Rerun Bandit and relevant regression tests.", scanner="Bandit", cwe=_cwe(item.get("issue_cwe")), exploitability="THEORETICAL"))
    return findings, Check("Python SAST", "CHECKED", "Bandit")


def gitleaks(root: Path) -> tuple[list[Finding], Check]:
    if not (root / ".git").exists():
        return [], Check("Git history secrets", "SKIPPED", "Gitleaks", "no Git repository at audit root")
    binary = shutil.which("gitleaks")
    if binary is None:
        return [], Check("Git history secrets", "NOT_INSTALLED", "Gitleaks", "scanner executable not found")
    with tempfile.TemporaryDirectory() as temp:
        report = Path(temp) / "report.json"
        try:
            with tempfile.TemporaryFile() as output:
                completed = subprocess.run([binary, "detect", "--source", str(root), "--report-format", "json", "--report-path", str(report), "--no-banner", "--redact"], cwd=root, stdout=output, stderr=output, timeout=120, check=False)
                if output.tell() > MAX_OUTPUT:
                    return [], Check("Git history secrets", "FAILED", "Gitleaks", "scanner output limit exceeded")
                if completed.returncode not in (0, 1):
                    return [], Check("Git history secrets", "FAILED", "Gitleaks", f"scanner exit {completed.returncode}")
            if report.exists() and report.stat().st_size > MAX_OUTPUT:
                return [], Check("Git history secrets", "FAILED", "Gitleaks", "report limit exceeded")
            if completed.returncode == 1 and not report.exists():
                return [], Check("Git history secrets", "FAILED", "Gitleaks", "scanner reported findings without a report")
            data = json.loads(report.read_text()) if report.exists() else []
        except subprocess.TimeoutExpired:
            return [], Check("Git history secrets", "TIMEOUT", "Gitleaks", "scanner exceeded 120 seconds")
        except (OSError, ValueError):
            return [], Check("Git history secrets", "FAILED", "Gitleaks", "scanner failed or invalid report")
    if not isinstance(data, list):
        return [], Check("Git history secrets", "FAILED", "Gitleaks", "unexpected JSON root")
    findings = []
    for item in data[:10000]:
        if not isinstance(item, dict):
            continue
        rel = _safe_rel(root, item.get("File", ""))
        if rel is None:
            continue
        raw_line = item.get("StartLine", 1)
        line = _line(raw_line)
        findings.append(make("gitleaks/" + str(item.get("RuleID", "secret"))[:100], "Potential secret in Git history", "MEDIUM", "MEDIUM", "Secrets", rel, line, "Gitleaks matched a secret; value redacted", "A removed secret may remain usable until revoked.", "Revoke, rotate and assess history cleanup.", "Verify revocation and rerun Gitleaks.", scanner="Gitleaks", cwe="CWE-798"))
    return findings, Check("Git history secrets", "CHECKED", "Gitleaks")


def osv(root: Path) -> tuple[list[Finding], Check]:
    data, error = _invoke(["osv-scanner", "scan", "source", "--format", "json", "--verbosity", "error", "--no-resolve", "--all-packages", "--recursive", str(root)], root)
    if error:
        if error == "NO_SOURCES":
            return [], Check("Dependencies", "SKIPPED", "OSV-Scanner", "no supported dependency source found")
        return [], _check("Dependencies", "OSV-Scanner", error)
    if data.get("errors"):
        return [], _check("Dependencies", "OSV-Scanner", "scanner reported scan errors")
    if not isinstance(data.get("results"), list):
        return [], _check("Dependencies", "OSV-Scanner", "invalid results")
    if not data["results"]:
        return [], Check("Dependencies", "SKIPPED", "OSV-Scanner", "no supported dependency source found")
    findings = []
    for result in data.get("results", [])[:1000]:
        if not isinstance(result, dict):
            continue
        rel = _safe_rel(root, result.get("source", {}).get("path", "") if isinstance(result.get("source"), dict) else "")
        if rel is None:
            continue
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            continue
        for package in packages[:1000]:
            if not isinstance(package, dict):
                continue
            pkg = package.get("package") if isinstance(package.get("package"), dict) else {}
            name = str(pkg.get("name", "dependency"))[:100]
            version = str(pkg.get("version", "unknown"))[:80]
            ecosystem = str(pkg.get("ecosystem", "unknown"))[:80]
            vulnerabilities = package.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue
            for vuln in vulnerabilities[:100]:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("id", "unknown"))[:100]
                finding = make("osv/" + vid + "/" + ecosystem + "/" + name, f"Known vulnerability in {ecosystem} {name} {version}: {vid}", "MEDIUM", "HIGH", "Dependencies", rel, 1, f"OSV advisory {vid}; installed {version}; reachability UNKNOWN", "A vulnerable package may expose the application if affected code is reachable.", "Review advisory and update or mitigate the dependency.", "Check affected versions, reachability and rerun OSV-Scanner.", scanner="OSV-Scanner", exploitability="CONDITIONAL")
                finding.dependency = from_osv(pkg, vuln, dependency_context(root, rel, pkg)).data()
                findings.append(finding)
    return findings, Check("Dependencies", "CHECKED", "OSV-Scanner")


ADAPTERS = (
    ScannerAdapter("semgrep", "SAST", "SAST with bundled local rules", "https://semgrep.dev/docs/getting-started/", False, lambda root, rules: semgrep(root, rules)),
    ScannerAdapter("bandit", "Python SAST", "Python security checks", "https://bandit.readthedocs.io/en/latest/start.html", False, lambda root, rules: bandit(root)),
    ScannerAdapter("gitleaks", "Git history secrets", "Secret and Git history scan", "https://github.com/gitleaks/gitleaks", False, lambda root, rules: gitleaks(root)),
    ScannerAdapter("osv-scanner", "Dependencies", "Known advisories; npm SCA is experimental", "https://google.github.io/osv-scanner/", True, lambda root, rules: osv(root)),
)
PLANNED = (
    ScannerAdapter("gosec", "Go SAST", "Go security checks", "https://github.com/securego/gosec", False, None),
    ScannerAdapter("eslint-security", "JS/TS SAST", "ESLint security rules", "https://eslint.org/", False, None),
    ScannerAdapter("cargo-audit", "Rust SCA", "Rust dependency advisories", "https://github.com/RustSec/rustsec", True, None),
)


def run_external(root: Path, rules: Path, offline: bool, disabled: set[str] | None = None) -> tuple[list[Finding], list[Check]]:
    findings, checks = [], []
    disabled = disabled or set()
    for adapter in ADAPTERS:
        if adapter.name in disabled:
            checks.append(Check(adapter.category, "DISABLED", adapter.name, "disabled in config"))
        elif offline and adapter.network:
            checks.append(Check(adapter.category, "DISABLED", adapter.name, "offline mode"))
        elif shutil.which(adapter.name) is None:
            checks.append(Check(adapter.category, "NOT_INSTALLED", adapter.name, adapter.install_url))
        else:
            if adapter.runner is None:
                checks.append(Check(adapter.category, "FAILED", adapter.name, "adapter has no runner"))
                continue
            try:
                found, check = adapter.runner(root, rules)
            except Exception as exc:
                checks.append(Check(adapter.category, "FAILED", adapter.name, f"adapter raised {type(exc).__name__}; remaining checks continued"))
                continue
            findings.extend(found)
            if check.status == "CHECKED":
                check.status = "COMPLETED"
            checks.append(check)
    return findings, checks
