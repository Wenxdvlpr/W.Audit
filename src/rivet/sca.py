"""Canonical dependency vulnerability data shared by SCA adapters."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from .redact import redact


@dataclass(frozen=True)
class DependencyVulnerability:
    ecosystem: str
    package: str
    installed_version: str
    vulnerable_range: str
    fixed_version: str
    advisory_id: str
    cve: str
    ghsa: str
    osv_id: str
    upstream_severity: str
    rivet_severity: str
    dependency_type: str
    directness: str
    environment: str
    reachability: str
    source_scanner: str
    evidence: str
    remediation: str

    def data(self) -> dict[str, str]:
        return {key: redact(value) for key, value in asdict(self).items()}


def dependency_context(root: Path, source_path: str, package: dict[str, Any]) -> dict[str, str]:
    """Infer only lockfile-backed dependency scope; never infer reachability."""
    name = package.get("name")
    if not isinstance(name, str) or not name or len(name) > 200:
        return {"directness": "UNKNOWN", "environment": "UNKNOWN"}
    source = Path(source_path)
    if source.is_absolute() or ".." in source.parts:
        return {"directness": "UNKNOWN", "environment": "UNKNOWN"}
    manifest = root / source
    if source.name == "package-lock.json" and manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 10_000_000:
        try:
            lock = json.loads(manifest.read_text(encoding="utf-8"))
            packages = lock.get("packages") if isinstance(lock, dict) else None
            top = packages.get("") if isinstance(packages, dict) else None
            if not isinstance(top, dict):
                return {"directness": "UNKNOWN", "environment": "UNKNOWN"}
            runtime = set()
            development = set()
            for field in ("dependencies", "optionalDependencies"):
                value = top.get(field)
                if isinstance(value, dict):
                    runtime.update(k for k in value if isinstance(k, str))
            for field in ("devDependencies",):
                value = top.get(field)
                if isinstance(value, dict):
                    development.update(k for k in value if isinstance(k, str))
            if name in runtime:
                return {"directness": "DIRECT", "environment": "RUNTIME"}
            if name in development:
                return {"directness": "DIRECT", "environment": "DEV"}
            if isinstance(packages, dict):
                entries = [v for k, v in packages.items() if isinstance(k, str) and k.startswith("node_modules/") and k.rsplit("node_modules/", 1)[-1] == name and isinstance(v, dict)]
                if entries:
                    return {"directness": "TRANSITIVE", "environment": "DEV" if all(v.get("dev") is True for v in entries) else "RUNTIME"}
        except (OSError, ValueError, UnicodeError, RecursionError):
            pass
    if source.name.startswith("requirements") and source.suffix == ".txt":
        environment = "DEV" if any(tag in source.stem.lower() for tag in ("dev", "test", "lint")) else "RUNTIME"
        return {"directness": "DIRECT", "environment": environment}
    return {"directness": "UNKNOWN", "environment": "UNKNOWN"}


def from_osv(package: dict[str, Any], vulnerability: dict[str, Any], context: dict[str, str] | None = None) -> DependencyVulnerability:
    context = context or {}
    aliases = vulnerability.get("aliases", [])
    aliases = aliases if isinstance(aliases, list) else []
    ids = [str(vulnerability.get("id", "unknown"))] + [str(item) for item in aliases if isinstance(item, str)]
    vid = ids[0][:100]
    cve = next((item for item in ids if item.startswith("CVE-")), "")[:100]
    ghsa = next((item for item in ids if item.startswith("GHSA-")), "")[:100]
    fixed: list[str] = []
    ranges: list[str] = []
    affected = vulnerability.get("affected", [])
    for item in affected[:20] if isinstance(affected, list) else []:
        if not isinstance(item, dict):
            continue
        for raw_range in item.get("ranges", [])[:20] if isinstance(item.get("ranges"), list) else []:
            if not isinstance(raw_range, dict) or raw_range.get("type") != "ECOSYSTEM":
                continue
            events = raw_range.get("events", [])
            for event in events[:20] if isinstance(events, list) else []:
                if not isinstance(event, dict):
                    continue
                if isinstance(event.get("introduced"), str):
                    ranges.append("introduced " + event["introduced"][:80])
                if isinstance(event.get("fixed"), str):
                    fixed.append(event["fixed"][:80])
                    ranges.append("fixed " + event["fixed"][:80])
    upstream = "UNKNOWN"
    specific = vulnerability.get("database_specific")
    if isinstance(specific, dict) and str(specific.get("severity", "")).upper() in {"LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}:
        upstream = str(specific["severity"]).upper()
    return DependencyVulnerability(
        ecosystem=str(package.get("ecosystem", "unknown"))[:80],
        package=str(package.get("name", "dependency"))[:100],
        installed_version=str(package.get("version", "unknown"))[:80],
        vulnerable_range=", ".join(ranges)[:300] or "UNKNOWN",
        fixed_version=", ".join(sorted(set(fixed)))[:200] or "UNKNOWN",
        advisory_id=vid,
        cve=cve,
        ghsa=ghsa,
        osv_id=vid,
        upstream_severity=upstream,
        rivet_severity="MEDIUM",
        dependency_type=context.get("directness", "UNKNOWN"),
        directness=context.get("directness", "UNKNOWN"),
        environment=context.get("environment", "UNKNOWN"),
        reachability="UNKNOWN",
        source_scanner="OSV-Scanner",
        evidence=f"OSV advisory {vid}; installed version {package.get('version', 'unknown')}",
        remediation="Review advisory and update to a fixed version where available.",
    )
