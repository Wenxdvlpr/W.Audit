"""Bounded, offline CycloneDX inventory from pinned manifests and npm locks."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import quote


MAX_LOCK_BYTES = 10_000_000
MAX_COMPONENTS = 20_000
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)$")


def _purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:{ecosystem}/{quote(name, safe='/')}@{quote(version, safe='.+-!')}"


def _integrity(value: object) -> list[dict[str, str]]:
    if not isinstance(value, str):
        return []
    for token in value.split():
        try:
            algorithm, encoded = token.split("-", 1)
            if algorithm not in {"sha1", "sha256", "sha384", "sha512"}:
                continue
            digest = base64.b64decode(encoded, validate=True)
            if len(digest) != {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}[algorithm]:
                continue
            return [{"alg": algorithm.upper().replace("SHA", "SHA-"), "content": digest.hex()}]
        except (ValueError, UnicodeError):
            continue
    return []


def _npm_name(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def _npm_ref(packages: dict[str, Any], package_path: str, dependency: str) -> str | None:
    parent = package_path
    while True:
        candidate = f"{parent}/node_modules/{dependency}" if parent else f"node_modules/{dependency}"
        entry = packages.get(candidate)
        if isinstance(entry, dict) and isinstance(entry.get("version"), str):
            return _purl("npm", _npm_name(candidate), entry["version"])
        if not parent:
            return None
        parent = parent.rsplit("/node_modules/", 1)[0] if "/node_modules/" in parent else ""


def generate(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("SBOM target must be a directory")
    components: dict[str, dict[str, Any]] = {}
    edges: dict[str, set[str]] = {}
    warnings: list[str] = []
    root_ref = "rivet:project"
    edges[root_ref] = set()

    for manifest in sorted(root.glob("**/requirements*.txt")):
        if manifest.is_symlink() or not manifest.is_file():
            continue
        if any(part in {".git", ".venv", "venv", "node_modules"} for part in manifest.relative_to(root).parts):
            continue
        if manifest.stat().st_size > MAX_LOCK_BYTES:
            warnings.append("Oversized Python requirements skipped")
            continue
        for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = line.split("#", 1)[0].strip()
            match = PIN.fullmatch(raw)
            if match:
                name, version = match.groups()
                ref = _purl("pypi", name, version)
                environment = "DEV" if any(tag in manifest.stem.lower() for tag in ("dev", "test", "lint")) else "RUNTIME"
                components.setdefault(ref, {"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref, "properties": [{"name": "rivet:dependency-type", "value": "direct"}, {"name": "rivet:environment", "value": environment}]})
                edges[root_ref].add(ref)
            elif raw and not raw.startswith(("-", ".")):
                warnings.append("Unpinned or unsupported Python requirement omitted")
            if len(components) >= MAX_COMPONENTS:
                raise ValueError("SBOM component limit exceeded")

    for lock in sorted(root.glob("**/package-lock.json")):
        if lock.is_symlink() or not lock.is_file():
            continue
        if any(part in {".git", ".venv", "venv", "node_modules"} for part in lock.relative_to(root).parts):
            continue
        if lock.stat().st_size > MAX_LOCK_BYTES:
            warnings.append("Oversized npm lockfile skipped")
            continue
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            warnings.append("Invalid npm lockfile skipped")
            continue
        packages = data.get("packages") if isinstance(data, dict) else None
        if not isinstance(packages, dict):
            warnings.append("npm lockfile without packages map skipped")
            continue
        for path, entry in packages.items():
            if not isinstance(path, str) or not path.startswith("node_modules/") or not isinstance(entry, dict):
                continue
            name, version = _npm_name(path), entry.get("version")
            if not isinstance(version, str) or not version:
                continue
            ref = _purl("npm", name, version)
            component = {"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref, "properties": [{"name": "rivet:dependency-type", "value": "dev" if entry.get("dev") is True else "transitive"}, {"name": "rivet:environment", "value": "DEV" if entry.get("dev") is True else "RUNTIME"}]}
            hashes = _integrity(entry.get("integrity"))
            if hashes:
                component["hashes"] = hashes
            components.setdefault(ref, component)
            edges.setdefault(ref, set())
            if len(components) >= MAX_COMPONENTS:
                raise ValueError("SBOM component limit exceeded")
        for path, entry in packages.items():
            if not isinstance(path, str) or not isinstance(entry, dict):
                continue
            if path and not path.startswith("node_modules/"):
                continue
            own = root_ref if not path else _purl("npm", _npm_name(path), entry["version"]) if isinstance(entry.get("version"), str) else None
            if own is None:
                continue
            for field in ("dependencies", "optionalDependencies", "devDependencies") if not path else ("dependencies", "optionalDependencies"):
                deps = entry.get(field)
                if not isinstance(deps, dict):
                    continue
                for dep in deps:
                    if not isinstance(dep, str):
                        continue
                    ref = _npm_ref(packages, path, dep)
                    if ref and ref in components:
                        edges.setdefault(own, set()).add(ref)
                        if not path:
                            for prop in components[ref]["properties"]:
                                if prop["name"] == "rivet:dependency-type":
                                    prop["value"] = "dev" if field == "devDependencies" else "direct"
                                if prop["name"] == "rivet:environment":
                                    prop["value"] = "DEV" if field == "devDependencies" else "RUNTIME"

    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": {"component": {"type": "application", "bom-ref": root_ref, "name": root.name}}, "components": sorted(components.values(), key=lambda c: c["bom-ref"]), "dependencies": [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(edges.items())], "properties": [{"name": "rivet:limitations", "value": warning} for warning in sorted(set(warnings))]}
