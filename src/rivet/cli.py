from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import sys

from . import __version__
from .adapters import ADAPTERS, PLANNED, run_external, scanner_version
from .checks import run_builtin
from .config import PROFILES, load_config
from .discovery import discover
from .model import Check, SEVERITIES, deduplicate, stabilize_fingerprints
from .report import make_data, write_reports, clean
from .routes import analyze_python_routes, build_authorization_matrix
from .vibe import scan_vibe
from .dynamic import check_headers, validate_target
from .remediation import plan
from .walk import safe_files, read_text
from .sbom import generate as generate_sbom
from .api_test import run_safe_api_tests

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rivet", description="Local-first repository security audit")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("path", type=Path)
    scan.add_argument("--profile", choices=PROFILES, default="auto")
    scan.add_argument("--offline", action="store_true")
    scan.add_argument("--external", action="store_true", help="Explicitly run installed third-party scanners, including experimental npm OSV SCA")
    scan.add_argument("--out", type=Path, default=Path("security-audit-output"))
    scan.add_argument("--fail-on", choices=("none", "low", "medium", "high"), default="none")
    scan.add_argument("--simple", action="store_true")
    scan.add_argument("--technical", action="store_true")
    scan.add_argument("--exclude", action="append", default=[], help="Root-relative file or directory to skip (repeatable)")
    scan.add_argument("--config", type=Path, help="Strict JSON configuration file")
    dynamic = sub.add_parser("dynamic", help="EXPERIMENTAL explicit safe HTTP HEAD baseline")
    dynamic.add_argument("url")
    dynamic.add_argument("--test-environment", action="store_true", required=False, help="Explicit opt-in; use only on localhost or an authorized test environment")
    dynamic.add_argument("--allow-host", action="append", default=[])
    dynamic.add_argument("--out", type=Path, default=Path("security-audit-output"))
    api_test = sub.add_parser("api-test", help="EXPERIMENTAL bounded probes for OpenAPI read-only routes")
    api_test.add_argument("base_url")
    api_test.add_argument("--openapi", type=Path, required=True, help="Local OpenAPI JSON document")
    api_test.add_argument("--test-environment", action="store_true", help="Explicit experimental opt-in; use only on localhost or an authorized test environment")
    api_test.add_argument("--allow-host", action="append", default=[])
    api_test.add_argument("--out", type=Path, default=Path("security-audit-output/api-test"))
    sub.add_parser("doctor")
    sbom = sub.add_parser("sbom", help="Generate an offline CycloneDX JSON inventory")
    sbom.add_argument("path", type=Path)
    sbom.add_argument("--output", type=Path, default=Path("sbom.cdx.json"))
    sbom.add_argument("--format", choices=("cyclonedx",), default="cyclonedx")
    sbom.add_argument("--offline", action="store_true", help="Explicit offline mode; SBOM is always local")
    base = sub.add_parser("baseline")
    bs = base.add_subparsers(dest="baseline_command", required=True)
    create = bs.add_parser("create")
    create.add_argument("report", type=Path)
    create.add_argument("--out", type=Path, default=Path("security-baseline.json"))
    compare = bs.add_parser("compare")
    compare.add_argument("report", type=Path)
    compare.add_argument("baseline", type=Path)
    planning = sub.add_parser("plan-fix", help="Read-only remediation classification")
    planning.add_argument("report", type=Path)
    verify = sub.add_parser("verify", help="Rescan and check one prior finding")
    verify.add_argument("path", type=Path)
    verify.add_argument("--against", type=Path, required=True)
    verify.add_argument("--finding", required=True)
    verify.add_argument("--out", type=Path, default=Path("security-audit-output/retest"))
    return p


def scan(args) -> int:
    try:
        root = args.path.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("audit path must be a directory")
        config = load_config(args.config)
        profile_name = args.profile if args.profile != "auto" else config.profile
        fail_on = args.fail_on if args.fail_on != "none" else config.fail_on
        excludes = config.exclude + tuple(x.strip("/") for x in args.exclude if x and x.strip("/") and ".." not in Path(x).parts)
        try:
            output_rel = args.out.resolve().relative_to(root).as_posix()
            if output_rel != ".":
                excludes += (output_rel,)
        except ValueError:
            pass
        files = list(safe_files(root, excludes, config.include))
        texts = {}
        for path, rel in files:
            value = read_text(path)
            if value is not None:
                texts[rel] = value
        profile = discover(files, texts)
        findings, checks = run_builtin(texts)
        if profile_name == "vibe":
            for rel, value in texts.items():
                findings.extend(scan_vibe(rel, value))
            checks.append(Check("Vibe coding", "CHECKED", "W.Audit vibe rules", "Selected Python and frontend rules"))
        routes = []
        for rel, value in texts.items():
            if rel.endswith(".py"):
                detected, route_findings = analyze_python_routes(rel, value)
                routes.extend(detected)
                findings.extend(route_findings)
        checks.append(Check("Python routes and authorization", "CHECKED", "W.Audit AST", "Heuristic; manual review required"))
        offline = args.offline or config.offline or profile_name == "offline"
        if args.external and (config.include or config.exclude or args.exclude):
            checks.append(Check("External scanners", "SKIPPED", "third-party adapters", "include/exclude filters cannot yet be enforced for external tools"))
        elif args.external:
            rules = Path(__file__).resolve().parent / "rules" / "semgrep.yml"
            external_findings, external_checks = run_external(root, rules, offline, set(config.disabled_scanners))
            findings.extend(external_findings)
            checks.extend(external_checks)
        else:
            checks.append(Check("External scanners", "SKIPPED", "Semgrep/Bandit/Gitleaks/OSV-Scanner", "Use --external to enable installed tools"))
        findings = deduplicate(findings)
        stabilize_fingerprints(findings, texts)
        data = make_data(root, profile, findings, checks, profile_name)
        data["offline"] = offline
        data["route_matrix"] = routes
        data["authorization_matrix"] = build_authorization_matrix(routes)
        write_reports(args.out, data, findings, checks)
        counts = data["summary"]
        print(f"W.Audit {__version__} · {clean(root.name)}")
        print(f"Detected: {clean(', '.join(profile['languages'] + profile['frameworks'] + profile['infrastructure']) or 'unknown')}")
        print(f"HIGH {counts.get('HIGH', 0)} · MEDIUM {counts.get('MEDIUM', 0)} · LOW {counts.get('LOW', 0)}")
        print(f"Reports: {clean(args.out.resolve())}")
        if fail_on != "none":
            threshold = SEVERITIES.index(fail_on.upper())
            if any(SEVERITIES.index(f.severity) <= threshold for f in findings):
                return 1
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"rivet: {clean(exc)}", file=sys.stderr)
        return 2


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError("invalid report or baseline")
    return data


def baseline(args) -> int:
    try:
        report = _load(args.report)
        current = {str(f["fingerprint"]) for f in report["findings"] if isinstance(f, dict) and "fingerprint" in f}
        if args.baseline_command == "create":
            args.out.write_text(json.dumps({"schema_version": "1.0", "findings": [{"fingerprint": x} for x in sorted(current)]}, indent=2) + "\n", encoding="utf-8")
            print(f"Baseline created: {args.out}")
        else:
            old = {str(f["fingerprint"]) for f in _load(args.baseline)["findings"] if isinstance(f, dict) and "fingerprint" in f}
            previous = {str(f["fingerprint"]): str(f.get("status", "OPEN")) for f in _load(args.baseline)["findings"] if isinstance(f, dict) and "fingerprint" in f}
            regressed = {key for key in current & old if previous.get(key) in {"FIXED", "MITIGATED", "FALSE_POSITIVE"}}
            print(json.dumps({"NEW": sorted(current - old), "EXISTING": sorted((current & old) - regressed), "FIXED": sorted(old - current), "REGRESSED": sorted(regressed)}, indent=2))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"rivet: {clean(exc)}", file=sys.stderr)
        return 2


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.command == "scan":
        return scan(args)
    if args.command == "baseline":
        return baseline(args)
    if args.command == "sbom":
        try:
            document = generate_sbom(args.path)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"CycloneDX components: {len(document['components'])} · {clean(args.output.resolve())}")
            return 0
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"rivet: {clean(exc)}", file=sys.stderr)
            return 2
    if args.command == "plan-fix":
        try:
            print(json.dumps(plan(_load(args.report)), indent=2, ensure_ascii=False))
            return 0
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"rivet: {clean(exc)}", file=sys.stderr)
            return 2
    if args.command == "verify":
        try:
            prior = _load(args.against)
            known = {str(item.get("fingerprint")) for item in prior["findings"] if isinstance(item, dict)}
            if args.finding not in known:
                raise ValueError("finding fingerprint not present in prior report")
            scan_args = argparse.Namespace(path=args.path, profile="auto", offline=True, external=False, out=args.out, fail_on="none", simple=False, technical=False, exclude=[], config=None)
            with contextlib.redirect_stdout(io.StringIO()):
                code = scan(scan_args)
            if code != 0:
                return code
            current = _load(args.out / "security-report.json")
            active = {str(item.get("fingerprint")) for item in current["findings"] if isinstance(item, dict)}
            status = "STILL_PRESENT" if args.finding in active else "FIXED"
            print(json.dumps({"finding": args.finding, "status": status, "report": str(args.out.resolve())}, indent=2))
            return 0
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"rivet: {clean(exc)}", file=sys.stderr)
            return 2
    if args.command == "dynamic":
        if not args.test_environment:
            print("rivet: --test-environment is required for dynamic checks", file=sys.stderr)
            return 2
        print("WARNING: EXPERIMENTAL live HTTP check; use only against localhost or an authorized test environment.", file=sys.stderr)
        try:
            host = validate_target(args.url, tuple(args.allow_host))
            findings, checks = check_headers(args.url, tuple(args.allow_host))
            profile = {"languages": [], "frameworks": [], "infrastructure": [], "databases": [], "security_areas": []}
            data = make_data(Path(host), profile, findings, checks, "dynamic")
            data["target"] = clean(args.url)
            write_reports(args.out, data, findings, checks)
            print(f"Dynamic HEAD baseline: {clean(host)} · {len(findings)} findings")
            return 0
        except ValueError as exc:
            print(f"rivet: {clean(exc)}", file=sys.stderr)
            return 2
        except RuntimeError as exc:
            print(f"rivet: {clean(exc)}", file=sys.stderr)
            return 3
    if args.command == "api-test":
        if not args.test_environment:
            print("rivet: --test-environment is required for API probes", file=sys.stderr)
            return 2
        print("WARNING: EXPERIMENTAL live API probes; use only against localhost or an authorized test environment.", file=sys.stderr)
        try:
            host = validate_target(args.base_url, tuple(args.allow_host))
            findings, checks, routes, auth_matrix = run_safe_api_tests(args.base_url, args.openapi, tuple(args.allow_host))
            profile = {"languages": [], "frameworks": ["OpenAPI"], "infrastructure": [], "databases": [], "security_areas": ["Authentication", "Authorization"]}
            data = make_data(Path(host), profile, findings, checks, "api-test")
            data["target"] = clean(host)
            data["route_matrix"] = routes
            data["authorization_matrix"] = auth_matrix
            write_reports(args.out, data, findings, checks)
            print(f"Safe API probes: {len(routes)} documented routes · {len(findings)} findings · {clean(host)}")
            return 0
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"rivet: {clean(exc)}", file=sys.stderr)
            return 2
    for adapter in ADAPTERS:
        print(f"{adapter.name:16} {scanner_version(adapter.name):30} {adapter.purpose} · {adapter.install_url}")
    for adapter in PLANNED:
        print(f"{adapter.name:16} {'PLANNED':14} {adapter.purpose}")
    print("W.Audit never downloads scanners. Install optional tools from their official documentation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
