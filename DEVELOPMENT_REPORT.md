# Rivet v0.2.0a0 development report

## Project name

Rivet (`rivet-audit` on package indexes). The GitHub repository name has not been reserved.

## Architecture

Local Python CLI → bounded repository walk → discovery → built-in checks → optional scanner adapters → canonical findings → deduplication → Markdown/JSON/SARIF/HTML → baseline comparison. Separate explicit commands provide HEAD-only dynamic checks, read-only fix planning and a verification rescan. See `docs/architecture.md` and `docs/security-model.md`.

## File tree

```text
src/rivet/{cli,walk,discovery,checks,adapters,model,report,secrets,taint,auth,routes,ai,vibe,dynamic,remediation,config,redact}.py
src/rivet/rules/semgrep.yml
tests/{test_core.py,test_regression.py,test_taint.py,test_auth_routes.py,test_platform_rules.py,test_ai.py,test_vibe.py,test_dynamic.py,test_remediation.py,test_self_security.py,test_adapters.py,fixtures/}
docs/{architecture,security-model,roadmap,codex,claude-code,scanners,ci,configuration,supported-features}.md
AGENTS.md  CLAUDE.md  AGENT_SECURITY_GUIDE.md
action.yml  pyproject.toml  README.md  SECURITY.md
```

## Supported stacks and check categories

Discovery recognizes Python, JS/TS and several other languages; framework hints include selected AI stacks. Executable built-in checks cover selected Python AST patterns and local flows, auth and route heuristics, JS/TS, Docker, Compose, Kubernetes, Terraform and GitHub Actions patterns, redacted secret formats, AI/vibe clues and selected repository lockfile hygiene. Detection of a stack does not imply complete security coverage.

## Security tools

| Tool | Purpose | Integration status |
| --- | --- | --- |
| Rivet built-ins | Static patterns, local AST flow and config checks | Implemented with focused tests |
| Semgrep | Additional SAST | Adapter implemented; unavailable in test environment |
| Bandit | Python SAST | Adapter implemented; unavailable in test environment |
| Gitleaks | Git history secrets | Adapter implemented; unavailable in test environment |
| OSV-Scanner | Known dependency advisories | Adapter implemented; unavailable in test environment; skipped offline |
| gosec, ESLint security, cargo-audit | Language-specific adapters | Registry entries only; planned |
| Trivy, CodeQL, Checkov, ZAP, Nuclei | Additional static/dynamic checks | Not implemented |

## Automatic, AI and dynamic checks

Automatic checks are listed in `docs/roadmap.md`. The AI layer detects selected unsafe model-loading flags and local output-to-sink paths; it does not run an LLM or prove prompt injection. Explicit dynamic mode sends one allowlisted HEAD request and checks selected headers. Fix planning is read-only; no automatic remediation. No target project code is executed.

## Safety controls

No symlink following, nonregular and oversized file exclusion, bounded file count and total bytes, scanner timeouts, capped JSON ingestion, argument-array subprocess calls, terminal/Markdown/HTML escaping and secret redaction. External scanners are skipped when include/exclude filters cannot be honored. Optional external scanners should be isolated from host credentials for hostile targets. See `docs/security-model.md`.

## Test results and self-audit

Sixty-five tests pass. The suite covers CLI/configuration, Python positive/negative flows, auth/route heuristics, Docker/CI/Kubernetes, AI/vibe, redaction, HTML escaping, cross-scanner deduplication, all four report formats, baseline, dynamic allowlist, read-only remediation and self-security inputs. The installed-package smoke scan reports zero findings for the secure fixture; all six vulnerable fixture families produce expected findings. Source self-scan excluding test data reports zero findings. See `VERIFICATION.md` for exact commands and caveats. These results do not prove absence of vulnerabilities in Rivet.

## Known limitations

No interprocedural data-flow, proven BOLA, business-logic, cloud account, mobile or MCP contextual analysis. No dependency reachability proof, live credential validation, SBOM or broad dynamic API checks. Most profiles share check selection; `vibe` adds selected rules. Scanner adapters have not been integration-tested against installed binaries. There is no production release yet.

## Codex and Claude Code installation

Install with `python -m pip install --no-deps .`. Use `AGENTS.md` for Codex and `CLAUDE.md` for Claude Code, or reference `AGENT_SECURITY_GUIDE.md` in a prompt. Both workflows begin with offline static scanning and manual verification of severe findings.

## CLI usage

`rivet scan TARGET --offline --out REPORT_DIR`; `rivet scan TARGET --config rivet.json`; `rivet scan TARGET --external`; `rivet doctor`; `rivet baseline create REPORT`; `rivet baseline compare REPORT BASELINE`; `rivet plan-fix REPORT`; `rivet verify TARGET --against REPORT --finding ID`; `rivet dynamic URL --test-environment`.

## GitHub release readiness

The repository files and ZIP are prepared. GitHub remote creation, CI execution on GitHub, provenance and SBOM remain undone. The local `gh` installation has invalid authentication credentials, so no remote was created or published. Publication is not requested in this phase. Do not label v0.2 alpha production-ready.

## Next version ideas

Typed IaC parsers, lockfile-specific package reachability, isolated dynamic API harness, deeper data flow, policy as code, richer scanner adapters and authorization matrix tests with multiple roles.
