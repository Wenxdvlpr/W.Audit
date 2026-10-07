# Rivet Audit 0.3.0a0 (Alpha)

This is an alpha preview for local, evidence-led repository security auditing. It is not a beta release or a security certification.

## Included

- Offline built-in checks, discovery, and Markdown, JSON, SARIF, and HTML reports.
- Optional integrations for Semgrep, Bandit, Gitleaks, and OSV-Scanner.
- Limited CycloneDX SBOM support for pinned Python requirements and npm lockfiles.
- Bounded local-import Python flow checks and FastAPI route/role inferences, always marked as static evidence.
- Safe HTTP HEAD and OpenAPI JSON probes, disabled unless explicitly requested for a test environment; API probes use GET/HEAD and OPTIONS only.

## Limitations

Python data flow and route authorization are partial and heuristic; npm OSV live validation, ecosystem coverage, dependency reachability, and SBOM coverage are limited. External scanners are optional and may need network access. Dynamic checks do not perform broad testing. See `docs/supported-features.md` for the scope of each feature.

Built-in checks are local-first and do not execute target code. Dynamic testing is off by default. Review evidence and coverage; findings are not proof that a vulnerability is exploitable, and no findings are not proof of security.
