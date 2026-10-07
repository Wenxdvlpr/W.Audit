# Changelog

## 0.4.0b1 — 2026-10-07

Public beta preparation. Stable default scans run built-in analysis without network access or optional scanners. npm OSV SCA remains experimental and is reached only through explicit `--external`; live HTTP/API probes are separate experimental commands requiring `--test-environment` and print a warning. Kept the working Python SCA, SBOM, language and infrastructure rules, reports, baselines, redaction and agent guidance. The Python distribution and `rivet` CLI names remain for compatibility while the public project name is W.Audit.

## 0.3.0a0 — 2026-10-07

Validated Semgrep 1.179.0, Bandit 1.9.4, Gitleaks 8.30.1 and OSV-Scanner 2.6.0 against real binaries and added optional integration tests. Hardened adapter statuses, errors, timeouts, version detection, path handling and cross-scanner CWE deduplication. Added limited offline CycloneDX SBOM generation for pinned Python requirements and npm package-lock, OSV SCA metadata, bounded same-file interprocedural Python flow, tighter route inference, narrow MCP config checks, pinned-IP HEAD target protection and line-movement-stable baseline fingerprints. Still ALPHA; broad ecosystem coverage and beta safety gates remain incomplete.

Prepared a fresh wheel/source build and clean-install smoke; added bounded GitHub CI, dependency update automation, alpha release notes, first-run guidance and explicit intentional-fixture labeling. Owner-confirmed provenance is recorded in `PROJECT_ORIGIN.md`. No beta readiness claim is made.

Follow-up hardening adds bounded Python local-import source-to-sink tracing, lockfile-backed npm SCA scope normalization, runtime/dev SBOM properties, FastAPI inferred authorization matrices and POSSIBLE/LIKELY BOLA evidence, plus allowlisted OpenAPI JSON probes limited to GET/HEAD and OPTIONS. These remain partial where live scanner or runtime evidence is unavailable.

## 0.2.0a0 — 2026-10-07

Expanded regression suite; strict JSON config; stronger redacted secret detection; Python local flow, auth and route analysis; Docker/CI/Kubernetes and AI/vibe rules; scanner registry; explicit HEAD-only dynamic baseline; read-only fix planning and finding verification. Still an alpha with substantial coverage gaps.

## 0.1.0 — 2026-10-07

Initial local-first CLI, built-in rules, optional scanner adapters, four report formats, baseline, fixtures and GitHub Action.
