# W.Audit

W.Audit is currently a public beta: a defensive automated security analysis tool for source repositories. It examines files without executing project code and produces Markdown, JSON, SARIF and HTML reports with evidence, confidence, severity and limitations. It does not guarantee that a project is secure.

The [0.4.0b1 release notes](RELEASE_NOTES_0.4.0b1.md) describe supported scope and experimental features.

## 30-second start

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
rivet doctor
rivet scan /path/to/project --profile auto --offline --out ./audit-result
```

Open `audit-result/security-report.md`. To add installed third-party scanners, run `rivet scan /path/to/project --external --out ./audit-result`. Never point optional third-party scanners at hostile code on a host with valuable credentials; use a container or VM.

Example result:

```text
W.Audit 0.4.0b1 · sample-app
Detected: Python, Docker
HIGH 0 · MEDIUM 3 · LOW 1
Reports: /absolute/path/audit-result
```

## What works

| Area | Current implementation |
| --- | --- |
| Discovery | Language, selected frameworks including AI stacks, Docker/Kubernetes/Terraform/GitHub Actions, database clues and security areas |
| Built-in analysis | Redacted credential patterns and entropy candidates; bounded Python local-import data flow and auth rules; inferred route authorization; selected JS/TS sinks; Docker, Compose, Kubernetes, Terraform, CI and MCP config rules |
| External adapters | Semgrep with bundled local rule, Bandit, Gitleaks with Git history and OSV-Scanner; all require explicit `--external`; npm OSV SCA is experimental |
| Dependency inventory | Offline CycloneDX JSON for pinned `requirements*.txt` and npm `package-lock.json` v2/v3; npm dependency edges and integrity hashes |
| Results | Deduplication, HIGH/MEDIUM/LOW, confidence, technical and simple explanations, coverage matrix, four formats, baseline including REGRESSED |
| Safety | Built-in checks do not execute target code or send telemetry; file count/size/total-byte caps, scanner timeout/output cap, no symlink following, redacted secrets |

Python flow rules trace simple in-function paths and bounded route → imported helper → sink flows across local Python files for selected SQL, shell, filesystem, template, redirect and HTTP sinks. Files, depth, nodes and elapsed time are bounded. They do not prove exploitability or follow dynamic dispatch. Pattern-only findings and unverified credentials remain MEDIUM or LOW with contextual review required; a scanner result alone is never promoted to HIGH.

## CLI

```sh
rivet doctor
rivet scan . --profile auto --out ./audit-result
rivet api-test http://127.0.0.1:8000 --openapi ./openapi.json --test-environment # experimental
rivet scan . --config rivet.json
rivet scan . --profile vibe --simple
rivet scan . --external --fail-on high
rivet sbom . --offline --format cyclonedx --output sbom.cdx.json
rivet baseline create security-audit-output/security-report.json
rivet baseline compare security-audit-output/security-report.json security-baseline.json
rivet plan-fix security-audit-output/security-report.json
rivet verify . --against old/security-report.json --finding FINGERPRINT --out retest
rivet dynamic http://127.0.0.1:8000/ --test-environment --out dynamic-result # experimental
```

Exit codes: 0 completed; 1 selected severity threshold exceeded; 2 invalid input; 3 dynamic request failure. Most profiles currently share the same built-in check set; `vibe` adds selected beginner-focused rules. External scanners are off in every profile unless `--external` is supplied; this opt-in also enables experimental npm OSV SCA. `--offline` disables OSV-Scanner; online scans may send dependency identifiers and versions to its advisory service. SBOM generation is always local. `--simple` and `--technical` are accepted; reports contain both plain-language and technical explanations. The experimental `dynamic` and `api-test` commands are separate from scan profiles and require `--test-environment`. `dynamic` performs one HEAD request. `api-test` reads a local OpenAPI JSON schema and probes GET/HEAD plus OPTIONS only; it never sends write verbs. Both pin validated IPs, do not follow redirects, and use bounded response and request limits. OpenAPI declarations and authorization inferences need manual review. `plan-fix` is read-only; `verify` rescans the project and checks a prior fingerprint.

## Agent use

Copy or reference [AGENT_SECURITY_GUIDE.md](AGENT_SECURITY_GUIDE.md) in your target project. For Codex, add a short `AGENTS.md` pointing to it; for Claude Code, use `CLAUDE.md`. Sample instructions are included in this repository. Agents must independently verify HIGH findings and request authorization before changing the target.

## Security principles

Treat the target as hostile, do static analysis first, never expose secrets, document skipped checks, and never claim that a project is fully secure. See [security model](docs/security-model.md) and [architecture](docs/architecture.md). Please report tool vulnerabilities privately using [SECURITY.md](SECURITY.md).

## Experimental features

npm SCA through OSV-Scanner and live HTTP/API probes are experimental and disabled by default. npm SCA runs only when `--external` is explicitly supplied. Live probes use separate commands, require `--test-environment`, and print a warning; use them only against localhost or an authorized test environment.

The public project name is W.Audit. The Python distribution (`rivet-audit`) and CLI command (`rivet`) retain their legacy names for compatibility.

## Limitations

No autonomous AI analysis or repair, broad dynamic testing, dependency reachability proof, complete data-flow analysis, complete SBOM ecosystem coverage, cloud account auditing or comprehensive language coverage in this beta. External scanner availability and installation are the user's responsibility. The reports identify these gaps. See [roadmap](docs/roadmap.md) and [supported features](docs/supported-features.md).

## License and attribution

W.Audit is licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Use, modification, forks, commercial use, and redistribution are permitted under that license. If you distribute a modified version, follow the license terms, mark modified files as required, and preserve applicable notices and attribution. A third-party fork should identify its own maintainer and avoid implying official status or endorsement.

W.Audit name and branding are addressed separately in [TRADEMARKS.md](TRADEMARKS.md). See [AUTHORS.md](AUTHORS.md) for authorship, [PROJECT_ORIGIN.md](PROJECT_ORIGIN.md) for the project record, [CONTRIBUTING.md](CONTRIBUTING.md) for contributions, and the [release provenance checklist](docs/release-provenance.md) for future official releases.
