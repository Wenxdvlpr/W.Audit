# W.Audit supported features matrix (0.4.0b1)

VERIFIED means implemented and tested. PARTIAL means narrow coverage. EXPERIMENTAL means preliminary. UNSUPPORTED means not implemented.

| Feature | Status | Actual scope |
| --- | --- | --- |
| CLI, strict JSON config, four reports, baseline | VERIFIED | Baseline tracks NEW, EXISTING, FIXED, REGRESSED fingerprints |
| Working-tree secret scanning | PARTIAL | Selected token formats, key headers, database URLs and password-like assignments; never validates live credentials |
| Git history secrets | PARTIAL | Real Gitleaks integration on a synthetic Git history; no built-in history engine |
| Python SAST and data flow | PARTIAL | Selected AST calls and bounded local-import helper chains; no dynamic dispatch or whole-program analysis |
| Authentication and route authorization | PARTIAL | FastAPI Depends patterns and inferred role matrix; no runtime proof of authorization |
| JS/TS, Docker, CI, Kubernetes and Terraform | PARTIAL | Selected patterns only; not full parsers |
| AI/LLM/MCP analysis | PARTIAL | SDK discovery, unsafe loading flags, selected AI-output flows and narrow static MCP config checks; MCP runtime behavior not analyzed |
| External SAST integrations | VERIFIED | Real runs with Semgrep 1.179.0, Bandit 1.9.4 and Gitleaks 8.30.1; optional and enabled only with `--external` |
| PyPI SCA | VERIFIED | OSV-Scanner requirements scan; optional and enabled only with `--external` |
| npm SCA | EXPERIMENTAL | Real clean-fixture integration is unverified; available only with explicit `--external`, never from AUTO/FULL/default scans |
| SCA normalization | PARTIAL | OSV findings carry ecosystem/package/advisory/version/fix/scanner and lockfile-backed npm directness/environment; reachability remains UNKNOWN |
| Offline SBOM | PARTIAL | CycloneDX JSON for pinned Python requirements and npm package-lock v2/v3; runtime/dev scope and npm dependency edges where recorded |
| Dynamic HTTP | EXPERIMENTAL | Separate HEAD-only command; requires explicit `--test-environment`; excluded from all scan profiles |
| Safe API probes | EXPERIMENTAL | Separate OpenAPI command; requires explicit `--test-environment`; excluded from all scan profiles; live redirect regression is not yet verified outside sandbox |
| Fix planning and verification | PARTIAL | Read-only plan; full rescan of one prior fingerprint; no automatic code edits |
| Complete data flow, business logic, exploit validation | UNSUPPORTED | Not implemented |
| Cloud account, mobile binary, full language coverage | UNSUPPORTED | Not implemented |
| Automatic remediation, fuzzing, broad API negative tests | UNSUPPORTED | Not implemented |

No result is a security certification or proof of absence of vulnerabilities.
