# Coverage and roadmap

## v0.3 alpha implemented

Python AST rules include bounded route-to-sink tracing through local imports, with file/depth/node/time limits. Selected password hash, JWT, cookie and reset-token rules include a FastAPI dependency and inferred-role matrix; authorization remains static inference. JavaScript and TypeScript: selected eval, HTML and shell sinks. Secret patterns: selected keys, provider tokens, database URLs and password-like assignments with redaction. Configuration: selected Docker/Compose, Terraform, Kubernetes and GitHub Actions risks. AI flags, local AI-output flows and narrow MCP configuration checks, plus a separate vibe ruleset. Semgrep, Bandit, Gitleaks and OSV-Scanner adapters have real binary integration coverage; PyPI and npm lockfile contexts are normalized, while npm OSV live verification remains opt-in. Offline CycloneDX generation supports pinned Python requirements and npm package-lock v2/v3. Bounded OpenAPI JSON probes test GET/HEAD and OPTIONS only. Four reports, line-shift-tolerant baseline, explicit pinned-IP HEAD-only dynamic baseline, read-only remediation plan, verification rescan and CI action work locally.

## Planned or incomplete in v0.3 alpha

Whole-program data flow and dynamic dispatch, runtime-proven authorization/BOLA, write-operation API tests, active credential checks, broad dynamic HTTP tests, fuzzing, auto-fix, cloud account inspection, mobile binary analysis, complete IaC parsing, full ecosystem SBOM/provenance generation, dependency reachability, MCP contextual reasoning and remote AI analysis remain incomplete. Most profiles share the same static check set; `vibe` adds selected rules. There is no security score or compliance certification.

Next priorities: live npm OSV integration evidence, CycloneDX schema validation where a trusted schema is available, stronger secret false-positive controls and history handling, broader SCA/SBOM sources, policy as code and reviewed fix workflows. Each needs positive and negative fixtures before it is advertised as supported.
