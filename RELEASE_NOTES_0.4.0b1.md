# W.Audit 0.4.0b1 — Public Beta

W.Audit is currently a public beta for defensive automated security analysis. It does not guarantee that a project is safe or free of vulnerabilities.

Stable default scans run built-in checks offline and do not require optional scanners. Missing optional tools are reported as `NOT_INSTALLED` or `SKIPPED`; an optional scanner failure is recorded and the remaining checks continue.

## Experimental features

- npm SCA through OSV-Scanner: opt in with `rivet scan PATH --external`. This also enables installed external scanners. npm live integration is not yet verified for this beta.
- Live HTTP/API probes: separate commands, excluded from AUTO/FULL profiles, require `--test-environment`, and print a warning. Use only against localhost or an authorized test environment. Live API redirect regression remains unverified outside the sandbox.

Static OpenAPI parsing and the documented stable checks remain available without live probes. The existing Python distribution name `rivet-audit` and command `rivet` are retained for compatibility; the public project name is W.Audit.

The reports describe checks and evidence only; a clean result is not a security guarantee. Canonical repository: https://github.com/Wenxdvlpr/W.Audit. Vulnerability reports should use GitHub's private vulnerability reporting workflow; the repository owner must enable it in repository settings.
