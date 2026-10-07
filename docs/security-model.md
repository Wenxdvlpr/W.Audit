# Threat model of the auditor

## Assets and trust boundaries

The host's credentials, files outside the target, audit results and terminal are assets. The target repository, file names, source text, Git objects and external scanner output are untrusted. The scanner process is a trust boundary; W.Audit runs installed binaries only on explicit request. A scanner binary itself is trusted by the operator, not downloaded by W.Audit.

## Main attack paths and controls

| Attack | Control |
| --- | --- |
| Symlink escape or malicious filename | Walk with `followlinks=False`; skip symlinks, devices and oversized files; resolve paths and check containment. |
| Repository code execution | No imports from target, package install, build, test, Makefile or dynamic target execution. |
| Shell injection | `subprocess.run` uses argument arrays and `shell=False`; no shell interpolation. |
| Terminal escape and report injection | Sanitize terminal text; HTML escape all untrusted strings; Markdown escape line breaks/control characters. |
| Scanner output deception | Parse bounded JSON, validate field types and paths, map unknown severities conservatively, cap messages. |
| Secret leakage | Never include matching secret bytes in findings or reports; evidence uses a redacted indicator. |
| Resource exhaustion | Per-file, total-byte and repository file caps; scanner timeout and output cap. |
| Network exfiltration | Static built-in checks make no network requests; `--offline` disables network-capable adapters. Explicit dynamic mode sends one HEAD request to a loopback or allowlisted host. |

## Residual risk

Installed third-party scanners may read more of the host than W.Audit's built-in code can. Run those inside an isolated container or VM for untrusted repositories. W.Audit does not claim that a passing audit proves security. Reports distinguish checked, skipped and unsupported categories.
