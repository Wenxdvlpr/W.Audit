# Verification for 0.2.0a0

Date: 2026-10-07.

## Commands and results

- `PYTHONPATH=src python3 -m unittest discover -s tests -q`: 65 tests passed.
- Built wheel with the bundled Python and `pip wheel --no-deps --no-build-isolation`: succeeded.
- Installed that wheel into a clean target directory with `pip install --no-deps --target`: succeeded.
- Installed CLI reported `0.2.0a0` and generated Markdown, JSON, SARIF and HTML for every fixture.
- Built-in SARIF structural validator accepted each generated SARIF report. This is a structural validation, not an independent full JSON Schema conformance test.
- Installed CLI scans: secure-reference 0 findings; python-vulnerable 3; docker-insecure 2; terraform-insecure 1; api-bola 1; ai-output 1; ci-insecure 5. These are selected fixtures, not measured detection coverage across real projects.
- Installed `doctor`: Semgrep, Bandit, Gitleaks and OSV-Scanner reported `NOT INSTALLED`; gosec, ESLint security and cargo-audit reported `PLANNED`. `--external --offline` completed; unavailable scanners were recorded without failing the scan, and OSV-Scanner was skipped.
- Secret tests used synthetic values only and confirmed that full values were absent from Markdown, JSON, SARIF, HTML and terminal output.
- Self-security tests covered shell-like and control-character filenames, symlink escape, malformed/deep scanner JSON, oversized scanner output, malformed SARIF, scanner-message redaction and file-budget limits.
- Source self-scan with `--exclude tests`: 0 findings. Scanning tests themselves reports synthetic credentials intentionally present in test data.
- Dynamic mode was tested with a mocked loopback HEAD response because the sandbox does not permit binding a local HTTP server. No live dynamic endpoint test was performed.

## Remaining verification gaps

Installed third-party scanner binaries were unavailable, so adapter execution against real Semgrep, Bandit, Gitleaks and OSV-Scanner outputs remains unverified. No cross-platform CI run, full SARIF schema conformance, network dynamic integration, fuzzing or external penetration test was performed.
