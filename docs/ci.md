# GitHub Actions

After checking out both your project and W.Audit, use the local composite action at the W.Audit checkout path. It installs the compatibility distribution and runs built-in checks without optional scanners by default. Example:

```yaml
name: security-audit
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4 # pin to a full SHA in a hardened workflow
      - uses: actions/checkout@v4
        with:
          repository: YOUR_ORG/rivet-audit
          path: .rivet-tool
      - uses: ./.rivet-tool
        with:
          target: .
          fail-on: high
```

Replace `YOUR_ORG` after publishing. The action does not upload SARIF automatically; upload `security-audit-output/security-report.sarif` using your organization's approved Code Scanning step.
