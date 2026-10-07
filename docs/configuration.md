# Configuration

W.Audit accepts an explicit strict JSON file with `--config`. Unknown fields and malformed values fail with exit code 2. There is no implicit config loading or YAML parsing.

```json
{
  "include": ["*.py", "src/*.ts"],
  "exclude": ["generated/*", "tests/fixtures/*"],
  "profile": "quick",
  "disabled_scanners": ["bandit"],
  "fail_on": "medium",
  "offline": true
}
```

Patterns are root-relative glob strings. Include/exclude filters currently apply to built-in checks only. When any filters are active, W.Audit skips external scanners rather than silently scanning excluded material. `--profile` and `--fail-on` override their config values when set to a nondefault value. `--offline` always forces offline behavior. Supported profile names are shown by `rivet scan --help`; only `vibe` currently changes built-in rule selection.
