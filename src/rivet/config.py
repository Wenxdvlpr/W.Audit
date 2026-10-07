from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

PROFILES = ("auto", "quick", "standard", "full", "paranoid", "ci", "offline", "passive_only", "static_only", "ai", "vibe")
SCANNERS = {"semgrep", "bandit", "gitleaks", "osv-scanner", "trufflehog"}
THRESHOLDS = {"none", "low", "medium", "high"}


@dataclass(frozen=True)
class Config:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    profile: str = "auto"
    disabled_scanners: tuple[str, ...] = ()
    fail_on: str = "none"
    offline: bool = False


def _patterns(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(x, str) or not x or len(x) > 250 or Path(x).is_absolute() or ".." in Path(x).parts or "\\" in x for x in value):
        raise ValueError(f"{name} must be a list of safe root-relative patterns")
    return tuple(value)


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    if path.stat().st_size > 100_000:
        raise ValueError("config file is too large")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid JSON config") from exc
    if not isinstance(value, dict):
        raise ValueError("config must be an object")
    unknown = set(value) - {"include", "exclude", "profile", "disabled_scanners", "fail_on", "offline"}
    if unknown:
        raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
    profile = value.get("profile", "auto")
    fail_on = value.get("fail_on", "none")
    offline = value.get("offline", False)
    disabled = value.get("disabled_scanners", [])
    if profile not in PROFILES or fail_on not in THRESHOLDS or type(offline) is not bool:
        raise ValueError("invalid profile, threshold or offline setting")
    if not isinstance(disabled, list) or any(x not in SCANNERS for x in disabled):
        raise ValueError("invalid disabled_scanners setting")
    return Config(_patterns(value.get("include", []), "include"), _patterns(value.get("exclude", []), "exclude"), profile, tuple(disabled), fail_on, offline)
