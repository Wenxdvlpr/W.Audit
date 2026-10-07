from __future__ import annotations

import os
import fnmatch
from pathlib import Path
import stat

EXCLUDED = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "coverage", ".next", ".tox", "__pycache__", ".mypy_cache"}
MAX_FILES = 100_000
MAX_BYTES = 2_000_000
MAX_TOTAL_BYTES = 256_000_000


def safe_files(root: Path, excluded: tuple[str, ...] = (), included: tuple[str, ...] = ()):
    root = root.resolve(strict=True)
    count = 0
    total_bytes = 0
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(base) / d).is_symlink() and not _excluded((Path(base) / d).relative_to(root).as_posix(), excluded))
        for name in sorted(files):
            path = Path(base) / name
            if _excluded(path.relative_to(root).as_posix(), excluded):
                continue
            if included and not any(fnmatch.fnmatchcase(path.relative_to(root).as_posix(), pattern) for pattern in included):
                continue
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                    continue
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root):
                    continue
            except (OSError, RuntimeError):
                continue
            count += 1
            total_bytes += info.st_size
            if count > MAX_FILES:
                raise RuntimeError(f"file limit exceeded ({MAX_FILES})")
            if total_bytes > MAX_TOTAL_BYTES:
                raise RuntimeError(f"repository byte limit exceeded ({MAX_TOTAL_BYTES})")
            yield path, path.relative_to(root).as_posix()


def _excluded(rel: str, patterns: tuple[str, ...]) -> bool:
    return any(rel == pattern or rel.startswith(pattern.rstrip("/") + "/") or fnmatch.fnmatchcase(rel, pattern) for pattern in patterns)


def read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
        if b"\0" in raw[:4096]:
            return None
        return raw.decode("utf-8", "replace")
    except OSError:
        return None
