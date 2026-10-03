"""Resolve external tool paths and output locations.

Lookup order for each tool:
  1. Environment variable (PDT_7Z, PDT_SIGNTOOL)
  2. vendor/tools/<name>.exe under the repo (future vendored layout)
  3. Known prototype location at E:\\temp\\driver-source-tools\\latest (bridge)
  4. PATH
Missing-tool errors are raised at point of use, not here, so a collector that
does not need signtool can still run on a machine without it.
"""
from __future__ import annotations
import os
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_TOOLS = REPO_ROOT / "vendor" / "tools"
LEGACY_TOOLS = Path(r"E:\temp\driver-source-tools\latest")
LEGACY_SIGNTOOL = Path(r"E:\temp\catalog-driver-test\tools\signtool.exe")


def _resolve(env_name: str, basename: str, legacy: Path | None = None) -> Path | None:
    env = os.environ.get(env_name)
    if env and Path(env).exists():
        return Path(env)
    candidate = VENDOR_TOOLS / basename
    if candidate.exists():
        return candidate
    if legacy and legacy.exists():
        return legacy
    found = shutil.which(basename)
    return Path(found) if found else None


# 7-Zip CLI basenames across platforms: Windows (7z.exe), Debian p7zip-full
# (7z / 7za / 7zr), newer Debian 7zip package (7zz). The container installs one
# of these on PATH; a Windows dev box resolves via PATH or the legacy fallback.
_SEVENZIP_NAMES = ("7z.exe", "7z", "7zz", "7za", "7zr")


def sevenzip() -> Path:
    # 1. explicit override
    env = os.environ.get("PDT_7Z")
    if env and Path(env).exists():
        return Path(env)
    # 2. vendored under the repo
    for name in _SEVENZIP_NAMES:
        candidate = VENDOR_TOOLS / name
        if candidate.exists():
            return candidate
    # 3. on PATH (container installs it here; most dev boxes too)
    for name in _SEVENZIP_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)
    # 4. legacy prototype box, last resort
    legacy = LEGACY_TOOLS / "7z.exe"
    if legacy.exists():
        return legacy
    raise RuntimeError(
        "7-Zip CLI not found. Set PDT_7Z, drop a binary under vendor/tools/, or "
        "install 7-Zip (p7zip-full / the 7zip package / 7-Zip on Windows) to PATH."
    )


def signtool() -> Path | None:
    """Returns None if signtool is not installed — callers must handle that."""
    return _resolve("PDT_SIGNTOOL", "signtool.exe", LEGACY_SIGNTOOL)


def output_root() -> Path:
    env = os.environ.get("PDT_OUTPUT_DIR")
    root = Path(env) if env else REPO_ROOT / "pipeline_out"
    root.mkdir(parents=True, exist_ok=True)
    return root


def drivers_dir() -> Path:
    d = output_root() / "drivers"
    d.mkdir(parents=True, exist_ok=True)
    return d


def collectors_dir() -> Path:
    d = output_root() / "collectors"
    d.mkdir(parents=True, exist_ok=True)
    return d
