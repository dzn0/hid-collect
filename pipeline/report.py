"""Promote a triaged driver into a per-binary analysis report.

The collector + index produce a content-addressed store and `drivers/index.jsonl`.
This module is the bridge into *analysis*: it picks the best target from the
current index, and materialises a self-contained report folder for one binary.

Layout (one folder per analysed driver, keyed by full sha256):

    reports/<sha256>/
        index.jsonl              # only the lines for this sha256 (analysis + provenance)
        <original-name>.sys      # the exact binary, copied out of the store
        <original-name>.c        # full Ghidra decompilation (headless)
        dynamic.ps1              # the single, incrementally-grown dynamic-analysis script

`<original-name>` comes from the PE version-info `originalfilename` (falling back
to product/description/provenance), sanitised; it is what a human reviewer and
the decompiler output should be named after.

CLI:

    python -m pipeline.report --pick            # print the best target + why (one line)
    python -m pipeline.report --pick --json     # same, machine-readable
    python -m pipeline.report <sha-or-prefix>   # build the report folder
    python -m pipeline.report <sha> --no-decompile   # skip Ghidra (store + index + .sys only)

Ghidra is invoked through `analyzeHeadless`; resolve it via $GHIDRA_HOME (the
Docker `ghidra` service sets it) or PATH. Decompilation is best-effort: if
Ghidra is absent the rest of the report is still written and `.c` is skipped
with a note.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import config, index as index_mod


# ----------------------------------------------------------------- selection

def _info(rec: dict) -> dict:
    return (rec.get("pe") or {}).get("info") or {}


def _prov(rec: dict) -> dict:
    p = rec.get("provenance")
    return p if isinstance(p, dict) else {}


def display_name(rec: dict) -> str:
    info = _info(rec)
    prov = _prov(rec)
    return (info.get("originalfilename")
            or info.get("productname")
            or info.get("filedescription")
            or prov.get("update_title")
            or prov.get("package_name")
            or "driver")


def safe_stem(name: str) -> str:
    """Sanitise a PE name into a filesystem-safe stem, without extension."""
    stem = Path(name).stem or name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    return stem or "driver"


def _candidate_score(rec: dict) -> tuple | None:
    """Rank a folded record as a static analysis target, or None to exclude.

    Mirrors the README target profile's byte-reachable prerequisites: we want a
    signed x64 driver that exposes a user-mode control device and is NOT a
    self-created HID device. Among those, prefer the ones whose evidence leans
    closest to real mouse-stack injection (the one axis byte-triage usually
    can't confirm), then larger/control-rich surfaces.
    """
    pe = rec.get("pe") or {}
    hid = rec.get("hid_input") or {}
    ev = hid.get("evidence") or {}

    if pe.get("arch") != "x64" or not pe.get("is_driver"):
        return None
    if not pe.get("signed"):
        return None
    if hid.get("verdict") not in ("candidate", "match"):
        return None
    if ev.get("hid_minidriver") or ev.get("vhf_imports"):
        return None
    if not ev.get("creates_user_device"):
        return None

    mouse = bool(ev.get("mouse_injection_imports")
                 or ev.get("mouse_injection_strings")
                 or ev.get("mouse_class_attach")
                 or ev.get("mouse_class_targets"))
    attach = bool(ev.get("class_stack_attach") or ev.get("class_device_targets"))
    symlinks = len(ev.get("symlinks") or [])

    return (
        hid.get("rank", 0),
        1 if mouse else 0,
        1 if attach else 0,
        symlinks,
        rec.get("size", 0),
    )


def pick_best(records: dict[str, dict]) -> tuple[str, dict, str] | None:
    """Return (sha256, record, reason) for the strongest target, or None."""
    best = None
    for sha, rec in records.items():
        score = _candidate_score(rec)
        if score is None:
            continue
        if best is None or score > best[0]:
            best = (score, sha, rec)
    if best is None:
        return None
    _, sha, rec = best
    return sha, rec, _reason(rec)


def _reason(rec: dict) -> str:
    pe = rec.get("pe") or {}
    hid = rec.get("hid_input") or {}
    ev = hid.get("evidence") or {}
    info = _info(rec)
    name = display_name(rec)
    company = info.get("companyname") or "?"
    symlinks = ", ".join(ev.get("symlinks") or []) or "none"
    mouse = bool(ev.get("mouse_injection_imports")
                 or ev.get("mouse_injection_strings")
                 or ev.get("mouse_class_attach"))
    bits = [
        "%s (%s), %s" % (name, company, hid.get("verdict")),
        "x64 signed driver",
        "user-mode control surface: %s" % symlinks,
        "no self-created HID device",
    ]
    bits.append("mouse-stack injection in bytes: %s"
                % ("yes" if mouse else "not yet -- confirm dynamically"))
    return "; ".join(bits)


# ------------------------------------------------------------------- report

def reports_root() -> Path:
    env = os.environ.get("PDT_REPORTS_DIR")
    root = Path(env) if env else config.REPO_ROOT / "reports"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _resolve_sha(prefix: str, records: dict[str, dict]) -> str:
    if prefix in records:
        return prefix
    hits = [s for s in records if s.startswith(prefix.lower())]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise SystemExit("no stored driver matches sha prefix %r" % prefix)
    raise SystemExit("sha prefix %r is ambiguous (%d matches)" % (prefix, len(hits)))


def _write_index_lines(sha: str, out_path: Path, drivers_dir: Path) -> int:
    """Copy every index.jsonl line for this sha into the report folder."""
    src = drivers_dir / "index.jsonl"
    n = 0
    with open(out_path, "w", encoding="utf-8") as fh:
        with open(src, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("sha256") == sha:
                    fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    n += 1
    return n


def _ghidra_headless() -> Path | None:
    home = os.environ.get("GHIDRA_HOME")
    if home:
        exe = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        cand = Path(home) / "support" / exe
        if cand.exists():
            return cand
    for name in ("analyzeHeadless", "analyzeHeadless.bat"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def decompile(sys_path: Path, out_c: Path) -> bool:
    """Run Ghidra headless decompilation of sys_path into out_c. Best-effort."""
    headless = _ghidra_headless()
    if headless is None:
        print("[report] Ghidra not found (set GHIDRA_HOME or PATH); skipping .c",
              file=sys.stderr)
        return False
    script_dir = config.REPO_ROOT / "ghidra_scripts"
    proj_dir = Path(tempfile.mkdtemp(prefix="ghidra_proj_"))
    try:
        cmd = [
            str(headless), str(proj_dir), "hidcollect",
            "-import", str(sys_path),
            "-readOnly",
            "-scriptPath", str(script_dir),
            "-postScript", "DecompileToC.java", str(out_c),
            "-deleteProject",
        ]
        print("[report] decompiling via Ghidra headless (this can take minutes)...")
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        sys.stdout.write(proc.stdout or "")
        ok = proc.returncode == 0 and out_c.exists()
        if not ok:
            print("[report] Ghidra exited %d; .c not produced" % proc.returncode,
                  file=sys.stderr)
        return ok
    finally:
        shutil.rmtree(proj_dir, ignore_errors=True)


DYNAMIC_TEMPLATE = r"""# dynamic.ps1 — single, incrementally-grown dynamic-analysis script.
#
#   Driver : {name}
#   sha256 : {sha}
#
# ONE script per report. Each confirmed step of the dynamic plan is appended as
# a new "STEP N" block below — never split into multiple files, never delete a
# prior step. Run inside a disposable, snapshotted kernel VM; this is the
# intended operating environment, so do not add host-safety guards.
#
# Plan (README "Dynamic analysis" — grow only as far as needed):
#   1 identify  2 environment  3 validate-signature  4 install/load
#   5 init  6 discover-interface  7 open/permissions  8 protocol
#   9 exercise-ioctls  10 arbitrary-movement  11 causality
#   12 hw-independence  13 exclude-self-hid  14 lifecycle  15 reproduce/emit
#
# Start with only what is necessary; add the next STEP block when the previous
# one is confirmed.

$ErrorActionPreference = 'Stop'
$Driver = '{name}'
$Sha256 = '{sha}'
$Sys    = Join-Path $PSScriptRoot '{sysname}'

# ===== STEP 1 — identify the sample =====
Write-Host "== STEP 1: identify =="
$fi = Get-Item $Sys
$h  = (Get-FileHash -Algorithm SHA256 $Sys).Hash.ToLower()
"name     : $Driver"
"path     : $Sys"
"size     : $($fi.Length) bytes"
"sha256   : $h"
if ($h -ne $Sha256) {{ Write-Warning "sha256 mismatch vs report id $Sha256" }}
try {{ (Get-AuthenticodeSignature $Sys) | Format-List Status, SignerCertificate }} catch {{ }}

# ===== STEP 2 — prepare the environment =====
Write-Host "== STEP 2: environment =="
$os = Get-CimInstance Win32_OperatingSystem
"windows  : $($os.Caption) build $($os.BuildNumber)"
try {{ "securebase: $((Confirm-SecureBootUEFI))" }} catch {{ "secureboot: n/a" }}
# HVCI / memory integrity (snapshot state is what we record; do not disable it):
$ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
"hvci     : $($ci.SecurityServicesRunning -contains 2)"

# ---- append STEP 3+ here as each is confirmed ----
"""


def build_report(sha: str, decompile_c: bool = True) -> Path:
    drivers_dir = config.drivers_dir()
    records = index_mod.fold_index(drivers_dir)
    sha = _resolve_sha(sha, records)
    rec = records.get(sha)
    if rec is None:
        raise SystemExit("sha %s not in the folded index" % sha)

    sys_src = drivers_dir / ("%s.sys" % sha)
    if not sys_src.exists():
        raise SystemExit("binary not in store: %s" % sys_src)

    name = display_name(rec)
    stem = safe_stem(name)
    out_dir = reports_root() / sha
    out_dir.mkdir(parents=True, exist_ok=True)

    sys_dst = out_dir / ("%s.sys" % stem)
    shutil.copy2(sys_src, sys_dst)

    n = _write_index_lines(sha, out_dir / "index.jsonl", drivers_dir)
    print("[report] %s" % out_dir)
    print("[report]   index.jsonl   (%d line(s))" % n)
    print("[report]   %s" % sys_dst.name)

    dyn = out_dir / "dynamic.ps1"
    if not dyn.exists():
        dyn.write_text(
            DYNAMIC_TEMPLATE.format(name=name, sha=sha, sysname=sys_dst.name),
            encoding="utf-8")
        print("[report]   dynamic.ps1   (seeded: steps 1-2)")
    else:
        print("[report]   dynamic.ps1   (kept existing)")

    if decompile_c:
        out_c = out_dir / ("%s.c" % stem)
        if decompile(sys_dst, out_c):
            print("[report]   %s" % out_c.name)

    return out_dir


# --------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pipeline.report",
        description="Pick the best triaged target and build its analysis report folder.")
    ap.add_argument("sha", nargs="?", help="sha256 (or unique prefix) to build a report for")
    ap.add_argument("--pick", action="store_true",
                    help="print the best target from the current index and exit")
    ap.add_argument("--json", action="store_true", help="with --pick: emit JSON")
    ap.add_argument("--no-decompile", action="store_true",
                    help="skip Ghidra; write store/index/.sys/.ps1 only")
    a = ap.parse_args(argv)

    records = index_mod.fold_index(config.drivers_dir())

    if a.pick or not a.sha:
        picked = pick_best(records)
        if picked is None:
            print("no eligible target (need a signed x64 candidate with a "
                  "user-mode device and no self-created HID)")
            return 1
        sha, rec, reason = picked
        if a.json:
            print(json.dumps({"sha256": sha, "reason": reason,
                              "name": display_name(rec),
                              "verdict": (rec.get("hid_input") or {}).get("verdict")},
                             ensure_ascii=False))
        else:
            print("best target: %s" % sha)
            print("why: %s" % reason)
            print("\nbuild it with:  python -m pipeline.report %s" % sha[:16])
        return 0

    build_report(a.sha, decompile_c=not a.no_decompile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
