"""Drive `analyzeHeadless` over selected drivers and fold the verdicts back in.

    python -m pipeline.disasm                 # disasm every `target`-gate candidate
    python -m pipeline.disasm --gate target   # (default) the triage preset to select
    python -m pipeline.disasm --sha 40061b30   # one driver by sha256 prefix
    python -m pipeline.disasm --limit 50       # cap this run
    python -m pipeline.disasm --rebuild        # re-run even if a disasm line exists

Each run appends one ``{"sha256", "kind": "disasm", ...}`` line per driver to
``drivers/index.jsonl``; `fold_index` merges it onto the analysis line, so the
query layer sees the new verdicts (`mouse_injection`, `symlink_user_reachable`)
alongside the static fields. Already-analysed drivers are skipped unless
``--rebuild``.
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
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .. import config
from .. import index as _index
from .. import triage
from ..collectors import _common as C

_SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra_scripts"
_SCRIPT = "DriverTriage.py"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _write_asm(sys_path: Path, report_dir: Path) -> bool:
    """Raw full disassembly via objdump -> <report_dir>/disasm.txt.

    GNU objdump reads PE/COFF (pei-x86-64) regardless of host, so it works both
    on the host and inside the image (needs the ``binutils`` package). This is
    the confirmation-bias cross-check: a flat instruction stream to verify
    primitives the decompiler may have rendered wrong. Best-effort - a missing
    objdump or a parse hiccup must never sink the run.
    """
    objdump = shutil.which("objdump")
    if not objdump:
        return False
    try:
        proc = subprocess.run(
            [objdump, "-d", "-M", "intel", "--no-show-raw-insn", str(sys_path)],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return False
    try:
        (report_dir / "disasm.txt").write_text(
            proc.stdout or "", encoding="utf-8", errors="replace")
    except OSError:
        return False
    return True


def _name_base(rec: dict, sha: str) -> str:
    """Human driver name for the report files, from the index record."""
    vi = (((rec.get("pe") or {}).get("resources") or {}).get("version_info") or {})
    cand = (rec.get("original_name") or vi.get("OriginalFilename")
            or vi.get("InternalName") or "")
    cand = cand.strip()
    if cand.lower().endswith(".sys"):
        cand = cand[:-4]
    cand = _SAFE.sub("_", cand).strip("_")
    return cand or f"driver_{sha[:12]}"


def analyze_driver(sys_path: Path, ghidra: Path, *, report_dir: Path | None = None,
                   name_base: str = "driver", static_device: dict | None = None,
                   timeout: int = 600) -> dict:
    """Run Ghidra headless on one .sys and return the DriverTriage findings dict.

    Creates a throwaway project per binary (keeps runs independent and lets the
    caller parallelise later), points the post-script at a temp JSON file, and
    parses it back. When ``report_dir`` is given the post-script also writes the
    human artifacts (summary.md, <name_base>.c) there.
    ``static_device`` is the byte-level `device` dict from the index; it is handed
    to the post-script as a fallback for evidence Ghidra misses on CFG-guarded
    KMDF (SDDL, declared symlink paths). On any failure returns
    ``{"ok": False, "error": ...}`` — disassembly must never sink the pipeline.
    """
    sha = sys_path.stem
    with tempfile.TemporaryDirectory(prefix="ghidra_") as tmp:
        tmpd = Path(tmp)
        out_json = tmpd / "triage.json"
        static_json = tmpd / "static.json"
        static_json.write_text(json.dumps(static_device or {}), encoding="utf-8")
        cmd = [
            str(ghidra), str(tmpd), f"proj_{sha[:12]}",
            "-import", str(sys_path),
            "-scriptPath", str(_SCRIPT_DIR),
            "-postScript", _SCRIPT, str(out_json),
            str(report_dir or ""), name_base, str(static_json),
            "-analysisTimeoutPerFile", str(max(30, timeout - 30)),
            "-deleteProject",
        ]
        # Isolate each run's Ghidra *user* dir. The project is already per-temp,
        # but the user-settings dir (~/.ghidra) is shared and lock-guarded, so
        # concurrent analyzeHeadless instances (--jobs > 1) racing to init it fail
        # fast with "no post-script output". A private HOME per run removes the
        # race (costs a little first-run init, bounded and worth it).
        home = tmpd / "home"
        home.mkdir(exist_ok=True)
        env = dict(os.environ)
        env["HOME"] = str(home)
        env["USERPROFILE"] = str(home)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "ghidra timeout"}
        except OSError as e:
            return {"ok": False, "error": f"ghidra spawn failed: {e}"}
        if out_json.exists():
            try:
                return json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
            except ValueError as e:
                return {"ok": False, "error": f"bad post-script json: {e}",
                        "stderr": proc.stderr[-400:]}
        return {"ok": False, "error": "no post-script output",
                "stderr": (proc.stderr or proc.stdout)[-400:]}


def _done_shas(drivers_dir: Path) -> set[str]:
    path = drivers_dir / "index.jsonl"
    done: set[str] = set()
    if not path.exists():
        return done
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("kind") == "disasm" and r.get("sha256"):
            done.add(r["sha256"])
    return done


def _read_shas_file(path: str, records: dict[str, dict]) -> list[str]:
    """Read an explicit sha256 list (one per line, '#' comments / blanks ignored).

    Keeps order, dedups, and resolves each entry against the store: a full sha256
    present in ``records`` is taken as-is; otherwise it is treated as a prefix and
    matched (must be unambiguous). Unknown entries are dropped with a warning.
    """
    out: list[str] = []
    seen: set[str] = set()
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"--shas-file: cannot read {path}: {e}", file=sys.stderr)
        return out
    for ln in raw.splitlines():
        s = ln.split("#", 1)[0].strip().lower()
        if not s:
            continue
        if s in records:
            sha = s
        else:
            hits = [k for k in records if k.startswith(s)]
            if len(hits) != 1:
                print(f"--shas-file: {'ambiguous' if hits else 'unknown'} "
                      f"sha {s!r}, skipping", file=sys.stderr)
                continue
            sha = hits[0]
        if sha not in seen:
            seen.add(sha)
            out.append(sha)
    return out


def _select(records: dict[str, dict], gate: str, sha_prefix: str | None) -> list[str]:
    if sha_prefix:
        return [s for s in records if s.startswith(sha_prefix.lower())]
    gates = triage.PRESETS.get(gate, [gate])
    passing, _ = triage.evaluate(
        {s: r for s, r in records.items() if triage._pe(r)}, gates)
    return passing


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pipeline.disasm",
        description="Ghidra headless verdicts (mouse injection / symlink reachability).")
    ap.add_argument("--gate", default="target",
                    help="triage preset or single gate selecting candidates "
                         f"(default: target; presets: {','.join(triage.PRESETS)})")
    ap.add_argument("--sha", help="disasm only drivers whose sha256 starts with this")
    ap.add_argument("--shas-file", help="path to a file of sha256 (one per line, '#' "
                    "comments ok) to disasm EXACTLY - bypasses the gate; pairs with "
                    "a dedup'd list (e.g. one representative per imphash)")
    ap.add_argument("--jobs", "-j", type=int, default=1,
                    help="parallel Ghidra workers (default 1). Each is a JVM; 4-6 is "
                    "sane on a 12-core/16GB host for these small drivers")
    ap.add_argument("--limit", type=int, default=0, help="cap drivers this run (0 = all)")
    ap.add_argument("--timeout", type=int, default=600, help="per-driver seconds (default 600)")
    ap.add_argument("--rebuild", action="store_true", help="re-run even if a disasm line exists")
    args = ap.parse_args(argv)

    ghidra = config.ghidra_headless()
    if ghidra is None:
        print("ghidra analyzeHeadless not found. Set PDT_GHIDRA_HOME (or "
              "PDT_GHIDRA_HEADLESS), drop it under vendor/tools/, or build the "
              "image with --build-arg WITH_GHIDRA=1.", file=sys.stderr)
        return 2

    drivers_dir = config.drivers_dir()
    reports_root = config.reports_dir()
    records = _index.fold_index(drivers_dir)
    if args.shas_file:
        candidates = _read_shas_file(args.shas_file, records)
    else:
        candidates = _select(records, args.gate, args.sha)
    done = set() if args.rebuild else _done_shas(drivers_dir)
    todo = [s for s in candidates if s not in done]
    if args.limit > 0:
        todo = todo[:args.limit]

    jobs = max(1, args.jobs)
    sel_label = ("shas-file" if args.shas_file else (args.sha or args.gate))
    print(f"ghidra: {ghidra}")
    print(f"reports: {reports_root}")
    print(f"candidates ({sel_label}): {len(candidates)}  "
          f"already done: {len(candidates) - len(todo) if not args.limit else '-'}  "
          f"to run: {len(todo)}  jobs: {jobs}")

    n_todo = len(todo)

    def _work(sha):
        """Heavy per-driver step (runs in a worker thread): copy binary, emit raw
        asm, run Ghidra. Returns the parsed findings; index/counter/print happen
        back in the main thread so the append-only store index stays uncorrupted."""
        sys_path = drivers_dir / f"{sha}.sys"
        if not sys_path.exists():
            return None
        rec = records.get(sha, {})
        name_base = _name_base(rec, sha)
        report_dir = reports_root / sha
        report_dir.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(sys_path, report_dir / f"{name_base}.sys")
        except OSError:
            pass
        # raw assembly cross-check (objdump); Ghidra writes summary.md + <name>.c
        _write_asm(sys_path, report_dir)
        t0 = time.monotonic()
        findings = analyze_driver(sys_path, ghidra, report_dir=report_dir,
                                  name_base=name_base,
                                  static_device=rec.get("device"),
                                  timeout=args.timeout)
        return sha, report_dir.name, findings, time.monotonic() - t0

    ran = ok = inj = reach = 0
    if jobs == 1:
        results = (_work(s) for s in todo)
    else:
        pool = ThreadPoolExecutor(max_workers=jobs)
        futs = [pool.submit(_work, s) for s in todo]
        results = (f.result() for f in as_completed(futs))

    for res in results:
        if res is None:
            continue
        sha, report_name, findings, dt = res
        ran += 1
        # keep a compact verdict in the index so query --injects/--symlink-reachable work
        verdict = {k: findings.get(k) for k in
                   ("ok", "driver_entry", "mouse_injection", "symlink",
                    "symlink_user_reachable", "wdf_calls", "error")}
        C.append_index(drivers_dir, {"sha256": sha, "kind": "disasm", "disasm": verdict})
        if findings.get("ok"):
            ok += 1
            if (findings.get("mouse_injection") or {}).get("verdict"):
                inj += 1
            if findings.get("symlink_user_reachable"):
                reach += 1
        status = "ok" if findings.get("ok") else findings.get("error", "fail")
        print(f"  [{ran}/{n_todo}] {sha[:16]} -> {report_name} "
              f"{dt:5.1f}s  {status}", file=sys.stderr)

    if jobs > 1:
        pool.shutdown()

    print(f"done: ran {ran}, parsed {ok}, mouse-injection {inj}, "
          f"symlink-user-reachable {reach}")

    # refresh the lean reports index so the new disasm verdicts show up in it
    refreshed = _index.fold_index(drivers_dir)
    if args.sha or args.shas_file:
        sel = list(refreshed)
    else:
        sel = _select(refreshed, args.gate, None)
    n = triage.write_reports_index(
        {s: r for s, r in refreshed.items() if triage._pe(r)},
        [s for s in sel if triage._pe(refreshed.get(s, {}))],
        reports_root / "index.jsonl")
    print(f"per-driver reports under {reports_root}/<sha256>/")
    print(f"lean index: {reports_root / 'index.jsonl'}  ({n} line(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
