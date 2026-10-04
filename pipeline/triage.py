"""Policy gate over the collected corpus — the step the collector never had.

Collection is deliberately indiscriminate: it stores every ``.sys`` it can pull,
test-signed and 32-bit and private-CA alike. That is correct for a *net*, but it
leaves ``index.jsonl`` full of lines that can never satisfy the project's target
(a production-signed driver with a user-reachable device). Until now the only
way to cut that down was to delete files by hand.

``pipeline.triage`` makes the policy reproducible. It folds the index, applies a
set of composable **gates**, and reports — or, with ``--apply``, prunes — the
drivers that fail. Default is a dry run: it tells you what *would* go.

    python -m pipeline.triage                       # summary of what fails, dry run
    python -m pipeline.triage --require signed,prod-cert,x64,device
    python -m pipeline.triage --target               # preset for (a)+(c): the net's goal
    python -m pipeline.triage --require prod-cert --apply   # delete the rest (+ index lines)

Gates (``--require`` is a comma list; a driver must pass ALL of them):

    signed        embedded Authenticode present
    prod-cert     signature classified `production` (not test/private/unsigned)
    x64           PE architecture is x64 (loads on a 64-bit Windows kernel)
    driver        looks like a kernel driver (native subsystem / ntoskrnl import)
    device        declares a user-reachable device+symlink surface
    user-open     an embedded SDDL grants a non-admin principal
    hid           hid_input bucket is strong or candidate
    not-lol       NOT in the vendored LOLDrivers set   (use --require lol to invert)

``--apply`` deletes each failing ``<sha>.sys`` and drops every index line for that
sha (analysis + provenance), exactly like the manual cleanup, and writes a
``triage_removed_<ts>.txt`` manifest next to the index first.
"""
from __future__ import annotations

import argparse
import json
import stat
import sys
import time
from pathlib import Path

from . import config
from . import index as _index

# gate name -> predicate(folded record) -> bool (True = PASSES the gate)
GATES: dict[str, "callable"] = {
    "signed": lambda r: bool(_sig(r).get("embedded")),
    "prod-cert": lambda r: _sig(r).get("cert_class") == "production",
    "x64": lambda r: (_pe(r).get("arch") == "x64"),
    "driver": lambda r: bool(_pe(r).get("is_driver")),
    "device": lambda r: bool(_dev(r).get("declares_symlink")),
    "user-open": lambda r: bool(_dev(r).get("sddl_grants_user")),
    "hid": lambda r: (r.get("hid_input") or {}).get("bucket") in ("strong", "candidate"),
    "not-lol": lambda r: not (r.get("loldrivers") or {}).get("known"),
    "lol": lambda r: bool((r.get("loldrivers") or {}).get("known")),
}

# Named presets.
PRESETS = {
    # the net's stated goal: production-signed, x64, with a user-reachable device.
    "target": ["signed", "prod-cert", "x64", "driver", "device"],
    # just the "stop wasting space" baseline the manual cleanup applied.
    "loadable": ["signed", "prod-cert", "x64"],
}


def _pe(r: dict) -> dict:
    pe = r.get("pe")
    return pe if isinstance(pe, dict) else {}


def lean_record(sha: str, rec: dict) -> dict:
    """One compact index line: only what (a)+(b)+(c) triage needs.

    Deliberately drops the bulky, re-derivable material the store's analysis line
    carries — the raw ASCII/UTF-16 string dumps, the full import map, exports and
    section tables — keeping just the verdicts and the handful of identifying
    fields. Empty/None fields are omitted so each line stays short.
    """
    pe = _pe(rec)
    sig = _sig(rec)
    dev = _dev(rec)
    hid = rec.get("hid_input") or {}
    dis = rec.get("disasm") or {}
    vi = (pe.get("resources") or {}).get("version_info") or {}
    out = {
        "sha256": sha,
        "name": rec.get("original_name") or vi.get("OriginalFilename")
        or vi.get("InternalName"),
        "arch": pe.get("arch"),
        "size": rec.get("size"),
        "signer": sig.get("signer_cn"),
        "cert_class": sig.get("cert_class"),
        "kmdf": (pe.get("kmdf") or {}).get("is_kmdf"),
        "framework": dev.get("framework"),
        "declares_symlink": dev.get("declares_symlink"),
        "symlink_paths": dev.get("symlink_paths") or [],
        "sddl_grants_user": dev.get("sddl_grants_user"),
        "hid": f"{hid.get('bucket', 'none')}:{hid.get('score', 0)}",
        "loldrivers": bool((rec.get("loldrivers") or {}).get("known")) or None,
        "report": sha,
        # AI-authored review status (e.g. "rejected"), persisted in the store index
        # via pipeline.status and folded back in here. Empty/None is dropped below.
        "status": rec.get("status"),
        "status_reason": rec.get("status_reason"),
    }
    if dis:
        # (b) re-derived from sub-signals: class-callback-hook alone identifies a
        # mouse/kbd class FILTER (ETD, Apkbfiltr, Razer rz*endpt - all rejected in
        # VM), NOT a user-mode injector. Only `class_send` (sends synthetic data
        # to the class) and `vhid_inject` (virtual-HID device + user symlink)
        # count. Re-deriving here re-classifies drivers disasm'd before the fix
        # without re-running Ghidra; new disasms set `verdict` the same way.
        mi = dis.get("mouse_injection") or {}
        sym = dis.get("symlink") or {}
        class_send = bool(mi.get("sendclass_strings")
                          and mi.get("indirect_call_present"))
        vhid_inject = bool(mi.get("vhid_strings") and sym.get("creates_symlink"))
        out["injects"] = bool(class_send or vhid_inject)
        filter_hook = bool(
            mi.get("class_strings")
            and (mi.get("connect_apis") or mi.get("connect_ioctls"))
            and mi.get("indirect_call_present"))
        if filter_hook:                     # only emit when True (True == class filter;
            out["filter_hook"] = True       # absent == not a filter OR not disasm'd)
        out["symlink_user_reachable"] = dis.get("symlink_user_reachable")
        out["requires_pnp"] = sym.get("requires_pnp_enumeration")
    return {k: v for k, v in out.items() if v not in (None, [], "")}


def _rank(lr: dict) -> tuple:
    """Best candidates first: proven injection, then reachable symlink, then hid.

    Rejected rows sink to the very bottom (they stay in the index for audit, but
    the FAST START flow skips them) so they never crowd out live candidates.
    """
    score = 0
    try:
        score = int((lr.get("hid") or "none:0").split(":")[1])
    except (ValueError, IndexError):
        pass
    not_rejected = lr.get("status") != "rejected"
    return (not_rejected, bool(lr.get("injects")),
            bool(lr.get("symlink_user_reachable")),
            bool(lr.get("sddl_grants_user")), score)


def write_reports_index(records: dict[str, dict], shas: list[str],
                        out_path: Path) -> int:
    """Write the lean, best-first ``reports/index.jsonl`` for `shas`."""
    rows = [lean_record(s, records[s]) for s in shas]
    rows.sort(key=_rank, reverse=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(rows)


def _sig(r: dict) -> dict:
    return _pe(r).get("signature") or {}


def _dev(r: dict) -> dict:
    return r.get("device") or {}


def evaluate(records: dict[str, dict], gates: list[str]) -> tuple[list[str], list[str]]:
    """Split folded records into (passing shas, failing shas) under all gates."""
    preds = [GATES[g] for g in gates]
    passing, failing = [], []
    for sha, rec in records.items():
        try:
            ok = all(p(rec) for p in preds)
        except Exception:
            ok = False
        (passing if ok else failing).append(sha)
    return passing, failing


def _reason(rec: dict, gates: list[str]) -> str:
    """First gate a record fails, for the dry-run breakdown."""
    for g in gates:
        try:
            if not GATES[g](rec):
                return g
        except Exception:
            return g
    return ""


def _prune(drivers_dir: Path, remove: set[str]) -> tuple[int, int, int]:
    """Delete <sha>.sys and drop every index line for shas in `remove`."""
    idx = drivers_dir / "index.jsonl"
    dropped = kept = 0
    tmp = idx.with_suffix(".jsonl.tmp")
    with open(idx, encoding="utf-8") as fin, \
            open(tmp, "w", encoding="utf-8", newline="\n") as fout:
        for line in fin:
            s = line.strip()
            if not s:
                continue
            try:
                sha = json.loads(s).get("sha256")
            except ValueError:
                fout.write(s + "\n"); kept += 1; continue
            if sha in remove:
                dropped += 1
            else:
                fout.write(s + "\n"); kept += 1
    tmp.replace(idx)

    deleted = 0
    for sha in remove:
        f = drivers_dir / f"{sha}.sys"
        if not f.exists():
            continue
        try:
            f.unlink()
            deleted += 1
        except PermissionError:
            try:
                f.chmod(stat.S_IWRITE); f.unlink(); deleted += 1
            except OSError:
                pass
    return deleted, dropped, kept


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pipeline.triage",
        description="Policy gate over the collected corpus (dry run unless --apply).")
    ap.add_argument("--require", default="",
                    help="comma list of gates every kept driver must pass "
                         f"(available: {','.join(GATES)})")
    for name in PRESETS:
        ap.add_argument(f"--{name}", action="store_true",
                        help=f"preset: --require {','.join(PRESETS[name])}")
    ap.add_argument("--apply", action="store_true",
                    help="actually delete failing .sys and drop their index lines "
                         "(default is a dry run)")
    ap.add_argument("--list-failing", action="store_true",
                    help="print the sha of every failing driver")
    ap.add_argument("--no-index", action="store_true",
                    help="do not (re)write the lean reports/index.jsonl")
    args = ap.parse_args(argv)

    gates: list[str] = []
    for name, seq in PRESETS.items():
        if getattr(args, name.replace("-", "_")):
            gates = seq
            break
    if args.require:
        gates = [g.strip() for g in args.require.replace(";", ",").split(",") if g.strip()]
    if not gates:
        gates = PRESETS["loadable"]
    unknown = [g for g in gates if g not in GATES]
    if unknown:
        ap.error(f"unknown gate(s): {unknown}. available: {list(GATES)}")

    drivers_dir = config.drivers_dir()
    records = _index.fold_index(drivers_dir)
    analysis = {s: r for s, r in records.items() if _pe(r) or "strings" in r}
    passing, failing = evaluate(analysis, gates)

    print(f"gates: {' AND '.join(gates)}")
    print(f"corpus: {len(analysis)} analysed driver(s)")
    print(f"  PASS: {len(passing)}")
    print(f"  FAIL: {len(failing)}")

    # breakdown of the first gate each failing driver trips
    from collections import Counter
    why = Counter(_reason(analysis[s], gates) for s in failing)
    if why:
        print("  failing by first gate missed:")
        for g, n in why.most_common():
            print(f"    {n:6d}  {g}")

    if args.list_failing:
        for s in sorted(failing):
            print(s)

    if not args.no_index:
        idx_path = config.reports_dir() / "index.jsonl"
        n = write_reports_index(analysis, passing, idx_path)
        print(f"  lean index: {idx_path}  ({n} line(s))")

    if not args.apply:
        print("\n(dry run - nothing deleted. re-run with --apply to prune.)")
        return 0

    if not failing:
        print("\nnothing to prune.")
        return 0

    manifest = drivers_dir / f"triage_removed_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    manifest.write_text("\n".join(sorted(failing)) + "\n", encoding="utf-8")
    deleted, dropped, kept = _prune(drivers_dir, set(failing))
    print(f"\napplied. manifest: {manifest.name}")
    print(f"  .sys deleted: {deleted}")
    print(f"  index lines dropped: {dropped}  (kept: {kept})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
