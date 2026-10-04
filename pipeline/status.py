"""Persist an AI-authored review status per driver (e.g. ``rejected``).

The point of a status is to *stick*: once a driver has been looked at and ruled
out, the FAST START flow must not keep re-picking it as a candidate. The lean
``reports/index.jsonl`` is regenerated from scratch by triage and by every disasm
refresh, so a status written into that file would be clobbered. Instead the status
lives where every other durable fact lives — as an append-only line in the store
index ``pipeline_out/drivers/index.jsonl``:

    {"sha256": "...", "kind": "status", "status": "rejected",
     "status_reason": "fails (c): PnP-gated", "status_by": "ai", "status_ts": "..."}

``index.fold_index`` merges that line onto the driver's record (last non-null wins),
``triage.lean_record`` surfaces ``status``/``status_reason`` into the lean index, and
``triage._rank`` sinks rejected rows to the bottom. Setting a status again just appends
a newer line that overrides the old one; ``clear`` appends an empty status, which folds
back to "no status".

    python -m pipeline.status reject 1a2b3c --reason "fails (c): symlink not from DriverEntry"
    python -m pipeline.status clear 1a2b3c
    python -m pipeline.status set 1a2b3c confirmed --reason "b+c verified in VM"
    python -m pipeline.status list

A sha256 prefix is enough as long as it is unambiguous. Nothing here opens a binary.
"""
from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import config
from . import index as _index
from . import triage

# Known status values. `rejected` is the one the FAST START flow skips; the others
# exist so the same field can carry a positive verdict. Any string is accepted via
# `set`, but these are what the docs and ranker understand.
VALID = ("rejected", "confirmed", "candidate", "active")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_sha(prefix: str, records: dict[str, dict]) -> str:
    """Resolve a sha256 prefix to the one full sha it matches, or raise."""
    prefix = prefix.lower().strip()
    if prefix in records:
        return prefix
    hits = [s for s in records if s.startswith(prefix)]
    if not hits:
        raise KeyError(f"no driver matches sha prefix {prefix!r}")
    if len(hits) > 1:
        raise KeyError(f"sha prefix {prefix!r} is ambiguous ({len(hits)} matches); "
                       "use more characters")
    return hits[0]


def set_status(sha: str, status: str, reason: str | None = None,
               drivers_dir: Path | None = None, by: str = "ai") -> str:
    """Append a status line to the store index. `status=""` clears it. Returns full sha."""
    drivers_dir = drivers_dir or config.drivers_dir()
    records = _index.fold_index(drivers_dir)
    full = resolve_sha(sha, records)
    line = {
        "sha256": full,
        "kind": "status",
        "status": status,
        "status_reason": reason or "",
        "status_by": by,
        "status_ts": _now(),
    }
    path = drivers_dir / "index.jsonl"
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")
    return full


def refresh_lean(drivers_dir: Path | None = None,
                 reports_root: Path | None = None) -> int:
    """Rewrite reports/index.jsonl from the store so a status change shows up in it."""
    drivers_dir = drivers_dir or config.drivers_dir()
    reports_root = reports_root or config.reports_dir()
    records = _index.fold_index(drivers_dir)
    shas = [s for s, r in records.items() if triage._pe(r)]
    return triage.write_reports_index(
        {s: r for s, r in records.items() if triage._pe(r)},
        shas, reports_root / "index.jsonl")


def iter_status(records: dict[str, dict]):
    """Yield (sha, record) for every driver carrying a non-empty status."""
    for sha, rec in records.items():
        if rec.get("status"):
            yield sha, rec


# ------------------------------------------------------------------------- CLI


def _cmd_set(status: str, args) -> int:
    drivers_dir = config.drivers_dir()
    try:
        full = set_status(args.sha, status, getattr(args, "reason", None), drivers_dir)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    n = refresh_lean(drivers_dir)
    shown = status or "(cleared)"
    reason = getattr(args, "reason", None)
    tail = f"  reason: {reason}" if reason else ""
    print(f"{full[:12]} status={shown}{tail}")
    print(f"lean index: {config.reports_dir() / 'index.jsonl'}  ({n} line(s))")
    return 0


def _cmd_list(args) -> int:
    records = _index.fold_index(config.drivers_dir())
    rows = sorted(iter_status(records), key=lambda kv: kv[1].get("status", ""))
    if not rows:
        print("no drivers carry a status yet")
        return 0
    for sha, rec in rows:
        name = rec.get("original_name") or (
            (triage._pe(rec).get("resources") or {}).get("version_info")
            or {}).get("OriginalFilename") or "?"
        reason = rec.get("status_reason") or ""
        tail = f"  — {reason}" if reason else ""
        print(f"{sha[:12]}  {rec.get('status'):<10} {name}{tail}")
    print(f"\n{len(rows)} driver(s) with a status")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m pipeline.status",
        description="Persist an AI review status (e.g. 'rejected') per driver, "
                    "stored in the append-only index and surfaced in reports/index.jsonl.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("reject", help="mark a driver rejected (skipped by FAST START)")
    sp.add_argument("sha")
    sp.add_argument("--reason", help="why it was rejected (which gate/verdict it fails)")

    sp = sub.add_parser("clear", help="remove a driver's status")
    sp.add_argument("sha")

    sp = sub.add_parser("set", help="set an arbitrary status value")
    sp.add_argument("sha")
    sp.add_argument("status", help=f"status value (known: {', '.join(VALID)})")
    sp.add_argument("--reason")

    sub.add_parser("list", help="list every driver that carries a status")

    args = p.parse_args(argv)
    if args.cmd == "reject":
        return _cmd_set("rejected", args)
    if args.cmd == "clear":
        return _cmd_set("", args)
    if args.cmd == "set":
        return _cmd_set(args.status, args)
    if args.cmd == "list":
        return _cmd_list(args)
    p.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
