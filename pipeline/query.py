"""Query the folded driver index from the command line.

`drivers/index.jsonl` is append-only and each line is a dense, multi-kilobyte
JSON object — not something to read by eye. This module folds it (via
`pipeline.index.fold_index`) into one record per sha256 and lets you slice the
corpus with composable filters, then print a table, CSV, JSON, a per-driver
detail view, or summary stats.

    # strong HID-injection candidates that are unsigned
    python -m pipeline.query --hid-bucket strong --unsigned

    # anything importing a physical-memory primitive, as CSV
    python -m pipeline.query --capability phys_mem --csv

    # drivers known to LOLDrivers, newest-corpus-first, top 20
    python -m pipeline.query --loldrivers --sort hid_score --desc --limit 20

    # everything from a brand, full JSON (feed another tool)
    python -m pipeline.query --brand logitech --json

    # one driver in detail (sha256 prefix is enough)
    python -m pipeline.query --show 1a2b3c

Filters combine with AND. A repeatable filter (e.g. several --capability) matches
a record if ANY of its values match (OR within one flag). Everything is derived
from the index alone; no binary is opened here.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from typing import Any, Callable, Iterable

from . import index as _index

# capability bucket names, straight from the analyzer so the two never drift
_CAP_NAMES = sorted(_index._CAPABILITIES.keys())
_BUCKETS = ("strong", "candidate", "weak", "none")


# ----------------------------------------------------------------- extraction


def _dig(rec: dict, path: str) -> Any:
    """Follow a dotted path into nested dicts; None if any hop is missing."""
    cur: Any = rec
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _pe(rec: dict) -> dict:
    pe = rec.get("pe")
    return pe if isinstance(pe, dict) else {}


def _caps(rec: dict) -> list[str]:
    return sorted((_pe(rec).get("capabilities") or {}).keys())


def _version_info(rec: dict) -> dict:
    vi = _dig(rec, "pe.resources.version_info")
    return vi if isinstance(vi, dict) else {}


def _display_name(rec: dict) -> str:
    vi = _version_info(rec)
    return (rec.get("original_name")
            or vi.get("OriginalFilename")
            or vi.get("InternalName")
            or vi.get("ProductName")
            or _dig(rec, "provenance.package_name")
            or "-")


def _signed(rec: dict) -> bool:
    return bool(_dig(rec, "pe.signature.embedded"))


def _has_wx(rec: dict) -> bool:
    return any(s.get("wx") for s in (_pe(rec).get("sections") or []))


def _all_strings(rec: dict) -> list[str]:
    s = rec.get("strings") or {}
    return list(s.get("ascii") or []) + list(s.get("utf16") or [])


def _import_names(rec: dict) -> list[str]:
    out: list[str] = []
    for fns in (_pe(rec).get("imports") or {}).values():
        out.extend(fns)
    return out


# Virtual columns: short names usable in --fields / --sort, resolved ahead of a
# raw dotted path. Values are kept scalar-ish so table/CSV/sort behave.
_RESOLVERS: dict[str, Callable[[dict], Any]] = {
    "sha": lambda r: (r.get("sha256") or "")[:12],
    "sha256": lambda r: r.get("sha256") or "",
    "name": _display_name,
    "arch": lambda r: _pe(r).get("arch") or "-",
    "size": lambda r: r.get("size") or 0,
    "entropy": lambda r: r.get("entropy") or 0.0,
    "sig": lambda r: "Y" if _signed(r) else "-",
    "signed": _signed,
    "cert": lambda r: _dig(r, "pe.signature.cert_class") or "-",
    "signer": lambda r: _dig(r, "pe.signature.signer_cn") or "-",
    "kmdf": lambda r: "Y" if _dig(r, "pe.kmdf.is_kmdf") else "-",
    "fw": lambda r: _dig(r, "device.framework") or "-",
    "symlink": lambda r: "Y" if _dig(r, "device.declares_symlink") else "-",
    "useropen": lambda r: "Y" if _dig(r, "device.sddl_grants_user") else "-",
    "inject": lambda r: "Y" if _dig(r, "disasm.mouse_injection.verdict") else "-",
    "reach": lambda r: "Y" if _dig(r, "disasm.symlink_user_reachable") else "-",
    "hid": lambda r: f"{_dig(r, 'hid_input.bucket') or 'none'}:{_dig(r, 'hid_input.score') or 0}",
    "hid_bucket": lambda r: _dig(r, "hid_input.bucket") or "none",
    "hid_score": lambda r: _dig(r, "hid_input.score") or 0,
    "lol": lambda r: "Y" if _dig(r, "loldrivers.known") else "-",
    "caps": lambda r: ",".join(_caps(r)) or "-",
    "wx": lambda r: "Y" if _has_wx(r) else "-",
    "driver": lambda r: "Y" if _pe(r).get("is_driver") else "-",
    "nx": lambda r: "Y" if _pe(r).get("nx") else "-",
    "aslr": lambda r: "Y" if _pe(r).get("aslr") else "-",
    "cf": lambda r: "Y" if _pe(r).get("guard_cf") else "-",
    "brand": lambda r: _dig(r, "provenance.brand_name") or "-",
    "company": lambda r: _version_info(r).get("CompanyName") or "-",
    "product": lambda r: _version_info(r).get("ProductName") or "-",
    "package": lambda r: _dig(r, "provenance.package_name") or "-",
    "url": lambda r: _dig(r, "provenance.package_url") or "-",
    "imphash": lambda r: _pe(r).get("imphash") or "-",
}

_DEFAULT_FIELDS = ["sha", "arch", "sig", "hid", "lol", "caps", "name"]


def _field(rec: dict, name: str) -> Any:
    fn = _RESOLVERS.get(name)
    return fn(rec) if fn else _dig(rec, name)


# ------------------------------------------------------------------- filtering


def _contains_ci(haystacks: Iterable[str], needle: str) -> bool:
    n = needle.lower()
    return any(n in (h or "").lower() for h in haystacks)


def _build_predicates(a: argparse.Namespace) -> list[Callable[[dict], bool]]:
    preds: list[Callable[[dict], bool]] = []

    if a.sha:
        subs = [s.lower() for s in a.sha]
        preds.append(lambda r: any(s in (r.get("sha256") or "").lower() for s in subs))
    if a.name:
        preds.append(lambda r: _contains_ci(
            [_display_name(r), *( _version_info(r).get(k, "") for k in
              ("OriginalFilename", "InternalName", "ProductName", "FileDescription"))],
            a.name))
    if a.brand:
        preds.append(lambda r: _contains_ci([_dig(r, "provenance.brand_name") or ""], a.brand))
    if a.company:
        preds.append(lambda r: _contains_ci([_version_info(r).get("CompanyName", "")], a.company))
    if a.arch:
        want = {x.lower() for x in a.arch}
        preds.append(lambda r: (_pe(r).get("arch") or "").lower() in want)
    if a.capability:
        want = set(a.capability)
        if "any" in want:
            preds.append(lambda r: bool(_caps(r)))
            want.discard("any")
        if want:
            preds.append(lambda r: want.issubset(set(_caps(r))))
    if a.hid_bucket:
        want = set(a.hid_bucket)
        preds.append(lambda r: (_dig(r, "hid_input.bucket") or "none") in want)
    if a.min_hid_score is not None:
        preds.append(lambda r: (_dig(r, "hid_input.score") or 0) >= a.min_hid_score)
    if a.creates_user_device:
        preds.append(lambda r: bool(_dig(r, "hid_input.creates_user_device")))
    if a.signed:
        preds.append(_signed)
    if a.unsigned:
        preds.append(lambda r: not _signed(r))
    if a.cert_class:
        want = set(a.cert_class)
        preds.append(lambda r: (_dig(r, "pe.signature.cert_class") or "unknown") in want)
    if a.prod_cert:
        preds.append(lambda r: _dig(r, "pe.signature.cert_class") == "production")
    if a.kmdf:
        preds.append(lambda r: bool(_dig(r, "pe.kmdf.is_kmdf")))
    if a.declares_symlink:
        preds.append(lambda r: bool(_dig(r, "device.declares_symlink")))
    if a.user_open:
        preds.append(lambda r: bool(_dig(r, "device.sddl_grants_user")))
    if a.injects:
        preds.append(lambda r: bool(_dig(r, "disasm.mouse_injection.verdict")))
    if a.symlink_reachable:
        preds.append(lambda r: bool(_dig(r, "disasm.symlink_user_reachable")))
    if a.loldrivers:
        preds.append(lambda r: bool(_dig(r, "loldrivers.known")))
    if a.wx:
        preds.append(_has_wx)
    if a.driver:
        preds.append(lambda r: bool(_pe(r).get("is_driver")))
    if a.overlay:
        preds.append(lambda r: bool(_pe(r).get("overlay")))
    if a.min_entropy is not None:
        preds.append(lambda r: (r.get("entropy") or 0.0) >= a.min_entropy)
    if a.max_entropy is not None:
        preds.append(lambda r: (r.get("entropy") or 0.0) <= a.max_entropy)
    if a.import_:
        subs = a.import_
        preds.append(lambda r: all(_contains_ci(_import_names(r), s) for s in subs))
    if a.export:
        subs = a.export
        preds.append(lambda r: all(_contains_ci(_pe(r).get("exports") or [], s) for s in subs))
    if a.string:
        subs = a.string
        preds.append(lambda r: all(_contains_ci(_all_strings(r), s) for s in subs))
    if a.url:
        preds.append(lambda r: _contains_ci(_dig(r, "interesting_strings.urls") or [], a.url))
    if a.guid:
        preds.append(lambda r: _contains_ci(_dig(r, "interesting_strings.guids") or [], a.guid))
    if a.device_path:
        preds.append(lambda r: _contains_ci(
            _dig(r, "interesting_strings.device_paths") or [], a.device_path))
    return preds


# --------------------------------------------------------------------- output


_COLOR = sys.stdout.isatty()
_C = {"strong": "\033[31m", "candidate": "\033[33m", "weak": "\033[36m",
      "none": "\033[2m", "lol": "\033[31m", "reset": "\033[0m", "dim": "\033[2m"}


def _paint(text: str, color: str) -> str:
    return f"{_C[color]}{text}{_C['reset']}" if _COLOR and color in _C else text


def _print_table(records: list[dict], fields: list[str]) -> None:
    rows = [[str(_field(r, f)) for f in fields] for r in records]
    widths = [len(h) for h in fields]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    header = "  ".join(h.upper().ljust(widths[i]) for i, h in enumerate(fields))
    print(_paint(header, "dim"))
    for r, row in zip(records, rows):
        cells = []
        for i, cell in enumerate(row):
            padded = cell.ljust(widths[i])
            f = fields[i]
            if f == "hid":
                padded = _paint(padded, (_dig(r, "hid_input.bucket") or "none"))
            elif f in ("lol",) and cell.strip() == "Y":
                padded = _paint(padded, "lol")
            cells.append(padded)
        print("  ".join(cells))


def _print_csv(records: list[dict], fields: list[str]) -> None:
    w = csv.writer(sys.stdout, lineterminator="\n")
    w.writerow(fields)
    for r in records:
        w.writerow([_field(r, f) for f in fields])


def _slim_for_json(rec: dict, with_strings: bool) -> dict:
    """Drop the heavy raw-strings blob from JSON unless explicitly requested."""
    if with_strings:
        return rec
    out = dict(rec)
    s = out.get("strings")
    if isinstance(s, dict):
        out["strings"] = {"count": s.get("count"), "truncated": s.get("truncated"),
                          "_omitted": "pass --strings to include ascii/utf16"}
    return out


# ------------------------------------------------------------------- detail


def _print_detail(rec: dict, with_strings: bool) -> None:
    pe = _pe(rec)
    vi = _version_info(rec)
    sig = pe.get("signature") or {}
    hid = rec.get("hid_input") or {}
    lol = rec.get("loldrivers") or {}
    prov = rec.get("provenance") or {}
    inter = rec.get("interesting_strings") or {}

    def head(t): print(_paint(f"\n== {t} ==", "dim"))

    print(_paint(rec.get("sha256", "?"), "dim"))
    print(f"name        {_display_name(rec)}")
    print(f"size        {rec.get('size')} bytes   entropy {rec.get('entropy')}")
    print(f"md5         {rec.get('md5')}")
    print(f"sha1        {rec.get('sha1')}")

    head("pe")
    if pe:
        print(f"arch        {pe.get('arch')}  subsystem {pe.get('subsystem_name')}  "
              f"is_driver {pe.get('is_driver')}")
        print(f"linker      {pe.get('linker')}  imphash {pe.get('imphash')}")
        print(f"mitigations nx={pe.get('nx')} aslr={pe.get('aslr')} guard_cf={pe.get('guard_cf')}  "
              f"checksum_valid={pe.get('checksum_valid')}")
        wx = [s["name"] for s in (pe.get("sections") or []) if s.get("wx")]
        if wx:
            print(f"W^X broken  sections: {', '.join(wx)}")
        if pe.get("overlay"):
            ov = pe["overlay"]
            print(f"overlay     offset={ov.get('offset')} size={ov.get('size')} "
                  f"entropy={ov.get('entropy')}")
    else:
        print("(not a PE / unparsed)")

    head("signature")
    if sig.get("embedded"):
        print(f"embedded    yes ({sig.get('size')} bytes)")
        for cn in (sig.get("cert_common_names") or []):
            print(f"  cert      {cn}")
    else:
        print("embedded    no")

    head("capabilities")
    caps = pe.get("capabilities") or {}
    if caps:
        for cat, fns in sorted(caps.items()):
            print(f"  {cat:<16} {', '.join(fns)}")
    else:
        print("  (none of the tracked buckets)")
    dang = pe.get("dangerous_imports") or []
    if dang:
        print(f"dangerous   {', '.join(dang)}")

    head("hid_input")
    print(f"bucket      {hid.get('bucket')}  score {hid.get('score')}  "
          f"creates_user_device {hid.get('creates_user_device')}")
    for k in ("string_hits", "import_hits", "class_guids"):
        if hid.get(k):
            print(f"  {k:<12} {', '.join(hid[k])}")

    head("loldrivers")
    if lol.get("known"):
        print(f"known       yes (match={lol.get('match')}, id={lol.get('id')})")
        print(f"category    {lol.get('category')}")
        if lol.get("tags"):
            print(f"tags        {', '.join(lol['tags'])}")
    else:
        print("known       no")

    if vi:
        head("version_info")
        for k in ("CompanyName", "ProductName", "FileDescription", "OriginalFilename",
                  "FileVersion", "ProductVersion", "LegalCopyright"):
            if vi.get(k):
                print(f"  {k:<18} {vi[k]}")

    head("provenance")
    for k in ("brand_name", "package_name", "package_url", "aggregator", "package_sha256"):
        if prov.get(k):
            print(f"  {k:<16} {prov[k]}")
    if rec.get("seen_in"):
        print(f"  seen_in         {len(rec['seen_in'])} package(s)")

    head("interesting strings")
    for k in ("device_paths", "registry", "guids", "urls", "other_sys"):
        vals = inter.get(k) or []
        if vals:
            shown = ", ".join(vals[:12])
            more = f"  (+{len(vals) - 12} more)" if len(vals) > 12 else ""
            print(f"  {k:<14} {shown}{more}")

    if with_strings:
        head("strings (raw)")
        for s in _all_strings(rec):
            print(f"  {s}")


# -------------------------------------------------------------------- stats


def _print_stats(records: list[dict]) -> None:
    from collections import Counter
    n = len(records)
    print(f"records            {n}")
    if not n:
        return
    signed = sum(1 for r in records if _signed(r))
    print(f"signed / unsigned  {signed} / {n - signed}")
    lol = sum(1 for r in records if _dig(r, "loldrivers.known"))
    print(f"loldrivers known   {lol}")
    wx = sum(1 for r in records if _has_wx(r))
    print(f"W^X section        {wx}")

    def _dist(label: str, counter: Counter) -> None:
        parts = ", ".join(f"{k}={v}" for k, v in counter.most_common())
        print(f"{label:<18} {parts}")

    _dist("hid buckets", Counter((_dig(r, "hid_input.bucket") or "none") for r in records))
    _dist("arch", Counter((_pe(r).get("arch") or "-") for r in records))
    cap_counter: Counter = Counter()
    for r in records:
        cap_counter.update(_caps(r))
    if cap_counter:
        _dist("capabilities", cap_counter)
    _dist("top brands", Counter((_dig(r, "provenance.brand_name") or "-")
                                for r in records))


# --------------------------------------------------------------------- main


def _resolve_show(records: dict[str, dict], token: str) -> dict | None:
    token = token.lower()
    if token in records:
        return records[token]
    hits = [r for sha, r in records.items() if sha.lower().startswith(token)]
    if not hits:
        hits = [r for sha, r in records.items() if token in sha.lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        print(f"ambiguous: {len(hits)} records match {token!r}; add more hex digits",
              file=sys.stderr)
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pipeline.query",
        description="Filter and inspect the folded driver index (drivers/index.jsonl).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Filters AND together; a repeated flag ORs its own values.")

    # filters
    f = ap.add_argument_group("filters")
    f.add_argument("--sha", action="append", metavar="HEX", help="sha256 substring (repeatable)")
    f.add_argument("--name", metavar="SUBSTR", help="match name / version-info (ci)")
    f.add_argument("--brand", metavar="SUBSTR", help="provenance brand name (ci)")
    f.add_argument("--company", metavar="SUBSTR", help="version-info CompanyName (ci)")
    f.add_argument("--arch", action="append", choices=None, metavar="ARCH",
                   help="x64/x86/arm64/… (repeatable)")
    f.add_argument("--capability", action="append", metavar="CAP",
                   choices=[*_CAP_NAMES, "any"],
                   help=f"require capability bucket (repeatable): {', '.join(_CAP_NAMES)}, any")
    f.add_argument("--hid-bucket", action="append", choices=list(_BUCKETS),
                   dest="hid_bucket", metavar="BUCKET", help="strong/candidate/weak/none")
    f.add_argument("--min-hid-score", type=int, metavar="N", dest="min_hid_score")
    f.add_argument("--creates-user-device", action="store_true", dest="creates_user_device",
                   help="hid_input.creates_user_device is true")
    f.add_argument("--signed", action="store_true", help="has embedded Authenticode")
    f.add_argument("--unsigned", action="store_true", help="no embedded Authenticode")
    f.add_argument("--cert-class", action="append", dest="cert_class", metavar="CLASS",
                   help="signature cert_class in {production,test,private,unsigned,unknown} "
                        "(repeatable)")
    f.add_argument("--prod-cert", action="store_true", dest="prod_cert",
                   help="signed with a production certificate")
    f.add_argument("--kmdf", action="store_true", help="KMDF driver (binds wdfldr)")
    f.add_argument("--declares-symlink", action="store_true", dest="declares_symlink",
                   help="declares a user-reachable device+symlink surface")
    f.add_argument("--user-open", action="store_true", dest="user_open",
                   help="an embedded SDDL grants a non-admin principal")
    f.add_argument("--injects", action="store_true",
                   help="disasm verdict: drives the mouse class service callback")
    f.add_argument("--symlink-reachable", action="store_true", dest="symlink_reachable",
                   help="disasm verdict: symlink created from DriverEntry and user-openable")
    f.add_argument("--loldrivers", action="store_true", help="known in the LOLDrivers snapshot")
    f.add_argument("--wx", action="store_true", help="has a writable+executable section")
    f.add_argument("--driver", action="store_true", help="PE looks like a kernel driver")
    f.add_argument("--overlay", action="store_true", help="has appended overlay data")
    f.add_argument("--min-entropy", type=float, metavar="H", dest="min_entropy")
    f.add_argument("--max-entropy", type=float, metavar="H", dest="max_entropy")
    f.add_argument("--import", action="append", dest="import_", metavar="SUBSTR",
                   help="imported function name contains (ci; repeatable = AND)")
    f.add_argument("--export", action="append", metavar="SUBSTR",
                   help="exported name contains (ci; repeatable = AND)")
    f.add_argument("--string", action="append", metavar="SUBSTR",
                   help="any extracted string contains (ci; repeatable = AND)")
    f.add_argument("--url", metavar="SUBSTR", help="interesting URL contains (ci)")
    f.add_argument("--guid", metavar="SUBSTR", help="interesting GUID contains (ci)")
    f.add_argument("--device-path", metavar="SUBSTR", dest="device_path",
                   help="interesting device path contains (ci)")

    # output
    o = ap.add_argument_group("output")
    o.add_argument("--show", metavar="SHA", help="detail view for one record (sha256 prefix)")
    o.add_argument("--json", action="store_true", help="emit matching records as a JSON array")
    o.add_argument("--jsonl", action="store_true", help="emit matching records as JSON lines")
    o.add_argument("--csv", action="store_true", help="emit a CSV with the selected fields")
    o.add_argument("--count", action="store_true", help="print only the number of matches")
    o.add_argument("--stats", action="store_true", help="print summary stats for the matches")
    o.add_argument("--strings", action="store_true",
                   help="include raw ascii/utf16 strings (in --show and --json)")
    o.add_argument("--fields", metavar="A,B,C",
                   help=f"columns for table/csv (default: {','.join(_DEFAULT_FIELDS)}). "
                        f"Names: {', '.join(_RESOLVERS)} or any dotted path.")
    o.add_argument("--sort", metavar="FIELD", help="sort by a field name (see --fields)")
    o.add_argument("--desc", action="store_true", help="sort descending")
    o.add_argument("--limit", type=int, metavar="N", help="keep only the first N matches")
    o.add_argument("--no-color", action="store_true", help="disable ANSI color")

    a = ap.parse_args(argv)

    global _COLOR
    if a.no_color:
        _COLOR = False

    folded = _index.fold_index()

    # --show short-circuits every other filter
    if a.show:
        rec = _resolve_show(folded, a.show)
        if rec is None:
            if not any(sha.lower().startswith(a.show.lower()) for sha in folded):
                print(f"no record matching {a.show!r}", file=sys.stderr)
            return 1
        _print_detail(rec, a.strings)
        return 0

    records = list(folded.values())
    for pred in _build_predicates(a):
        records = [r for r in records if pred(r)]

    if a.sort:
        def _key(r):
            v = _field(r, a.sort)
            return (v is None, v if v is not None else "")
        try:
            records.sort(key=_key, reverse=a.desc)
        except TypeError:
            records.sort(key=lambda r: str(_field(r, a.sort)), reverse=a.desc)
    else:
        # stable, useful default: strongest HID signal first
        records.sort(key=lambda r: (_dig(r, "hid_input.score") or 0), reverse=True)

    if a.limit is not None:
        records = records[: max(0, a.limit)]

    if a.count:
        print(len(records))
        return 0
    if a.stats:
        _print_stats(records)
        return 0
    if a.json:
        json.dump([_slim_for_json(r, a.strings) for r in records], sys.stdout,
                  ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0
    if a.jsonl:
        for r in records:
            sys.stdout.write(json.dumps(_slim_for_json(r, a.strings), ensure_ascii=False) + "\n")
        return 0

    fields = [s.strip() for s in a.fields.split(",")] if a.fields else _DEFAULT_FIELDS
    if a.csv:
        _print_csv(records, fields)
    else:
        _print_table(records, fields)
        if not records:
            print(_paint("(no matches)", "dim"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
