"""Query the folded driver index from the command line.

`drivers/index.jsonl` is append-only and each line is a lean, triage-focused
JSON object — one *analysis* line per binary plus later *provenance* lines. This
module folds it (via `pipeline.index.fold_index`) into one record per sha256 and
lets you slice the corpus with composable filters, then print a table, CSV,
JSON, a per-driver detail view, or summary stats.

    # the full primitive — decompile these first
    python -m pipeline.query --verdict match

    # injects into the class stack directly and is not a virtual HID device
    python -m pipeline.query --direct-injection --no-virtual-hid

    # anything importing a physical-memory primitive, as CSV
    python -m pipeline.query --capability phys_mem --csv

    # drivers known to LOLDrivers, strongest HID signal first, top 20
    python -m pipeline.query --loldrivers --sort rank --desc --limit 20

    # everything matching a product, full JSON (feed another tool)
    python -m pipeline.query --product logitech --json

    # one driver in detail (sha256 prefix is enough)
    python -m pipeline.query --show 1a2b3c

Filters combine with AND. A repeatable filter (e.g. several --capability) matches
a record if ALL of its values match (AND within one flag). Everything is derived
from the index alone; no binary is opened here.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from typing import Any, Callable, Iterable

# Driver metadata carries non-Latin text (Japanese/fullwidth product names,
# vendor strings). The Windows console defaults to cp1252 and raises
# UnicodeEncodeError on those. Re-encode stdout/stderr as UTF-8 and never let an
# unencodable glyph crash a listing — replace it instead.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from . import index as _index

# capability bucket names, straight from the analyzer so the two never drift
_CAP_NAMES = sorted(_index._CAPABILITIES.keys())
# the index's verdict space (see pipeline.index.hid_input_signals).
# `virtual_hid` is the legacy name for `self_hid` and still accepted so older
# saved commands keep working against folded records that pre-date the rename.
_VERDICTS = ("match", "candidate", "keyboard_only", "self_hid",
             "virtual_hid", "none")


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


def _info(rec: dict) -> dict:
    """VS_VERSIONINFO fields the analyzer kept, keyed lower-case."""
    info = _pe(rec).get("info")
    return info if isinstance(info, dict) else {}


def _caps(rec: dict) -> list[str]:
    return sorted((_pe(rec).get("capabilities") or {}).keys())


def _hid(rec: dict) -> dict:
    hid = rec.get("hid_input")
    return hid if isinstance(hid, dict) else {}


def _evidence(rec: dict) -> dict:
    ev = _hid(rec).get("evidence")
    return ev if isinstance(ev, dict) else {}


def _prov(rec: dict) -> dict:
    prov = rec.get("provenance")
    return prov if isinstance(prov, dict) else {}


def _display_name(rec: dict) -> str:
    info = _info(rec)
    prov = _prov(rec)
    return (info.get("originalfilename")
            or info.get("productname")
            or info.get("filedescription")
            or prov.get("update_title")
            or prov.get("package_name")
            or "-")


def _signed(rec: dict) -> bool:
    return bool(_pe(rec).get("signed"))


def _has_wx(rec: dict) -> bool:
    return bool(_pe(rec).get("wx"))


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
    "signer": lambda r: (_pe(r).get("signers") or ["-"])[0],
    # the triage verdict and its rank (match=3 … none=0)
    "hid": lambda r: f"{_hid(r).get('verdict') or 'none'}:{_hid(r).get('rank') or 0}",
    "verdict": lambda r: _hid(r).get("verdict") or "none",
    "rank": lambda r: _hid(r).get("rank") or 0,
    "inj": lambda r: "Y" if _hid(r).get("direct_injection") else "-",
    "umi": lambda r: "Y" if _hid(r).get("user_mode_interface") else "-",
    "vhid": lambda r: "Y" if _hid(r).get("self_hid_device",
                                        _hid(r).get("virtual_hid")) else "-",
    "mouse": lambda r: "Y" if _hid(r).get("mouse_injection") else "-",
    "kbd": lambda r: "Y" if _hid(r).get("keyboard_injection") else "-",
    "shid": lambda r: "Y" if _hid(r).get("self_hid_device",
                                         _hid(r).get("virtual_hid")) else "-",
    "hwi": lambda r: "Y" if _hid(r).get("hardware_independent_init") else "-",
    "x64": lambda r: "Y" if _hid(r).get("x64_driver") else "-",
    "lol": lambda r: "Y" if _dig(r, "loldrivers.known") else "-",
    "caps": lambda r: ",".join(_caps(r)) or "-",
    "wx": lambda r: "Y" if _has_wx(r) else "-",
    "driver": lambda r: "Y" if _pe(r).get("is_driver") else "-",
    "native": lambda r: "Y" if _pe(r).get("native") else "-",
    "exports": lambda r: _pe(r).get("exports") or 0,
    "imphash": lambda r: _pe(r).get("imphash") or "-",
    "pdb": lambda r: _pe(r).get("pdb") or "-",
    "company": lambda r: _info(r).get("companyname") or "-",
    "product": lambda r: _info(r).get("productname") or "-",
    "package": lambda r: _prov(r).get("package_name") or "-",
    "url": lambda r: _prov(r).get("package_url") or "-",
    "uid": lambda r: _prov(r).get("catalog_uid") or "-",
    "title": lambda r: _prov(r).get("update_title") or "-",
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
            [_display_name(r), *(_info(r).get(k, "") for k in
             ("originalfilename", "productname", "filedescription"))],
            a.name))
    if a.company:
        preds.append(lambda r: _contains_ci([_info(r).get("companyname", "")], a.company))
    if a.product:
        preds.append(lambda r: _contains_ci([_info(r).get("productname", "")], a.product))
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

    # ── the three triage axes ────────────────────────────────────────────────
    if a.verdict:
        want = set(a.verdict)
        preds.append(lambda r: (_hid(r).get("verdict") or "none") in want)
    if a.min_rank is not None:
        preds.append(lambda r: (_hid(r).get("rank") or 0) >= a.min_rank)
    if a.direct_injection:
        preds.append(lambda r: bool(_hid(r).get("direct_injection")))
    if a.mouse_injection:
        preds.append(lambda r: bool(_hid(r).get("mouse_injection")))
    if a.keyboard_injection:
        preds.append(lambda r: bool(_hid(r).get("keyboard_injection")))
    if a.user_mode_interface:
        preds.append(lambda r: bool(_hid(r).get("user_mode_interface")))

    def _self_hid(r: dict) -> bool:  # new field, with legacy fallback
        h = _hid(r)
        return bool(h.get("self_hid_device", h.get("virtual_hid")))

    if a.virtual_hid or a.self_hid:
        preds.append(_self_hid)
    if a.no_virtual_hid or a.no_self_hid:
        preds.append(lambda r: not _self_hid(r))
    if a.hw_independent:
        preds.append(lambda r: bool(_hid(r).get("hardware_independent_init")))
    if a.x64_driver:
        preds.append(lambda r: bool(_hid(r).get("x64_driver")))

    if a.signed:
        preds.append(_signed)
    if a.unsigned:
        preds.append(lambda r: not _signed(r))
    if a.signer:
        preds.append(lambda r: _contains_ci(_pe(r).get("signers") or [], a.signer))
    if a.loldrivers:
        preds.append(lambda r: bool(_dig(r, "loldrivers.known")))
    if a.wx:
        preds.append(_has_wx)
    if a.driver:
        preds.append(lambda r: bool(_pe(r).get("is_driver")))
    if a.native:
        preds.append(lambda r: bool(_pe(r).get("native")))
    if a.min_entropy is not None:
        preds.append(lambda r: (r.get("entropy") or 0.0) >= a.min_entropy)
    if a.max_entropy is not None:
        preds.append(lambda r: (r.get("entropy") or 0.0) <= a.max_entropy)
    if a.imphash:
        preds.append(lambda r: _contains_ci([_pe(r).get("imphash") or ""], a.imphash))
    if a.pdb:
        preds.append(lambda r: _contains_ci([_pe(r).get("pdb") or ""], a.pdb))

    # ── evidence-string filters (from hid_input.evidence) ────────────────────
    if a.symlink:
        preds.append(lambda r: _contains_ci(_evidence(r).get("symlinks") or [], a.symlink))
    if a.device:
        preds.append(lambda r: _contains_ci(_evidence(r).get("device_names") or [], a.device))
    if a.class_guid:
        preds.append(lambda r: _contains_ci(_evidence(r).get("class_guids") or [], a.class_guid))
    return preds


# --------------------------------------------------------------------- output


_COLOR = sys.stdout.isatty()
_C = {"match": "\033[31m", "candidate": "\033[33m",
      "keyboard_only": "\033[2m", "self_hid": "\033[36m", "virtual_hid": "\033[36m",
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
            if f in ("hid", "verdict"):
                padded = _paint(padded, (_hid(r).get("verdict") or "none"))
            elif f == "lol" and cell.strip() == "Y":
                padded = _paint(padded, "lol")
            cells.append(padded)
        print("  ".join(cells))


def _print_csv(records: list[dict], fields: list[str]) -> None:
    w = csv.writer(sys.stdout, lineterminator="\n")
    w.writerow(fields)
    for r in records:
        w.writerow([_field(r, f) for f in fields])


# ------------------------------------------------------------------- detail


def _print_detail(rec: dict) -> None:
    pe = _pe(rec)
    info = _info(rec)
    hid = _hid(rec)
    ev = _evidence(rec)
    lol = rec.get("loldrivers") or {}
    prov = _prov(rec)

    def head(t): print(_paint(f"\n== {t} ==", "dim"))

    print(_paint(rec.get("sha256", "?"), "dim"))
    print(f"name        {_display_name(rec)}")
    print(f"size        {rec.get('size')} bytes   entropy {rec.get('entropy')}")
    print(f"md5         {rec.get('md5')}")

    head("pe")
    if pe and not pe.get("parse_error"):
        print(f"arch        {pe.get('arch')}  is_driver {pe.get('is_driver')}  "
              f"native {pe.get('native')}")
        print(f"imphash     {pe.get('imphash')}")
        print(f"exports     {pe.get('exports')}   W^X {pe.get('wx')}")
        if pe.get("pdb"):
            print(f"pdb         {pe.get('pdb')}")
        print(f"signed      {pe.get('signed')}")
        for cn in (pe.get("signers") or []):
            print(f"  signer    {cn}")
    elif pe.get("parse_error"):
        print(f"(parse error: {pe.get('parse_error')})")
    else:
        print("(not a PE / unparsed)")

    head("capabilities")
    caps = pe.get("capabilities") or {}
    if caps:
        for cat, fns in sorted(caps.items()):
            print(f"  {cat:<16} {', '.join(fns)}")
    else:
        print("  (none of the tracked buckets)")

    head("hid_input")
    print(f"verdict     {_paint(hid.get('verdict') or 'none', hid.get('verdict') or 'none')}"
          f"  rank {hid.get('rank')}")
    print(f"axes        mouse_injection={hid.get('mouse_injection')}  "
          f"keyboard_injection={hid.get('keyboard_injection')}  "
          f"user_mode_interface={hid.get('user_mode_interface')}")
    print(f"            self_hid_device="
          f"{hid.get('self_hid_device', hid.get('virtual_hid'))}  "
          f"hardware_independent_init={hid.get('hardware_independent_init')}")
    print(f"            x64_driver={hid.get('x64_driver')}  "
          f"signature_present={hid.get('signature_present')}")
    if ev:
        _ev_list("mouse inj imports", ev.get("mouse_injection_imports"))
        _ev_list("mouse inj strings", ev.get("mouse_injection_strings"))
        _ev_list("mouse class targets", ev.get("mouse_class_targets"))
        if ev.get("mouse_class_attach"):
            print("  mouse_class_attach  yes (IoGetDeviceObjectPointer + attach)")
        _ev_list("kbd inj imports", ev.get("keyboard_injection_imports"))
        _ev_list("kbd inj strings", ev.get("keyboard_injection_strings"))
        _ev_list("kbd class targets", ev.get("keyboard_class_targets"))
        if ev.get("keyboard_class_attach"):
            print("  kbd_class_attach    yes (IoGetDeviceObjectPointer + attach)")
        if ev.get("creates_user_device"):
            print("  creates_user_device yes (IoCreateDevice + IoCreateSymbolicLink)")
        _ev_list("symlinks", ev.get("symlinks"))
        _ev_list("device names", ev.get("device_names"))
        _ev_list("vhf imports", ev.get("vhf_imports"))
        if ev.get("hid_minidriver"):
            print("  hid_minidriver      yes (HidRegisterMinidriver / hidclass)")
        _ev_list("class guids", ev.get("class_guids"))

    head("loldrivers")
    if lol.get("known"):
        print(f"known       yes (match={lol.get('match')}, id={lol.get('id')})")
        print(f"category    {lol.get('category')}")
        if lol.get("tags"):
            print(f"tags        {', '.join(lol['tags'])}")
    else:
        print("known       no")

    if info:
        head("version_info")
        for k in ("companyname", "productname", "filedescription",
                  "originalfilename", "fileversion"):
            if info.get(k):
                print(f"  {k:<18} {info[k]}")

    head("provenance")
    for k in ("source_kind", "aggregator", "update_title", "update_product",
              "update_classification", "update_date", "update_version",
              "catalog_uid", "package_name", "package_url", "package_sha256"):
        if prov.get(k):
            print(f"  {k:<22} {prov[k]}")
    if prov.get("matched_queries"):
        print(f"  matched_queries        {', '.join(prov['matched_queries'])}")
    if rec.get("seen_in"):
        print(f"  seen_in                {len(rec['seen_in'])} package(s)")


def _ev_list(label: str, vals: list | None) -> None:
    vals = vals or []
    if not vals:
        return
    shown = ", ".join(vals[:12])
    more = f"  (+{len(vals) - 12} more)" if len(vals) > 12 else ""
    print(f"  {label:<20}{shown}{more}")


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

    _dist("verdicts", Counter((_hid(r).get("verdict") or "none") for r in records))
    _dist("axes true", Counter(
        axis for r in records for axis in
        ("mouse_injection", "keyboard_injection", "user_mode_interface",
         "self_hid_device", "hardware_independent_init",
         "x64_driver", "signature_present")
        if _hid(r).get(axis)))
    _dist("arch", Counter((_pe(r).get("arch") or "-") for r in records))
    cap_counter: Counter = Counter()
    for r in records:
        cap_counter.update(_caps(r))
    if cap_counter:
        _dist("capabilities", cap_counter)
    _dist("top products", Counter((_info(r).get("productname") or "-")
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
        epilog="Filters AND together; a repeated flag ANDs its own values.")

    # filters
    f = ap.add_argument_group("filters")
    f.add_argument("--sha", action="append", metavar="HEX", help="sha256 substring (repeatable)")
    f.add_argument("--name", metavar="SUBSTR", help="match name / version-info (ci)")
    f.add_argument("--company", metavar="SUBSTR", help="version-info CompanyName (ci)")
    f.add_argument("--product", metavar="SUBSTR", help="version-info ProductName (ci)")
    f.add_argument("--arch", action="append", metavar="ARCH",
                   help="x64/x86/arm64/… (repeatable)")
    f.add_argument("--capability", action="append", metavar="CAP",
                   choices=[*_CAP_NAMES, "any"],
                   help=f"require capability bucket (repeatable): {', '.join(_CAP_NAMES)}, any")

    # the three triage axes
    f.add_argument("--verdict", action="append", choices=list(_VERDICTS),
                   metavar="VERDICT", help="match/candidate/virtual_hid/none (repeatable)")
    f.add_argument("--min-rank", type=int, metavar="N", dest="min_rank",
                   help="hid_input.rank >= N "
                        "(match=4, candidate=3, self_hid=2, keyboard_only=1, none=0)")
    f.add_argument("--direct-injection", action="store_true", dest="direct_injection",
                   help="drives any input class stack directly (legacy; mouse OR keyboard)")
    f.add_argument("--mouse-injection", action="store_true", dest="mouse_injection",
                   help="drives the MOUSE class stack directly (optional evidence)")
    f.add_argument("--keyboard-injection", action="store_true", dest="keyboard_injection",
                   help="drives the keyboard class stack directly "
                        "(disqualifying on its own under the target profile)")
    f.add_argument("--user-mode-interface", action="store_true", dest="user_mode_interface",
                   help="exposes a user-mode control interface (device + symlink)")
    f.add_argument("--self-hid", action="store_true", dest="self_hid",
                   help="creates or depends on its own HID device "
                        "(VHF / HID minidriver / hidclass/hidparse/vhf linkage; confirm creation)")
    f.add_argument("--no-self-hid", action="store_true", dest="no_self_hid",
                   help="is NOT a self-created HID device")
    f.add_argument("--virtual-hid", action="store_true", dest="virtual_hid",
                   help="legacy alias of --self-hid")
    f.add_argument("--no-virtual-hid", action="store_true", dest="no_virtual_hid",
                   help="legacy alias of --no-self-hid")
    f.add_argument("--hw-independent", action="store_true", dest="hw_independent",
                   help="hardware independence is verified "
                        "(currently unknown in byte triage; this filter yields no candidates)")
    f.add_argument("--x64-driver", action="store_true", dest="x64_driver",
                   help="PE is an x64 kernel driver (target profile prerequisite)")

    f.add_argument("--signed", action="store_true", help="has embedded Authenticode")
    f.add_argument("--unsigned", action="store_true", help="no embedded Authenticode")
    f.add_argument("--signer", metavar="SUBSTR", help="signer common-name contains (ci)")
    f.add_argument("--loldrivers", action="store_true", help="known in the LOLDrivers snapshot")
    f.add_argument("--wx", action="store_true", help="has a writable+executable section")
    f.add_argument("--driver", action="store_true", help="PE looks like a kernel driver")
    f.add_argument("--native", action="store_true", help="native subsystem (subsystem 1)")
    f.add_argument("--min-entropy", type=float, metavar="H", dest="min_entropy")
    f.add_argument("--max-entropy", type=float, metavar="H", dest="max_entropy")
    f.add_argument("--imphash", metavar="SUBSTR", help="imphash contains (ci)")
    f.add_argument("--pdb", metavar="SUBSTR", help="CodeView PDB path contains (ci)")
    f.add_argument("--symlink", metavar="SUBSTR",
                   help="evidence symbolic-link path contains (ci)")
    f.add_argument("--device", metavar="SUBSTR",
                   help="evidence device name contains (ci)")
    f.add_argument("--class-guid", metavar="SUBSTR", dest="class_guid",
                   help="evidence HID class GUID name contains (ci)")

    # output
    o = ap.add_argument_group("output")
    o.add_argument("--show", metavar="SHA", help="detail view for one record (sha256 prefix)")
    o.add_argument("--json", action="store_true", help="emit matching records as a JSON array")
    o.add_argument("--jsonl", action="store_true", help="emit matching records as JSON lines")
    o.add_argument("--csv", action="store_true", help="emit a CSV with the selected fields")
    o.add_argument("--count", action="store_true", help="print only the number of matches")
    o.add_argument("--stats", action="store_true", help="print summary stats for the matches")
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
        _print_detail(rec)
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
        records.sort(key=lambda r: (_hid(r).get("rank") or 0), reverse=True)

    if a.limit is not None:
        records = records[: max(0, a.limit)]

    if a.count:
        print(len(records))
        return 0
    if a.stats:
        _print_stats(records)
        return 0
    if a.json:
        json.dump(records, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0
    if a.jsonl:
        for r in records:
            sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
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
