"""Parse driver binaries as bytes and feed the live `drivers/index.jsonl`.

The content-addressed store (`pipeline_out/drivers/<sha256>.sys`) is a flat tree
of hash-named binaries. `index.jsonl` is the single, append-only index kept
alongside it: as each new binary is stored, collection appends one *analysis*
line describing it, and later one or more *provenance* lines once origin is
known. Nothing is executed — binaries are parsed purely as bytes.

A line is a JSON object keyed by `sha256`. Analysis lines carry:

  * **infos**  — PE identity: machine/arch, subsystem, timestamp, imphash, size,
                 original_name, extraction_path
  * **apis**   — every imported symbol, grouped by DLL plus a flagged
                 driver-abuse subset
  * **strings** — deduped ASCII and UTF-16LE strings

Provenance lines carry `{"sha256", "provenance": {...}}`. A reader folds every
line sharing a `sha256` to get the full record (see `fold_index`).

This module also provides `analyze_binary()` (used by the collectors at store
time) and a CLI that backfills analysis lines for any `.sys` already in the
store that is missing one — useful after a reset or an interrupted run:

    python -m pipeline.index            # append missing analysis lines
    python -m pipeline.index --rebuild  # drop + rebuild all analysis lines
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from . import config
from .collectors import _common as C

_MACHINE = {0x014c: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x01c0: "arm", 0x01c4: "armnt"}
_SUBSYSTEM = {0: "unknown", 1: "native", 2: "gui", 3: "console"}

# Imports worth surfacing: the primitives kernel-driver exploits lean on
# (physical memory, MSR/CR, port I/O, process handles, arbitrary copies). Not a
# verdict — just a flag so the index is scannable. Matched case-insensitively.
_DANGEROUS = {
    "mmmapiospace", "mmmapiospaceex", "mmunmapiospace", "mmgetphysicaladdress",
    "zwmapviewofsection", "zwopensection", "mmcopymemory", "mmcopyvirtualmemory",
    "__readmsr", "__writemsr", "__readcr", "__writecr0", "__writecr3", "__writecr4",
    "__inbyte", "__inword", "__indword", "__outbyte", "__outword", "__outdword",
    "halgetbusdatabyoffset", "halsetbusdatabyoffset", "pssetloadimagenotifyroutine",
    "pslookupprocessbyprocessid", "obopenobjectbypointer", "obreferenceobjectbyhandle",
    "kestackattachprocess", "zwdeviceiocontrolfile", "mmmaplockedpagesspecifycache",
    "iocreatesymboliclink", "iocreatedevice", "rtlcopymemory", "memcpy",
}

_ASCII_PAT = rb"[\x20-\x7e]{%d,}"
_UTF16_PAT = rb"(?:[\x20-\x7e]\x00){%d,}"


# ---------------------------------------------------------------- PE parsing


def _cstr(data: bytes, off: int, limit: int = 256) -> str:
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("ascii", "replace")


def _rva_to_off(rva: int, sections: list[tuple[int, int, int, int]]) -> int | None:
    for va, vsize, raw_ptr, raw_size in sections:
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            return raw_ptr + (rva - va)
    return None


def pe_info(data: bytes) -> dict | None:
    """Parse a PE's headers and import table from bytes. None if not a PE."""
    try:
        if data[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return None
        coff = pe + 4
        machine, nsec = struct.unpack_from("<HH", data, coff)
        timestamp = struct.unpack_from("<I", data, coff + 4)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        plus = magic == 0x20b
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        dd_off = opt + (112 if plus else 96)
        n_dd = struct.unpack_from("<I", data, opt + (108 if plus else 92))[0]
        import_rva = 0
        if n_dd > 1:
            import_rva = struct.unpack_from("<I", data, dd_off + 8)[0]

        sec_off = opt + opt_size
        sections: list[tuple[int, int, int, int]] = []
        for i in range(nsec):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
            sections.append((va, vsize, raw_ptr, raw_size))

        imports = _parse_imports(data, import_rva, sections, plus) if import_rva else {}
        flat = sorted({f for fns in imports.values() for f in fns})
        return {
            "machine": hex(machine),
            "arch": _MACHINE.get(machine, hex(machine)),
            "subsystem": subsystem,
            "subsystem_name": _SUBSYSTEM.get(subsystem, str(subsystem)),
            "native": subsystem == 1,
            "timestamp": timestamp,
            "imports": imports,
            "api_count": len(flat),
            "dangerous_imports": [f for f in flat if f.lower() in _DANGEROUS],
            "imphash": _imphash(imports),
        }
    except (struct.error, IndexError, ValueError):
        return None


def _parse_imports(data, import_rva, sections, plus) -> dict[str, list[str]]:
    imports: dict[str, list[str]] = {}
    desc = _rva_to_off(import_rva, sections)
    if desc is None:
        return imports
    thunk_sz = 8 if plus else 4
    ord_flag = (1 << 63) if plus else (1 << 31)
    for i in range(4096):  # hard cap on descriptor count
        base = desc + i * 20
        if base + 20 > len(data):
            break
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, base)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        name_off = _rva_to_off(name_rva, sections)
        dll = _cstr(data, name_off).lower() if name_off is not None else f"rva_{name_rva:#x}"
        thunk_off = _rva_to_off(oft or ft, sections)
        if thunk_off is None:
            imports.setdefault(dll, [])
            continue
        funcs: list[str] = []
        for j in range(8192):  # hard cap on symbols per DLL
            toff = thunk_off + j * thunk_sz
            if toff + thunk_sz > len(data):
                break
            val = struct.unpack_from("<Q" if plus else "<I", data, toff)[0]
            if val == 0:
                break
            if val & ord_flag:
                funcs.append(f"ord{val & 0xffff}")
            else:
                hn = _rva_to_off(val & 0x7fffffff, sections)
                if hn is not None:
                    funcs.append(_cstr(data, hn + 2))
        imports[dll] = funcs
    return imports


def _imphash(imports: dict[str, list[str]]) -> str | None:
    """pefile-compatible imphash over the parsed import table."""
    parts: list[str] = []
    for dll, funcs in imports.items():
        base = dll.lower()
        for ext in (".dll", ".ocx", ".sys"):
            if base.endswith(ext):
                base = base[:-len(ext)]
                break
        for fn in funcs:
            parts.append(f"{base}.{fn.lower()}")
    if not parts:
        return None
    return hashlib.md5(",".join(parts).encode()).hexdigest()


# ------------------------------------------------------------------- strings


def extract_strings(data: bytes, min_len: int = 5, max_count: int = 3000) -> dict:
    a = {m.group().decode("ascii", "replace")
         for m in re.finditer(_ASCII_PAT % min_len, data)}
    u = {m.group().decode("utf-16-le", "replace")
         for m in re.finditer(_UTF16_PAT % min_len, data)}
    u -= a  # a utf16 run also matches ascii on its low bytes; keep one bucket
    asc, wide = sorted(a), sorted(u)
    truncated = False
    if len(asc) > max_count:
        asc, truncated = asc[:max_count], True
    if len(wide) > max_count:
        wide, truncated = wide[:max_count], True
    return {"ascii": asc, "utf16": wide,
            "count": len(a) + len(u), "truncated": truncated}


# ----------------------------------------------------------------- analysis


def analyze_binary(path: Path, *, min_str: int = 5, max_str: int = 3000) -> dict:
    """Full byte-derived analysis line for a stored binary (sha256 = filename)."""
    data = path.read_bytes()
    return {
        "sha256": path.stem,
        "kind": "analysis",
        "size": len(data),
        "pe": pe_info(data),
        "strings": extract_strings(data, min_str, max_str),
    }


# ------------------------------------------------------------------- readers


def fold_index(drivers_dir: Path | None = None) -> dict[str, dict]:
    """Fold `index.jsonl` into one merged record per sha256 (analysis + provenance)."""
    drivers_dir = drivers_dir or config.drivers_dir()
    path = drivers_dir / "index.jsonl"
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        sha = r.get("sha256")
        if not sha:
            continue
        e = out.setdefault(sha, {"sha256": sha, "seen_in": []})
        prov = r.pop("provenance", None)
        r.pop("ts", None)
        for k, v in r.items():
            if v is not None and k != "sha256":
                e[k] = v
        if prov:
            e["provenance"] = {**(e.get("provenance") or {}), **prov}
            pkg = prov.get("package_url") or prov.get("installer_url")
            if pkg and pkg not in e["seen_in"]:
                e["seen_in"].append(pkg)
    return out


# ------------------------------------------------------------------- backfill


def _analysed_shas(drivers_dir: Path) -> set[str]:
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
        if r.get("kind") == "analysis" or "strings" in r:
            if r.get("sha256"):
                done.add(r["sha256"])
    return done


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pipeline.index",
        description="Backfill analysis lines in drivers/index.jsonl for stored binaries.")
    ap.add_argument("--min-str", type=int, default=5, help="minimum string length (default 5)")
    ap.add_argument("--max-str", type=int, default=3000,
                    help="max strings per bucket per driver (default 3000)")
    ap.add_argument("--rebuild", action="store_true",
                    help="drop every existing analysis line and re-emit them "
                         "(provenance lines are preserved)")
    args = ap.parse_args(argv)
    drivers_dir = config.drivers_dir()
    ledger = drivers_dir / "index.jsonl"

    if args.rebuild and ledger.exists():
        kept = [ln for ln in ledger.read_text(encoding="utf-8").splitlines()
                if ln.strip() and _is_provenance(ln)]
        ledger.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")

    done = _analysed_shas(drivers_dir)
    sys_files = sorted(drivers_dir.glob("*.sys"))
    added = 0
    for i, p in enumerate(sys_files, 1):
        if p.stem in done:
            continue
        try:
            entry = analyze_binary(p, min_str=args.min_str, max_str=args.max_str)
        except OSError:
            continue
        C.append_index(drivers_dir, entry)
        added += 1
        if added % 100 == 0:
            print(f"  analysed {added} new", file=sys.stderr)
    print(f"{ledger}: {len(sys_files)} binaries in store, {added} analysis line(s) appended")
    return 0


def _is_provenance(line: str) -> bool:
    try:
        r = json.loads(line)
    except ValueError:
        return False
    return r.get("kind") != "analysis" and "strings" not in r and "provenance" in r


if __name__ == "__main__":
    raise SystemExit(main())
