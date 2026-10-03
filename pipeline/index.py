"""Build a single `drivers/index.json` over the content-addressed store.

The store (`pipeline_out/drivers/<sha256>.sys`) is a flat tree of hash-named
binaries. This module parses each one *as bytes* — no execution, no external
deps — to extract the information a triage pass actually reads:

  * **infos**  — PE identity: machine/arch, subsystem, timestamp, size, imphash
  * **apis**   — every imported symbol, grouped by DLL plus a flat list, with a
                 flagged subset of driver-abuse-relevant imports
  * **strings** — deduped ASCII and UTF-16LE strings

and joins the origin metadata (`original_name`, provenance, packages a binary
shipped in) recorded during collection in `drivers/_provenance.jsonl` and in run
`manifest.json` files. The result is written as one `drivers/index.json`.

Run:  python -m pipeline.index  [--min-str N] [--max-str N] [--out PATH]
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

SCHEMA_VERSION = 1

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

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


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
        import_rva = import_size = 0
        if n_dd > 1:
            import_rva, import_size = struct.unpack_from("<II", data, dd_off + 8)

        sec_off = opt + opt_size
        sections: list[tuple[int, int, int, int]] = []
        for i in range(nsec):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
            sections.append((va, vsize, raw_ptr, raw_size))

        imports: dict[str, list[str]] = {}
        if import_rva:
            imports = _parse_imports(data, import_rva, sections, plus)

        flat = sorted({f for fns in imports.values() for f in fns})
        info = {
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
        return info
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
        thunk_rva = oft or ft
        thunk_off = _rva_to_off(thunk_rva, sections)
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
    if not imports:
        return None
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


def extract_strings(data: bytes, min_len: int, max_count: int) -> dict:
    ascii_re = re.compile(_ASCII_RE.pattern % min_len)
    utf16_re = re.compile(_UTF16_RE.pattern % min_len)
    a = {m.group().decode("ascii", "replace") for m in ascii_re.finditer(data)}
    u = {m.group().decode("utf-16-le", "replace") for m in utf16_re.finditer(data)}
    u -= a  # a utf16 run also matches ascii on its low bytes; keep it in one bucket
    asc = sorted(a)
    wide = sorted(u)
    truncated = False
    if len(asc) > max_count:
        asc, truncated = asc[:max_count], True
    if len(wide) > max_count:
        wide, truncated = wide[:max_count], True
    return {"ascii": asc, "utf16": wide,
            "count": len(a) + len(u), "truncated": truncated}


# ------------------------------------------------------------- provenance join


def load_provenance(drivers_dir: Path) -> dict[str, dict]:
    """Merge per-sha provenance from `_provenance.jsonl` and run manifests."""
    merged: dict[str, dict] = {}

    def fold(sha: str, *, original_name=None, provenance=None, extraction_path=None,
             size=None, carved=None):
        e = merged.setdefault(sha, {"seen_in": []})
        if original_name and not e.get("original_name"):
            e["original_name"] = original_name
        if extraction_path and not e.get("extraction_path"):
            e["extraction_path"] = extraction_path
        if size and not e.get("size"):
            e["size"] = size
        if carved:
            e["carved"] = True
        if provenance:
            e["provenance"] = {**(e.get("provenance") or {}), **provenance}
            pkg = provenance.get("package_url") or provenance.get("installer_url")
            if pkg and pkg not in e["seen_in"]:
                e["seen_in"].append(pkg)

    ledger = drivers_dir / "_provenance.jsonl"
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            sha = r.get("sha256")
            if sha:
                fold(sha, original_name=r.get("original_name"),
                     provenance=r.get("provenance"), extraction_path=r.get("extraction_path"),
                     size=r.get("size"), carved=r.get("carved"))

    # Run manifests carry the richest records (original_name + full provenance).
    for manifest in config.collectors_dir().rglob("manifest.json"):
        try:
            m = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for d in m.get("drivers") or []:
            sha = d.get("sha256")
            if sha:
                fold(sha, original_name=d.get("original_name"),
                     provenance=d.get("provenance"), extraction_path=d.get("extraction_path"),
                     size=d.get("size"), carved=d.get("carved"))

    # Fallback: the touslesdrivers download ledger maps package url -> sha list.
    for proc in config.collectors_dir().rglob("processed.jsonl"):
        for line in proc.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            url = r.get("url")
            for sha in r.get("sys") or []:
                if sha in merged and not merged[sha].get("provenance") and url:
                    fold(sha, provenance={"source_kind": "touslesdrivers-aggregator-input",
                                          "aggregator": "touslesdrivers.com", "package_url": url})
    return merged


# ------------------------------------------------------------------- builder


def build_index(*, min_str: int = 5, max_str: int = 3000) -> dict:
    drivers_dir = config.drivers_dir()
    prov = load_provenance(drivers_dir)
    sys_files = sorted(drivers_dir.glob("*.sys"))
    drivers: dict[str, dict] = {}
    for i, p in enumerate(sys_files, 1):
        sha = p.stem
        try:
            data = p.read_bytes()
        except OSError:
            continue
        pe = pe_info(data)
        strings = extract_strings(data, min_str, max_str)
        meta = prov.get(sha, {})
        drivers[sha] = {
            "sha256": sha,
            "original_name": meta.get("original_name"),
            "size": p.stat().st_size,
            "pe": pe,
            "strings": strings,
            "provenance": meta.get("provenance"),
            "seen_in": meta.get("seen_in") or [],
            "extraction_path": meta.get("extraction_path"),
            "carved": meta.get("carved", False),
        }
        if i % 100 == 0 or i == len(sys_files):
            print(f"  indexed {i}/{len(sys_files)}", file=sys.stderr)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": C.utc_now(),
        "driver_count": len(drivers),
        "params": {"min_str": min_str, "max_str": max_str},
        "drivers": drivers,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build drivers/index.json over the store.")
    ap.add_argument("--min-str", type=int, default=5, help="minimum string length (default 5)")
    ap.add_argument("--max-str", type=int, default=3000,
                    help="max strings per bucket per driver (default 3000)")
    ap.add_argument("--out", type=Path, default=None,
                    help="output path (default: pipeline_out/drivers/index.json)")
    args = ap.parse_args(argv)
    out = args.out or (config.drivers_dir() / "index.json")
    index = build_index(min_str=args.min_str, max_str=args.max_str)
    C.save_json(out, index)
    print(f"wrote {out}  ({index['driver_count']} drivers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
