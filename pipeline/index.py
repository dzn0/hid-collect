"""Parse driver binaries as bytes and feed the live `drivers/index.jsonl`.

The content-addressed store (`pipeline_out/drivers/<sha256>.sys`) is a flat tree
of hash-named binaries. `index.jsonl` is the single, append-only index kept
alongside it: as each new binary is stored, collection appends one *analysis*
line, and later one or more *provenance* lines once origin is known. Nothing is
executed — binaries are parsed purely as bytes (no disassembly, no emulation).

The index has ONE job: decide, from bytes alone, which drivers are worth pulling
into a disassembler / decompiler. It is a triage filter, not an archive — so each
analysis line is deliberately lean: just enough identity to recognise a binary,
plus the signals that answer the project's question, and nothing that belongs in
the decompiler instead (no raw import table, no string dumps, no section maps).

The question, stated precisely. We hunt a driver that:
  1. exposes a **user-mode control interface** — a device + symbolic link user
     mode can open and drive with IOCTLs;
  2. is **not a virtual HID device** — it does NOT present synthetic input the
     legitimate way (Virtual HID Framework / HID minidriver); and
  3. **injects mouse/keyboard input by driving the class stack directly** —
     calling MouseClassServiceCallback (or attaching to \\Device\\PointerClass0)
     with crafted MOUSE_INPUT_DATA, bypassing the real HID stack.

Each analysis line is a JSON object keyed by `sha256`:

  * **identity** — size, md5, imphash, file entropy; and under `pe`: arch,
    is_driver/native, signed + signer CN(s), W^X section flag, export count,
    CodeView PDB path, and a few VS_VERSIONINFO fields (company/product/…)
  * **capabilities** — curated kernel-primitive buckets (phys_mem, port_io,
    msr_control_reg, process_access, device_io, input_injection)
  * **hid_input** — the triage verdict: the three booleans above
    (`user_mode_interface`, `virtual_hid`, `direct_injection`), a `verdict`
    (`match`/`candidate`/`virtual_hid`/`none`) + `rank`, and the `evidence`
    (which imports/strings/symlinks/GUIDs fired) so the call is auditable
  * **loldrivers** — cross-reference against a vendored LOLDrivers snapshot

A reader folds every line sharing a `sha256` (see `fold_index`). This module also
exposes `analyze_binary()` (used by the collectors at store time) and a CLI that
backfills analysis lines for `.sys` already in the store:

    python -m pipeline.index            # append missing analysis lines
    python -m pipeline.index --rebuild  # drop + re-emit all analysis lines
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path

from . import config
from .collectors import _common as C

_REFS = Path(__file__).resolve().parent / "refs"

_MACHINE = {0x014c: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x01c0: "arm", 0x01c4: "armnt",
            0x0200: "ia64"}
_SUBSYSTEM = {0: "unknown", 1: "native", 2: "gui", 3: "console", 9: "wince", 14: "xbox"}

_CHARACTERISTICS = {
    0x0002: "executable", 0x0020: "large_address_aware", 0x2000: "dll",
    0x1000: "system", 0x0001: "relocs_stripped",
}
_DLLCHARS = {
    0x0040: "dynamic_base", 0x0080: "force_integrity", 0x0100: "nx_compat",
    0x0200: "no_isolation", 0x0400: "no_seh", 0x0800: "no_bind",
    0x1000: "appcontainer", 0x2000: "wdm_driver", 0x4000: "guard_cf",
    0x8000: "terminal_server_aware", 0x0020: "high_entropy_va",
}
_DD_NAMES = ["export", "import", "resource", "exception", "security", "basereloc",
             "debug", "arch", "globalptr", "tls", "load_config", "bound_import",
             "iat", "delay_import", "clr", "reserved"]

# Imports worth surfacing: primitives kernel-driver exploits lean on. Not a
# verdict — a flag so the index is scannable. Matched case-insensitively.
_CAPABILITIES = {
    "input_injection": {"mouseclassservicecallback", "mouclassservicecallback",
                        "keyboardclassservicecallback", "kbdclassservicecallback"},
    "phys_mem": {"mmmapiospace", "mmmapiospaceex", "mmgetphysicaladdress",
                 "mmmaplockedpagesspecifycache", "zwmapviewofsection", "zwopensection",
                 "mmcopymemory"},
    "msr_control_reg": {"__readmsr", "__writemsr", "__readcr", "__writecr0",
                        "__writecr3", "__writecr4", "__readcr3"},
    "port_io": {"__inbyte", "__outbyte", "__inword", "__outword", "__indword",
                "__outdword", "halgetbusdatabyoffset", "halsetbusdatabyoffset",
                "readportuchar", "writeportuchar"},
    "process_access": {"pslookupprocessbyprocessid", "pssetloadimagenotifyroutine",
                       "pssetcreateprocessnotifyroutine", "obopenobjectbypointer",
                       "kestackattachprocess", "zwopenprocess", "zwterminateprocess",
                       "zwprotectvirtualmemory"},
    "mem_copy": {"memcpy", "memmove", "rtlcopymemory", "rtlmovememory"},
    "device_io": {"iocreatedevice", "iocreatesymboliclink", "ioattachdevicetodevicestack",
                  "iogetdeviceobjectpointer", "obreferenceobjectbyname",
                  "iocreatedevicesecure", "wdmlibiocreatedevicesecure"},
}
# ── the three triage axes (byte-only) ────────────────────────────────────────
#
# (3) DIRECT INJECTION — driving the input class stack directly. The class
# service callbacks are the smoking gun: a driver either imports them, or (more
# often, to dodge trivial import scans) resolves them by name at runtime via
# MmGetSystemRoutineAddress, so the name survives as a string too.
_INJECT_IMPORTS = {
    "mouseclassservicecallback", "mouclassservicecallback",
    "keyboardclassservicecallback", "kbdclassservicecallback",
}
_INJECT_STRINGS = {
    "mouseclassservicecallback", "mouclassservicecallback",
    "keyboardclassservicecallback", "kbdclassservicecallback",
    "mouse_input_data", "keyboard_input_data",
    "\\driver\\mouclass", "\\driver\\kbdclass",
    "\\driver\\mouhid", "\\driver\\kbdhid",
}
# class device objects an injector attaches to / targets directly
_CLASS_DEVICE_STRINGS = {"\\device\\pointerclass", "\\device\\keyboardclass"}
# the attach-to-class-stack primitive (alternative to calling the callback)
_ATTACH_IMPORTS = {"iogetdeviceobjectpointer", "ioattachdevicetodevicestack"}

# (1) USER-MODE INTERFACE — a device plus a symbolic link user mode can open.
_CREATE_DEVICE_IMPORTS = {"iocreatedevice", "iocreatedevicesecure",
                          "wdmlibiocreatedevicesecure"}
_SYMLINK_IMPORT = "iocreatesymboliclink"

# (2) VIRTUAL HID — the *legitimate* way to present synthetic input. Its presence
# disqualifies a driver as the abuse primitive we hunt (it is doing it the right
# way). VHF = Virtual HID Framework; a HID minidriver links hidclass/hidparse.
_VHF_IMPORTS = {"vhfcreate", "vhfstart", "vhfreadreportsubmit", "vhfdeletedevice",
                "vhfasleep", "vhfresume"}
_HID_MINIDRIVER_IMPORTS = {"hidregisterminidriver"}
_HID_CLASS_DLLS = {"hidclass.sys", "hidparse.sys", "vhf.sys"}

_HID_CLASS_GUIDS = {
    "4d36e96f-e325-11ce-bfc1-08002be10318": "GUID_CLASS_MOUSE",
    "4d36e96b-e325-11ce-bfc1-08002be10318": "GUID_CLASS_KEYBOARD",
    "378de44c-56ef-11d1-bc8c-00a0c91405dd": "GUID_DEVINTERFACE_MOUSE",
    "884b96c3-56ef-11d1-bc8c-00a0c91405dd": "GUID_DEVINTERFACE_KEYBOARD",
    "4d1e55b2-f16f-11cf-88cb-001111000030": "GUID_DEVINTERFACE_HID",
    "745a17a0-74d3-11d0-b6fe-00a0c90f57da": "HIDClass",
}

_ASCII_PAT = rb"[\x20-\x7e]{%d,}"
_UTF16_PAT = rb"(?:[\x20-\x7e]\x00){%d,}"
_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

_LOL: dict | None = None


# ---------------------------------------------------------------- small utils


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    n = len(data)
    h = 0.0
    for c in hist:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return round(h, 3)


def _cstr(data: bytes, off: int, limit: int = 512) -> str:
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("ascii", "replace")


# ------------------------------------------------------------------- PE model


class PE:
    """Minimal, defensive PE parser over an in-memory image (no execution)."""

    def __init__(self, data: bytes):
        self.data = data
        self.ok = False
        self.sections: list[dict] = []
        self.dirs: list[tuple[int, int]] = []
        if data[:2] != b"MZ":
            return
        self.pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.pe:self.pe + 4] != b"PE\0\0":
            return
        coff = self.pe + 4
        self.machine, self.nsec = struct.unpack_from("<HH", data, coff)
        self.timestamp = struct.unpack_from("<I", data, coff + 4)[0]
        self.opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        self.characteristics = struct.unpack_from("<H", data, coff + 18)[0]
        opt = coff + 20
        self.opt = opt
        self.magic = struct.unpack_from("<H", data, opt)[0]
        self.plus = self.magic == 0x20b
        self.linker = (data[opt + 2], data[opt + 3])
        self.entrypoint = struct.unpack_from("<I", data, opt + 16)[0]
        if self.plus:
            self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        else:
            self.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        self.checksum = struct.unpack_from("<I", data, opt + 64)[0]
        self.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        self.dllchars = struct.unpack_from("<H", data, opt + 70)[0]
        n_dd = struct.unpack_from("<I", data, opt + (108 if self.plus else 92))[0]
        dd_off = opt + (112 if self.plus else 96)
        self.dirs = []
        for i in range(min(n_dd, 16)):
            self.dirs.append(struct.unpack_from("<II", data, dd_off + i * 8))
        sec_off = opt + self.opt_size
        for i in range(self.nsec):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            name = data[base:base + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
            flags = struct.unpack_from("<I", data, base + 36)[0]
            self.sections.append({"name": name, "vaddr": va, "vsize": vsize,
                                  "rawsize": raw_size, "rawptr": raw_ptr, "flags": flags})
        self.ok = True

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            span = max(s["vsize"], s["rawsize"])
            if s["vaddr"] <= rva < s["vaddr"] + span:
                return s["rawptr"] + (rva - s["vaddr"])
        return None

    def dir(self, idx: int) -> tuple[int, int]:
        return self.dirs[idx] if idx < len(self.dirs) else (0, 0)

    # ---- header summary

    def header(self) -> dict:
        data = self.data
        chars = [v for k, v in _CHARACTERISTICS.items() if self.characteristics & k]
        dchars = [v for k, v in _DLLCHARS.items() if self.dllchars & k]
        is_driver = (self.subsystem == 1) or \
            ("ntoskrnl.exe" in {d.lower() for d in self.imports()})
        return {
            "machine": hex(self.machine),
            "arch": _MACHINE.get(self.machine, hex(self.machine)),
            "pointer_size": 64 if self.plus else 32,
            "subsystem": self.subsystem,
            "subsystem_name": _SUBSYSTEM.get(self.subsystem, str(self.subsystem)),
            "native": self.subsystem == 1,
            "is_driver": bool(is_driver),
            "timestamp": self.timestamp,
            "linker": f"{self.linker[0]}.{self.linker[1]}",
            "image_base": hex(self.image_base),
            "entrypoint": hex(self.entrypoint),
            "checksum": hex(self.checksum),
            "checksum_valid": self._checksum_ok(),
            "characteristics": chars,
            "dll_characteristics": dchars,
            "nx": bool(self.dllchars & 0x0100),
            "aslr": bool(self.dllchars & 0x0040),
            "guard_cf": bool(self.dllchars & 0x4000),
            "data_directories": {_DD_NAMES[i]: {"rva": hex(r), "size": s}
                                 for i, (r, s) in enumerate(self.dirs) if r or s},
        }

    def _checksum_ok(self) -> bool:
        try:
            data, n = self.data, len(self.data)
            ck_off = self.opt + 64
            s = 0
            i = 0
            while i + 1 < n:
                w = 0 if ck_off <= i < ck_off + 4 else data[i] | (data[i + 1] << 8)
                s += w
                s = (s & 0xffff) + (s >> 16)
                i += 2
            if i < n:
                s += 0 if ck_off <= i < ck_off + 4 else data[i]
                s = (s & 0xffff) + (s >> 16)
            s = ((s & 0xffff) + (s >> 16)) & 0xffff
            return ((s + n) & 0xffffffff) == self.checksum
        except Exception:
            return False

    def sections_info(self) -> list[dict]:
        out = []
        for s in self.sections:
            blob = self.data[s["rawptr"]:s["rawptr"] + s["rawsize"]]
            fl = s["flags"]
            out.append({
                "name": s["name"], "vaddr": hex(s["vaddr"]), "vsize": s["vsize"],
                "rawsize": s["rawsize"], "entropy": _entropy(blob),
                "perms": ("r" if fl & 0x40000000 else "") + ("w" if fl & 0x80000000 else "")
                         + ("x" if fl & 0x20000000 else ""),
                "wx": bool(fl & 0x80000000 and fl & 0x20000000),
            })
        return out

    # ---- imports / exports

    def imports(self) -> dict[str, list[str]]:
        if hasattr(self, "_imp"):
            return self._imp
        imp: dict[str, list[str]] = {}
        rva, _ = self.dir(1)
        desc = self.rva_to_off(rva) if rva else None
        if desc is None:
            self._imp = imp
            return imp
        thunk_sz = 8 if self.plus else 4
        ord_flag = (1 << 63) if self.plus else (1 << 31)
        data = self.data
        try:
            for i in range(4096):
                base = desc + i * 20
                if base + 20 > len(data):
                    break
                oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, base)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                noff = self.rva_to_off(name_rva)
                dll = _cstr(data, noff).lower() if noff is not None else f"rva_{name_rva:#x}"
                toff = self.rva_to_off(oft or ft)
                funcs: list[str] = []
                if toff is not None:
                    for j in range(8192):
                        t = toff + j * thunk_sz
                        if t + thunk_sz > len(data):
                            break
                        val = struct.unpack_from("<Q" if self.plus else "<I", data, t)[0]
                        if val == 0:
                            break
                        if val & ord_flag:
                            funcs.append(f"ord{val & 0xffff}")
                        else:
                            hn = self.rva_to_off(val & 0x7fffffff)
                            if hn is not None:
                                funcs.append(_cstr(data, hn + 2, 128))
                imp[dll] = funcs
        except struct.error:
            pass
        self._imp = imp
        return imp

    def exports(self) -> list[str]:
        rva, _ = self.dir(0)
        off = self.rva_to_off(rva) if rva else None
        if off is None:
            return []
        data = self.data
        try:
            n_names = struct.unpack_from("<I", data, off + 24)[0]
            names_rva = struct.unpack_from("<I", data, off + 32)[0]
            names_off = self.rva_to_off(names_rva)
            if names_off is None:
                return []
            out = []
            for i in range(min(n_names, 8192)):
                nrva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                no = self.rva_to_off(nrva)
                if no is not None:
                    out.append(_cstr(data, no, 128))
            return out
        except struct.error:
            return []

    def imphash(self) -> str | None:
        parts = []
        for dll, funcs in self.imports().items():
            base = dll.lower()
            for ext in (".dll", ".ocx", ".sys"):
                if base.endswith(ext):
                    base = base[:-len(ext)]
                    break
            for fn in funcs:
                parts.append(f"{base}.{fn.lower()}")
        return hashlib.md5(",".join(parts).encode()).hexdigest() if parts else None

    # ---- debug / pdb

    def debug(self) -> dict | None:
        rva, size = self.dir(6)
        off = self.rva_to_off(rva) if rva else None
        if off is None:
            return None
        data = self.data
        try:
            for i in range(size // 28):
                base = off + i * 28
                dtype = struct.unpack_from("<I", data, base + 12)[0]
                sizeof = struct.unpack_from("<I", data, base + 16)[0]
                ptr = struct.unpack_from("<I", data, base + 24)[0]
                if dtype == 2 and data[ptr:ptr + 4] == b"RSDS":
                    g = data[ptr + 4:ptr + 20]
                    guid = (f"{int.from_bytes(g[0:4],'little'):08x}-"
                            f"{int.from_bytes(g[4:6],'little'):04x}-"
                            f"{int.from_bytes(g[6:8],'little'):04x}-"
                            f"{g[8:10].hex()}-{g[10:16].hex()}")
                    age = struct.unpack_from("<I", data, ptr + 20)[0]
                    pdb = _cstr(data, ptr + 24, 260)
                    return {"pdb": pdb, "guid": guid, "age": age}
        except struct.error:
            return None
        return None

    # ---- resources: version info + type map

    def resources(self) -> dict:
        rva, _ = self.dir(2)
        root = self.rva_to_off(rva) if rva else None
        info = {"types": [], "has_manifest": False, "has_version": False, "rcdata": 0}
        if root is None:
            return info
        data = self.data
        try:
            n_named = struct.unpack_from("<H", data, root + 12)[0]
            n_id = struct.unpack_from("<H", data, root + 14)[0]
            version_blob = None
            for e in range(n_named + n_id):
                eoff = root + 16 + e * 8
                rid, child = struct.unpack_from("<II", data, eoff)
                if rid & 0x80000000:  # named type, skip id mapping
                    continue
                info["types"].append(rid)
                if rid == 24:
                    info["has_manifest"] = True
                if rid == 10:
                    info["rcdata"] += 1
                if rid == 16:
                    info["has_version"] = True
                    version_blob = self._first_resource_data(root, child & 0x7fffffff)
            if version_blob:
                v = parse_version_info(version_blob)
                if v:
                    info["version_info"] = v
        except struct.error:
            pass
        return info

    def _first_resource_data(self, root: int, dir_rva_off: int) -> bytes | None:
        """Descend a resource subtree (name -> lang) to its first data entry."""
        data = self.data
        off = root + dir_rva_off
        try:
            for _ in range(3):  # name level, lang level, then a leaf
                n_named = struct.unpack_from("<H", data, off + 12)[0]
                n_id = struct.unpack_from("<H", data, off + 14)[0]
                if n_named + n_id == 0:
                    return None
                _rid, child = struct.unpack_from("<II", data, off + 16)  # first entry
                if child & 0x80000000:  # another subdirectory
                    off = root + (child & 0x7fffffff)
                    continue
                # leaf: IMAGE_RESOURCE_DATA_ENTRY (OffsetToData rva, Size, ...)
                data_rva, dsize = struct.unpack_from("<II", data, root + child)
                doff = self.rva_to_off(data_rva)
                return data[doff:doff + dsize] if doff is not None else None
        except struct.error:
            return None
        return None

    # ---- authenticode

    def signature(self) -> dict:
        off, size = self.dir(4)  # NOTE: security dir offset is a FILE offset
        if not size or off + size > len(self.data):
            return {"embedded": False}
        blob = self.data[off:off + size]
        cert = blob[8:] if len(blob) > 8 else b""  # skip WIN_CERTIFICATE header
        return {"embedded": True, "size": size, "cert_common_names": _cert_cns(cert)}


# ------------------------------------------------------- version-info parser


def parse_version_info(blob: bytes) -> dict | None:
    """Best-effort VS_VERSIONINFO -> {fixed version + string table fields}."""
    try:
        out: dict = {}
        # VS_FIXEDFILEINFO: locate the 0xFEEF04BD signature robustly
        sig = blob.find((0xFEEF04BD).to_bytes(4, "little"))
        if sig >= 0 and sig + 24 <= len(blob):
            ms, ls = struct.unpack_from("<II", blob, sig + 8)
            pms, pls = struct.unpack_from("<II", blob, sig + 16)
            out["file_version"] = f"{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}"
            out["product_version"] = f"{pms >> 16}.{pms & 0xffff}.{pls >> 16}.{pls & 0xffff}"
        # string table entries: scan for key\0\0value\0 UTF-16 pairs under StringFileInfo
        wanted = {"CompanyName", "ProductName", "FileDescription", "OriginalFilename",
                  "InternalName", "FileVersion", "ProductVersion", "LegalCopyright"}
        text = blob.decode("utf-16-le", "replace")
        for key in wanted:
            m = re.search(re.escape(key) + r"\x00+([^\x00]{1,200})", text)
            if m:
                out[key] = m.group(1).strip()
        return out or None
    except (struct.error, ValueError):
        return None


# ------------------------------------------------------- certificate CN scan


def _cert_cns(der: bytes) -> list[str]:
    """Pull X.509 commonName attribute values out of a PKCS#7 blob (best-effort)."""
    cns: list[str] = []
    pat = b"\x06\x03\x55\x04\x03"  # OID 2.5.4.3 (commonName)
    i = 0
    while True:
        j = der.find(pat, i)
        if j < 0:
            break
        k = j + 5
        i = k
        if k + 2 > len(der):
            break
        tag = der[k]
        ln = der[k + 1]
        vstart = k + 2
        if ln & 0x80:
            nb = ln & 0x7f
            if nb == 0 or k + 2 + nb > len(der):
                continue
            ln = int.from_bytes(der[k + 2:k + 2 + nb], "big")
            vstart = k + 2 + nb
        val = der[vstart:vstart + ln]
        try:
            s = val.decode("utf-16-be" if tag == 0x1e else "utf-8", "replace").strip()
        except ValueError:
            s = ""
        if s and s not in cns:
            cns.append(s)
    return cns[:16]


# ------------------------------------------------------------------- strings


def extract_strings(data: bytes, min_len: int = 5) -> list[str]:
    """All printable ASCII + UTF-16LE runs, deduped and sorted. Used only to
    derive signals — the raw list is never stored in the index."""
    a = {m.group().decode("ascii", "replace")
         for m in re.finditer(_ASCII_PAT % min_len, data)}
    u = {m.group().decode("utf-16-le", "replace")
         for m in re.finditer(_UTF16_PAT % min_len, data)}
    return sorted(a | u)


# ----------------------------------------------------------- HID-input signals


def hid_input_signals(imports_flat: set[str], imported_dlls: set[str],
                      strings_low: list[str], guids: set[str],
                      symlinks: list[str], device_names: list[str]) -> dict:
    """Score the three triage axes and return a verdict + auditable evidence.

    The target is a driver that injects input by driving the class stack directly
    (axis 3) AND is reachable from user mode (axis 1) AND is NOT a virtual HID
    device (axis 2 — the legitimate path, which disqualifies)."""
    joined = "\n".join(strings_low)

    # (3) direct input-stack injection
    inj_imports   = sorted(imports_flat & _INJECT_IMPORTS)
    inj_strings   = sorted(s for s in _INJECT_STRINGS if s in joined)
    class_targets = sorted(s for s in _CLASS_DEVICE_STRINGS if s in joined)
    class_attach  = _ATTACH_IMPORTS.issubset(imports_flat) and bool(class_targets)
    direct_injection = bool(inj_imports or inj_strings or class_attach)

    # (1) user-mode control interface (device + openable symbolic link)
    creates_device = bool(imports_flat & _CREATE_DEVICE_IMPORTS) and \
        _SYMLINK_IMPORT in imports_flat
    user_mode_interface = creates_device or bool(symlinks)

    # (2) virtual HID device — the legitimate path; disqualifies as our target
    vhf = sorted(imports_flat & _VHF_IMPORTS)
    hid_minidriver = bool(imports_flat & _HID_MINIDRIVER_IMPORTS) or \
        bool(imported_dlls & _HID_CLASS_DLLS)
    virtual_hid = bool(vhf or hid_minidriver)

    guid_hits = sorted({_HID_CLASS_GUIDS[g] for g in guids if g in _HID_CLASS_GUIDS})
    input_adjacent = bool(class_targets or guid_hits or any(
        t in joined for t in ("mouclass", "kbdclass", "pointerclass", "keyboardclass")))

    if direct_injection and not virtual_hid and user_mode_interface:
        verdict = "match"          # the full primitive — decompile this
    elif direct_injection and not virtual_hid:
        verdict = "candidate"      # injects directly, interface unconfirmed
    elif virtual_hid:
        verdict = "virtual_hid"    # legitimate synthetic-input path — filter out
    elif user_mode_interface and input_adjacent:
        verdict = "candidate"      # user-mode device touching the input class
    else:
        verdict = "none"
    rank = {"match": 3, "candidate": 2, "virtual_hid": 1, "none": 0}[verdict]

    return {
        "verdict": verdict,
        "rank": rank,
        "direct_injection": direct_injection,
        "user_mode_interface": user_mode_interface,
        "virtual_hid": virtual_hid,
        "evidence": {
            "injection_imports": inj_imports,
            "injection_strings": inj_strings,
            "class_stack_attach": class_attach,
            "class_device_targets": class_targets,
            "creates_user_device": creates_device,
            "symlinks": symlinks[:12],
            "device_names": device_names[:8],
            "vhf_imports": vhf,
            "hid_minidriver": hid_minidriver,
            "class_guids": guid_hits,
        },
    }


# ------------------------------------------------------------------ loldrivers


def _load_lol() -> dict:
    global _LOL
    if _LOL is None:
        p = _REFS / "loldrivers_index.json"
        try:
            _LOL = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _LOL = {"drivers": {}, "by_sha256": {}, "by_imphash": {}}
    return _LOL


def loldrivers_match(sha256: str, imphash: str | None) -> dict:
    lol = _load_lol()
    did = lol["by_sha256"].get(sha256.lower())
    match = "sha256" if did else None
    if not did and imphash:
        ids = lol["by_imphash"].get(imphash.lower())
        if ids:
            did, match = ids[0], "imphash"
    if not did:
        return {"known": False}
    meta = lol["drivers"].get(did, {})
    return {"known": True, "match": match, "id": did,
            "category": meta.get("category"), "tags": meta.get("tags") or []}


# ----------------------------------------------------------------- analysis


_VI_FIELDS = ("CompanyName", "ProductName", "FileDescription",
              "OriginalFilename", "FileVersion")


def analyze_binary(path: Path, *, min_str: int = 5) -> dict:
    """Lean, triage-focused analysis line for a stored binary (sha256 = filename).

    Deliberately omits the raw import table, string dumps, section maps and other
    bulk that belongs in a disassembler — the index only carries identity, the
    capability buckets, and the three-axis HID verdict used to pick what to open."""
    data = path.read_bytes()
    entry: dict = {
        "sha256": path.stem,
        "kind": "analysis",
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "entropy": _entropy(data),
    }

    # Strings feed the signals (callbacks resolved by name, device/symlink paths,
    # GUIDs) but are never stored raw.
    strs = extract_strings(data, min_str)
    strs_low = [s.lower() for s in strs]
    guids = {g.lower() for s in strs for g in _GUID_RE.findall(s)}
    symlinks = sorted({s.strip() for s in strs
                       if "\\dosdevices\\" in s.lower() or "\\??\\" in s.lower()})
    device_names = sorted({s.strip() for s in strs if "\\device\\" in s.lower()})

    pe = PE(data)
    imphash = None
    imports_flat: set[str] = set()
    imported_dlls: set[str] = set()
    if pe.ok:
        try:
            imports = pe.imports()
            imported_dlls = {d.lower() for d in imports}
            imports_flat = {f.lower() for fns in imports.values() for f in fns}
            imphash = pe.imphash()
            caps = {cat: sorted(imports_flat & names)
                    for cat, names in _CAPABILITIES.items()
                    if imports_flat & names}
            hdr = pe.header()
            sig = pe.signature()
            dbg = pe.debug() or {}
            vi = (pe.resources().get("version_info") or {})
            entry["pe"] = {
                "arch": hdr["arch"],
                "is_driver": hdr["is_driver"],
                "native": hdr["native"],
                "signed": bool(sig.get("embedded")),
                "signers": sig.get("cert_common_names") or [],
                "wx": any(s.get("wx") for s in pe.sections_info()),
                "exports": len(pe.exports()),
                "imphash": imphash,
                "pdb": dbg.get("pdb"),
                "capabilities": caps,
                "info": {k.lower(): vi[k] for k in _VI_FIELDS if vi.get(k)},
            }
        except Exception as exc:  # never let one sub-parser sink the line
            entry["pe"] = {"parse_error": f"{type(exc).__name__}: {exc}"}
    else:
        entry["pe"] = None

    entry["hid_input"] = hid_input_signals(
        imports_flat, imported_dlls, strs_low, guids, symlinks, device_names)
    entry["loldrivers"] = loldrivers_match(path.stem, imphash)
    return entry


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
        if (r.get("kind") == "analysis" or "strings" in r) and r.get("sha256"):
            done.add(r["sha256"])
    return done


def _is_provenance(line: str) -> bool:
    try:
        r = json.loads(line)
    except ValueError:
        return False
    return r.get("kind") != "analysis" and "strings" not in r and "provenance" in r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pipeline.index",
        description="Backfill analysis lines in drivers/index.jsonl for stored binaries.")
    ap.add_argument("--min-str", type=int, default=5, help="minimum string length (default 5)")
    ap.add_argument("--rebuild", action="store_true",
                    help="drop existing analysis lines and re-emit them "
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
    for p in sys_files:
        if p.stem in done:
            continue
        try:
            entry = analyze_binary(p, min_str=args.min_str)
        except OSError:
            continue
        C.append_index(drivers_dir, entry)
        added += 1
        if added % 100 == 0:
            print(f"  analysed {added} new", file=sys.stderr)
    print(f"{ledger}: {len(sys_files)} binaries in store, {added} analysis line(s) appended")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
