# -*- coding: utf-8 -*-
# DriverTriage.py - Ghidra headless post-script (Jython / GhidraScript API).
#
# Runs after auto-analysis under `analyzeHeadless ... -postScript DriverTriage.py
# <out.json>`. It answers the two questions byte-parsing cannot, by actually
# following code:
#
#   (b) mouse-movement injection - is there a reachable call that drives the
#       mouse class service callback (MouseClassServiceCallback / the
#       IOCTL_INTERNAL_MOUSE_CONNECT hook), i.e. synthetic input bypassing HID?
#
#   (c) user-reachable symlink - is the device + symbolic link created from
#       DriverEntry (available right after `sc start`, no PnP/hardware), and is
#       its security descriptor openable by a non-admin process?
#
# Script args: <out_json> [<report_dir> <name_base>]. It always writes ONE JSON
# object (machine-readable verdicts) to <out_json>. When a report dir + name base
# are given it also writes the human artifacts the analyst actually wants:
#
#   <report_dir>/summary.md       verdicts + (b)/(c) evidence + resolved WDF calls
#                                 + symlink callers (the index, no code dump)
#   <report_dir>/<name_base>.c    FULL pseudo-C: every function, each tagged
#                                 [REACHED]/[UNREACHED] by the DriverEntry walker
#                                 (UNREACHED + a primitive = walker blind spot)
#
# (the runner drops <name_base>.sys and disasm.txt - raw objdump assembly - next
# to them). The JSON carries the same verdicts plus the symlink-referencing
# functions and their callers.
#
# This is static reachability, not execution - strong evidence, not proof; final
# (c) confirmation is a dynamic load in an isolated VM. WDF index->name mapping
# is version-sensitive (see _WDF_FUNCTIONS); unknown indices are reported raw.
#
# @category DriverTriage
import json
import re
import sys

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

MONITOR = ConsoleTaskMonitor()
MAX_DEPTH = 6          # callee depth from DriverEntry to decompile
MAX_FUNCS = 160        # cap decompiled functions (headless time budget)

# --- (b) signals: two mechanisms for injecting synthetic HID input -----------
# (1) hooking the mouse/keyboard class service callback (resolved from the class
#     driver object at runtime), and
# (2) a virtual-HID device fed synthetic reports from user mode over IOCTL
#     (vhidmini/VHF-style) - no class-callback hook, but the same end: input
#     that did not come from real hardware.
_MOUSE_STRINGS = [
    "\\driver\\mouclass", "\\device\\pointerclass", "\\driver\\kbdclass",
    "mouclass", "kbdclass", "mouseclassservicecallback",
    "mouclassservicecallback", "keyboardclassservicecallback",
    "mouse_input_data", "keyboard_input_data",
]
_CONNECT_APIS = [
    "ObReferenceObjectByName", "IoGetDeviceObjectPointer",
    "ObReferenceObjectByPointer",
]
# IOCTL_INTERNAL_MOUSE_CONNECT (0x0f0203) / KEYBOARD_CONNECT (0x0b0203)
# CTL_CODE(FILE_DEVICE_MOUSE=0xf, 0x80, METHOD_NEITHER=3, FILE_ANY_ACCESS=0)
# = (0xf<<16)|(0x80<<2)|3 = 0x0f0203. (An earlier 0x0f0023 transposed the last
# two nibbles, so mouse-filter drivers that snoop the connect IOCTL never hit.)
_CONNECT_IOCTLS = [0x0f0203, 0x0b0203]
# virtual-HID injection tells: strings a driver that takes input reports from
# user mode and replays them as HID input tends to carry.
_VHID_STRINGS = [
    "notify_inputdata", "notify_keystate", "inject", "reportdescriptor",
    "myreportdescriptor", "vhf", "virtualhid", "vhidmini", "intercept_key",
    "hidinject", "input_data", "set_table",
]
# send-to-class injection tells: a driver that pushes synthetic scancodes / mouse
# packets straight into kbdclass/mouclass carries these. Same end as the
# connect-hook (input that never came from real hardware), but it may capture the
# class service callback by a path _CONNECT_APIS does not enumerate - e.g. a
# device-stack filter snooping the connect IRP - so this evidence must stand on
# its own or the path is a (b) false-negative. Seen live in ALPS Apkbfiltr:
#   "kbd : ioctl_sendkbddatatokbdclass enter."
#   "to kbdclass id(%d) make(0x%08x) flag(0x%08x) extrainfo(0x%08x)."
_SENDTOCLASS_STRINGS = [
    "sendkbddatatokbdclass", "sendmousedatatomouclass",
    "sendkbddata", "sendmousedata",
    "to kbdclass", "to mouclass",
]

# --- the real (c) signal: symbolic link + control device --------------------
_SYMLINK_APIS_WDM = ["IoCreateSymbolicLink", "IoCreateDevice",
                     "IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure"]
_PNP_GATES = ["AddDevice", "EvtDriverDeviceAdd", "EvtDevicePrepareHardware",
              "IoAttachDeviceToDeviceStack"]
# A driver that owns a PnP function device needs its devnode ENUMERATED before
# the function (and often the whole driver load) happens - so its interface is
# not exposed by a bare `sc start`. Under CFG-guarded KMDF the EvtDeviceAdd APIs
# do not resolve by name, but two byte-visible signals do: a hardware-ID string
# (the driver is bound to a devnode), and the framework's own debug strings.
_HWID_PREFIXES = ("root\\", "hid\\", "pci\\", "usb\\", "acpi\\", "hdaudio\\",
                  "swd\\", "umb\\")
_PNP_MARKERS = ("evtdeviceadd", "evtdriverdeviceadd", "evtdeviceprepare",
                "evtdeviced0", "prepare hardware", "add called")

# WDF function-table indices (WDFFUNCENUM) for the calls that matter. These are
# stable across recent KMDF versions (1.9-1.33) for the functions we read; if a
# driver binds an older/newer table an unknown index is still reported with its
# number so a human can map it. Extend as needed.
_WDF_FUNCTIONS = {
    12: "WdfDeviceCreate",
    15: "WdfDeviceCreateSymbolicLink",
    16: "WdfDeviceInitAssignSDDLString",
    17: "WdfDeviceInitSetDeviceType",
    27: "WdfControlDeviceInitAllocate",
    28: "WdfControlFinishInitializing",
    88: "WdfIoQueueCreate",
}


def _decompiler(program):
    dec = DecompInterface()
    dec.openProgram(program)
    return dec


def _entry_function(program):
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    for name in ("DriverEntry", "GsDriverEntry", "FxDriverEntry"):
        syms = st.getSymbols(name)
        for s in syms:
            f = fm.getFunctionAt(s.getAddress())
            if f is not None:
                return f
    # the PE entry point: Ghidra flags it as an external entry point and names
    # the function `entry`. This is the function other code's callers resolve to.
    for addr in st.getExternalEntryPointIterator():
        f = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if f is not None:
            return f
    # last resort: the first function the analyzer found at the entry
    it = fm.getFunctions(True)
    return it.next() if it.hasNext() else None


def _reachable(start, max_depth, max_funcs):
    """Functions reachable from `start` by direct calls, up to max_depth."""
    seen = {}
    frontier = [(start, 0)]
    while frontier and len(seen) < max_funcs:
        fn, d = frontier.pop()
        if fn is None or fn.getEntryPoint() in seen:
            continue
        seen[fn.getEntryPoint()] = fn
        if d >= max_depth:
            continue
        for callee in fn.getCalledFunctions(MONITOR):
            frontier.append((callee, d + 1))
    return list(seen.values())


def _all_functions(program, cap=2000):
    """Every real (non-external, non-thunk) function, in address order.

    Used for the FULL pseudo-C dump (walker evaluation): decompiling the whole
    program - not just the DriverEntry-reachable set - lets a human (or a grep)
    spot functions the walker never reached that still reference a symlink /
    connect / class-callback primitive. Those are the walker's blind spots.
    """
    fm = program.getFunctionManager()
    out = []
    it = fm.getFunctions(True)
    while it.hasNext() and len(out) < cap:
        f = it.next()
        if f.isExternal() or f.isThunk():
            continue
        out.append(f)
    return out


def _registered_callbacks(program, roots, max_funcs=64):
    """Functions whose address is *taken* inside `roots` (callback registration).

    KMDF stores EvtIoDeviceControl / EvtDriverDeviceAdd / EvtDeviceFileCreate as
    function pointers in config structs; they are never `call`ed from DriverEntry,
    so a callee walk misses them and the real injection/IOCTL logic goes
    unanalysed. A code reference to a function's entry that is NOT a call is an
    address-taken pointer - almost always a callback being registered.
    """
    fm = program.getFunctionManager()
    refmgr = program.getReferenceManager()
    root_addrs = set(r.getEntryPoint() for r in roots)
    out = {}
    for r in roots:
        body = r.getBody()
        ait = body.getAddresses(True)
        while ait.hasNext() and len(out) < max_funcs:
            a = ait.next()
            for ref in refmgr.getReferencesFrom(a):
                if ref.getReferenceType().isCall():
                    continue
                tgt = ref.getToAddress()
                f = fm.getFunctionAt(tgt)
                if f is not None and f.getEntryPoint() not in root_addrs:
                    out[f.getEntryPoint()] = f
    return list(out.values())


def _decompile(dec, fn):
    try:
        res = dec.decompileFunction(fn, 60, MONITOR)
        if res and res.decompileCompleted():
            return res.getDecompiledFunction().getC()
    except Exception:
        pass
    return ""


def _defined_strings(program):
    """Map lower-cased defined string -> list of addresses (as ints)."""
    out = {}
    listing = program.getListing()
    data = listing.getDefinedData(True)
    while data.hasNext():
        d = data.next()
        try:
            if d.hasStringValue():
                v = str(d.getValue())
                out.setdefault(v.lower(), []).append(d.getAddress())
        except Exception:
            continue
    return out


def _funcs_referencing(program, addr):
    """Functions that reference a given data address."""
    fm = program.getFunctionManager()
    refmgr = program.getReferenceManager()
    fns = set()
    for ref in refmgr.getReferencesTo(addr):
        f = fm.getFunctionContaining(ref.getFromAddress())
        if f is not None:
            fns.add(f)
    return fns


def _callers(fn):
    return list(fn.getCallingFunctions(MONITOR))


def _symbol_names_in(program):
    names = set()
    st = program.getSymbolTable()
    it = st.getAllSymbols(False)
    while it.hasNext():
        names.add(it.next().getName())
    return names


def _scan_wdf_calls(decomp_by_name):
    """Best-effort WDF function-table resolution from decompiled text.

    KMDF calls appear as an indirect call through WdfFunctions[idx]; the
    decompiler usually renders the index as a constant. We pick those constants
    out of the pseudo-C and map them to names via _WDF_FUNCTIONS. Crude but it
    recovers the calls that are invisible as imports.
    """
    import re
    idx_re = re.compile(r"WdfFunctions.{0,8}?\[?0x([0-9a-fA-F]+)\]?")
    found = {}
    for name, c in decomp_by_name.items():
        for m in idx_re.finditer(c or ""):
            idx = int(m.group(1), 16)
            label = _WDF_FUNCTIONS.get(idx, "WdfFunc_#%d" % idx)
            found.setdefault(label, []).append(name)
    return found


def _reaches(target, root, limit=4000):
    """True if `target` is `root`, or `root` transitively calls `target`.

    Walks callers upward from `target`; robust to thunk/pointer calls that a
    downward getCalledFunctions walk from `root` can miss.
    """
    root_addr = root.getEntryPoint()
    seen = set()
    stack = [target]
    while stack and len(seen) < limit:
        fn = stack.pop()
        a = fn.getEntryPoint()
        if a in seen:
            continue
        seen.add(a)
        if a == root_addr:
            return True
        for c in fn.getCallingFunctions(MONITOR):
            stack.append(c)
    return False


def _contains_any(text, needles):
    low = text.lower()
    return [n for n in needles if n.lower() in low]


def _load_static(path):
    """Load the static `device` dict (from index.py) used as a fallback.

    The byte-level analyzer catches evidence Ghidra's auto-analysis can miss on
    CFG-guarded KMDF - notably the SDDL descriptor and the declared symlink
    paths, which are raw .rdata constants Ghidra never types as strings.
    """
    try:
        f = open(path)
        try:
            return json.load(f) or {}
        finally:
            f.close()
    except Exception:
        return {}


# ---- dynamic-probe pre-fill: facts the VM template needs (not verdicts) ------
# The walker is the scrivener: beyond the pseudo-C it extracts the structured
# facts the AI pastes into the dynamic_probe.ps1 template - the candidate IOCTL
# codes from the dispatch and the HID report descriptor (payload shapes). These
# are HINTS for the VM step, never a static verdict (the VM is the judge).

def _extract_ioctls(full_c):
    """Candidate IOCTL codes from the decompiled dispatch: integer literals the
    control code is compared against (`== 0x...` / `case 0x...:`). Decoded as a
    CTL_CODE. High-recall hint for the probe template, NOT a verdict.

    `internal_only`: FILE_DEVICE_MOUSE/KEYBOARD + METHOD_NEITHER + FILE_ANY_ACCESS
    is the shape of IOCTL_INTERNAL_MOUSE/KEYBOARD_* - delivered via
    IRP_MJ_INTERNAL_DEVICE_CONTROL from mouclass/kbdclass (kernel->kernel) and
    unreachable from user-mode CreateFile+DeviceIoControl (which emits
    IRP_MJ_DEVICE_CONTROL). Proven on 02f02ef3 ETD: every one returned err=1 in
    the VM sweep. The probe should SKIP these; they must not count as (b) hints.
    """
    cands = {}
    # dispatch compares the control code with ==, != (default-branch guards) or case
    for m in re.finditer(r'(?:==|!=|case)\s*(0x[0-9a-fA-F]+)', full_c or ""):
        v = int(m.group(1), 16)
        if v < 0x10000 or v >= 0xffffffff:  # need a device-type high word; drop 64-bit addrs + ~0 sentinel
            continue
        if (v & 0xffff) == 0:               # round masks (0x40000000, 0x10000) are not IOCTLs
            continue
        dev = (v >> 16) & 0xffff
        method = v & 3
        access = (v >> 14) & 3
        internal_only = (dev in (0x0B, 0x0F) and method == 3 and access == 0)
        cands[v] = {
            "code": "0x%x" % v, "device_type": "0x%x" % dev,
            "function": "0x%x" % ((v >> 2) & 0xfff), "method": method,
            "access": access, "internal_only": internal_only,
        }
    return [cands[k] for k in sorted(cands)][:32]


_HID_USAGE = {
    (0x01, 0x01): "Pointer", (0x01, 0x02): "Mouse", (0x01, 0x06): "Keyboard",
    (0x01, 0x80): "System Control", (0x0c, 0x01): "Consumer Control",
}


def _parse_hid_descriptor(b):
    """Minimal HID report-descriptor parse -> per-ReportID payload sizes + label,
    so the probe can build exact inject buffers. Returns a list or None."""
    try:
        n = len(b)
        i = 0
        upage = None
        app_label = None
        rid = 0
        rsize = 0
        rcount = 0
        reps = {}
        while i < n:
            h = b[i]
            if h == 0xfe:                      # long item: skip
                i += 3 + (b[i + 1] if i + 1 < n else 0)
                continue
            size = h & 0x03
            if size == 3:
                size = 4
            tag = h & 0xfc
            data = 0
            for k in range(size):
                if i + 1 + k < n:
                    data |= b[i + 1 + k] << (8 * k)
            if tag == 0x04:                    # Usage Page (global)
                upage = data
            elif tag == 0x08:                  # Usage (local)
                if app_label is None:
                    app_label = _HID_USAGE.get((upage, data))
            elif tag == 0xc0:                  # End Collection -> next top-level
                app_label = None
            elif tag == 0x84:                  # Report ID
                rid = data
                reps.setdefault(rid, {"in": 0, "out": 0, "label": None})
            elif tag == 0x74:                  # Report Size
                rsize = data
            elif tag == 0x94:                  # Report Count
                rcount = data
            elif tag == 0x80:                  # Input (main)
                r = reps.setdefault(rid, {"in": 0, "out": 0, "label": None})
                r["in"] += rsize * rcount
                if r["label"] is None:
                    r["label"] = app_label
            elif tag == 0x90:                  # Output (main)
                r = reps.setdefault(rid, {"in": 0, "out": 0, "label": None})
                r["out"] += rsize * rcount
                if r["label"] is None:
                    r["label"] = app_label
            i += 1 + size
        out = []
        for k in sorted(reps):
            r = reps[k]
            out.append({"report_id": k, "label": r["label"],
                        "input_bytes": (r["in"] + 7) // 8,
                        "output_bytes": (r["out"] + 7) // 8})
        return out or None
    except Exception:
        return None


def _extract_report_descriptor(program):
    """Find + parse the HID report descriptor in the raw image. Reads the
    imported file (program.getExecutablePath()); the descriptor is a verbatim
    .rdata constant. Returns {offset,length,reports,hex} or None."""
    try:
        path = program.getExecutablePath()
        if not path:
            return None
        if path.startswith("/") and len(path) > 2 and path[2] == ":":
            path = path[1:]                    # Ghidra may prefix "/C:/..."
        f = open(path, "rb")
        try:
            data = bytearray(f.read())
        finally:
            f.close()
    except Exception:
        return None
    anchors = (b"\x05\x01\x09\x02\xa1\x01", b"\x05\x01\x09\x06\xa1\x01",
               b"\x05\x01\x09\x01\xa1\x01", b"\x05\x0c\x09\x01\xa1\x01")
    best = None
    for a in anchors:
        off = data.find(a)
        if off >= 0 and (best is None or off < best):
            best = off
    if best is None:
        return None
    i = best
    depth = 0
    end = best
    n = len(data)
    while i < n and i < best + 1024:
        h = data[i]
        size = h & 0x03
        if size == 3:
            size = 4
        tag = h & 0xfc
        if tag == 0xa0:
            depth += 1
        if tag == 0xc0:
            depth -= 1
        i += 1 + size
        if depth <= 0 and tag == 0xc0:
            end = i
            if i >= n or data[i] not in (0x05, 0x06):  # another top-level collection follows?
                break
    blob = bytearray(data[best:end])   # bytearray iterates as ints under Py2 (Jython) AND Py3; bytes() is str under Py2 -> "%02x" % char crash
    return {"offset": "0x%x" % best, "length": len(blob),
            "reports": _parse_hid_descriptor(blob),
            "hex": " ".join("%02x" % x for x in blob)[:1200]}


def main():
    args = getScriptArgs()
    out_path = args[0] if args else "driver_triage.json"
    report_dir = args[1] if len(args) > 1 else None
    name_base = args[2] if len(args) > 2 else "driver"
    static = _load_static(args[3]) if len(args) > 3 else {}
    program = getCurrentProgram()
    result = {
        "program": program.getName(),
        "ok": False,
    }
    decomp = {}
    decomp_all = []
    entry_c = ""
    try:
        dec = _decompiler(program)
        entry = _entry_function(program)
        if entry is None:
            result["error"] = "no DriverEntry / entry function found"
            _write_json(out_path, result)
            return
        result["driver_entry"] = str(entry.getEntryPoint())

        reach = _reachable(entry, MAX_DEPTH, MAX_FUNCS)
        # Seed in the WDF-registered callbacks (EvtIoDeviceControl, EvtDeviceAdd,
        # EvtDeviceFileCreate...). They are stored as pointers, never called from
        # DriverEntry, so the callee walk misses them - and that is exactly where
        # the IOCTL / injection logic lives.
        callbacks = _registered_callbacks(program, reach)
        for fn in callbacks:
            if fn not in reach:
                reach.append(fn)
        for fn in reach:
            decomp[fn.getName()] = _decompile(dec, fn)
        entry_c = decomp.get(entry.getName(), _decompile(dec, entry))

        # FULL pseudo-C for walker evaluation: decompile EVERY function and record
        # whether the DriverEntry walker reached it. Reuse the reachable-set decomp
        # we already have; decompile the rest once. decomp_all drives <name>.c.
        reachable_addrs = set(f.getEntryPoint() for f in reach)
        decomp_all = []  # (name, addr_str, reachable_bool, c_text)
        for fn in _all_functions(program):
            nm = fn.getName()
            c = decomp.get(nm) or _decompile(dec, fn)
            decomp_all.append((nm, str(fn.getEntryPoint()),
                               fn.getEntryPoint() in reachable_addrs, c))

        symbols = _symbol_names_in(program)
        strings = _defined_strings(program)
        wdf_calls = _scan_wdf_calls(decomp)
        all_c = "\n".join(v for v in decomp.values() if v)
        # (b) is scored over EVERY function, not just the DriverEntry-reachable
        # set: injection logic that lives in a function the walker never reached
        # (the same blind-spot class as (c)) would otherwise be a (b) false
        # negative. (c) reachability deliberately keeps using all_c (reachable).
        full_c = "\n".join(c for (_n, _a, _r, c) in decomp_all if c) or all_c
        is_kmdf = ("WdfVersionBind" in symbols
                   or bool(static.get("framework") in ("kmdf", "both")))

        # ---- (c) symbolic link reachability -----------------------------------
        sym_addrs = []
        sym_strings = []
        for s, addrs in strings.items():
            if "\\dosdevices\\" in s or s.startswith("\\??\\"):
                sym_strings.append(s)
                sym_addrs.extend(addrs)
        sym_funcs = set()
        for a in sym_addrs:
            sym_funcs |= _funcs_referencing(program, a)
        sym_func_names = sorted(f.getName() for f in sym_funcs)

        # reachable from DriverEntry? walk UP (callers) from each symlink fn.
        symlink_in_entry_path = any(_reaches(f, entry) for f in sym_funcs)

        # PnP function device? hardware-ID strings + framework PnP markers are
        # byte-visible even when the EvtDeviceAdd APIs do not resolve under CFG.
        hardware_ids = sorted(set(
            s for s in strings if s.startswith(_HWID_PREFIXES)))
        pnp_markers = sorted(set(
            m for m in _PNP_MARKERS
            if m in all_c.lower() or any(m in s for s in strings)))
        requires_pnp = bool(hardware_ids or pnp_markers)
        pnp_gated = bool(_contains_any(all_c, _PNP_GATES)
                         or (symbols & set(_PNP_GATES))
                         or requires_pnp)

        # creates a symlink: WDM import, resolved WDF call, OR - the robust,
        # framework-agnostic signal that survives CFG-guarded WDF dispatch - a
        # reachable function references a \DosDevices\ / \?? symlink NAME string.
        wdf_symlink = ("WdfDeviceCreateSymbolicLink" in wdf_calls
                       or "WdfDeviceCreateSymbolicLink" in symbols)
        creates_symlink = bool(
            (symbols & set(_SYMLINK_APIS_WDM)) or wdf_symlink
            or symlink_in_entry_path
            or (bool(sym_funcs) and (is_kmdf or bool(static.get("declares_symlink")))))

        # control device: resolved WdfControlDeviceInitAllocate, or inferred -
        # a KMDF driver that creates a symlink from DriverEntry and is NOT behind
        # a PnP gate is a control device (available at `sc start`, no hardware).
        control_resolved = ("WdfControlDeviceInitAllocate" in wdf_calls
                            or "WdfControlDeviceInitAllocate" in symbols)
        control_inferred = bool(is_kmdf and symlink_in_entry_path and not pnp_gated)
        is_control_device = bool(control_resolved or control_inferred)

        # SDDL: Ghidra-defined strings, else the static byte-scan from index.py
        # (the descriptor is often a raw .rdata constant Ghidra never typed).
        sddl = sorted(s for s in strings if s.startswith("d:") and "(a;" in s)
        sddl = [s.upper() for s in sddl]
        sddl_src = "ghidra"
        if not sddl and static.get("sddl"):
            sddl = list(static.get("sddl"))
            sddl_src = "static"
        sddl_grants_user = any(x in s.upper() for s in sddl
                               for x in (";;;WD)", ";;;AU)", ";;;IU)", ";;;BU)")) \
            or bool(static.get("sddl_grants_user"))

        result["symlink"] = {
            "creates_symlink": creates_symlink,
            "symlink_strings": sorted(set(sym_strings)
                                      or static.get("symlink_paths") or [])[:20],
            "created_by": sym_func_names[:20],
            "reachable_from_driver_entry": symlink_in_entry_path,
            "pnp_gated": pnp_gated,
            "requires_pnp_enumeration": requires_pnp,
            "hardware_ids": hardware_ids[:10],
            "pnp_markers": pnp_markers[:10],
            "is_control_device": is_control_device,
            "control_inferred": control_inferred and not control_resolved,
            "sddl": sddl[:10],
            "sddl_source": sddl_src,
            "sddl_grants_user": sddl_grants_user,
        }
        # verdict: created from DriverEntry (not PnP), reachable, user-openable.
        result["symlink_user_reachable"] = bool(
            creates_symlink and symlink_in_entry_path
            and (is_control_device or not pnp_gated)
            and sddl_grants_user)

        # ---- (b) input injection ---------------------------------------------
        # Empirical result (02f02ef3 ETD, c8819dbd vhidev, 3x Razer rz*endpt): a
        # driver that hooks the mouse/kbd class service callback (CONNECT_DATA
        # swap at IRP_MJ_INTERNAL_DEVICE_CONTROL + stored class cb invoked from
        # hw-input path) is a class FILTER, not a user-mode injector. The connect
        # IOCTLs 0xf0203/0xb0203 are kernel-only (mouclass/kbdclass -> filter);
        # user CreateFile+DeviceIoControl emits IRP_MJ_DEVICE_CONTROL and never
        # reaches that handler. So class-hook stays as a filter *signature* and
        # does NOT drive the (b) verdict.
        mouse_str = sorted(set(_contains_any(full_c, _MOUSE_STRINGS))
                           | set(s for s in strings if _contains_any(s, _MOUSE_STRINGS)))
        connect_apis = [a for a in _CONNECT_APIS if a in symbols]
        ioctl_hits = [hex(i) for i in _CONNECT_IOCTLS if ("%x" % i) in full_c.lower()]
        indirect_call = "(**" in full_c or "(*(code *)" in full_c
        filter_hook = bool(mouse_str and (connect_apis or ioctl_hits) and indirect_call)
        # (b) mechanism 1: push synthetic scancodes / mouse packets straight into
        # kbdclass/mouclass. Captures the class service callback by a path
        # _CONNECT_APIS does not enumerate (e.g. a device-stack filter snooping
        # the connect IRP), so send-to-class strings + an indirect call stand on
        # their own - without this the path is a (b) false-negative (Apkbfiltr).
        sendclass_str = sorted(set(s for s in strings if _contains_any(s, _SENDTOCLASS_STRINGS))
                               | set(_contains_any(full_c, _SENDTOCLASS_STRINGS)))
        class_send = bool(sendclass_str and indirect_call)
        # (b) mechanism 2: virtual-HID device fed synthetic reports over IOCTL
        vhid_str = sorted(set(s for s in strings if _contains_any(s, _VHID_STRINGS)))
        vhid_inject = bool(vhid_str and creates_symlink)
        inject = bool(class_send or vhid_inject)
        result["mouse_injection"] = {
            "verdict": inject,
            "mechanism": ("class_send_ioctl" if class_send
                          else "virtual_hid_ioctl" if vhid_inject else None),
            "filter_hook": filter_hook,
            "class_strings": mouse_str[:10],
            "connect_apis": connect_apis,
            "connect_ioctls": ioctl_hits,
            "sendclass_strings": sendclass_str[:10],
            "indirect_call_present": indirect_call,
            "vhid_strings": vhid_str[:10],
        }
        result["callbacks_analysed"] = sorted(f.getName() for f in callbacks)[:20]

        # ---- dynamic-probe pre-fill (hints for dynamic_probe.ps1, not verdicts)
        result["ioctls"] = _extract_ioctls(full_c)
        result["report_descriptor"] = _extract_report_descriptor(program)

        # ---- raw evidence the analyst wants -----------------------------------
        result["wdf_calls"] = {k: sorted(set(v))[:12] for k, v in wdf_calls.items()}
        result["pseudo_c"] = {
            "DriverEntry": entry_c,
            # symlink-referencing functions + a bounded slice of callees
            "symlink_funcs": {f.getName(): decomp.get(f.getName(), _decompile(dec, f))
                              for f in list(sym_funcs)[:4]},
        }
        result["callers_of_symlink_fn"] = {
            f.getName(): sorted(c.getName() for c in _callers(f))[:12]
            for f in list(sym_funcs)[:4]
        }
        result["functions_decompiled"] = len(decomp)
        result["functions_total"] = len(decomp_all)
        result["functions_unreached"] = sum(1 for _, _, r, _ in decomp_all if not r)
        result["ok"] = True
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)

    _write_json(out_path, result)
    if report_dir:
        try:
            _write_report(report_dir, name_base, result, entry_c, decomp_all)
        except Exception as exc:
            print("DriverTriage: report write failed: %s" % exc)


def _write_json(path, obj):
    f = open(path, "w")
    try:
        f.write(json.dumps(obj))
    finally:
        f.close()
    print("DriverTriage: wrote " + path)


def _write_text(path, text):
    """Write unicode/str as UTF-8 bytes. Ghidra runs Jython 2.7, where a
    text-mode open().write() of a unicode string carrying non-ASCII (common in
    decompiled driver strings - e.g. ALPS/Synaptics) raises UnicodeEncodeError
    and leaves a 0-byte file with nothing after it. Encoding to UTF-8 and writing
    in binary mode avoids that on both Jython 2 and Python 3."""
    try:
        data = text.encode("utf-8", "replace")
    except Exception:
        data = text
    f = open(path, "wb")
    try:
        f.write(data)
    finally:
        f.close()


def _write_report(report_dir, name_base, result, entry_c, decomp_all):
    """Human artifacts, two files:

      <name_base>.c   FULL pseudo-C - every function, each tagged [REACHED] or
                      [UNREACHED] by the DriverEntry walker. UNREACHED functions
                      that still touch a symlink/connect/class primitive are the
                      walker's blind spots (the point of dumping everything).
      summary.md      verdicts + (b)/(c) evidence + WDF calls + symlink callers.

    The raw assembly (disasm.txt) is emitted separately by the runner (objdump);
    it is the confirmation-bias cross-check against this pseudo-C.
    """
    import os
    try:
        os.makedirs(report_dir)
    except OSError:
        pass
    # independent so a failure in one still writes the other
    try:
        _write_full_c(report_dir, name_base, result, decomp_all)
    except Exception as exc:
        print("DriverTriage: full-C write failed: %s" % exc)
    try:
        _write_summary_md(report_dir, name_base, result)
    except Exception as exc:
        print("DriverTriage: summary write failed: %s" % exc)
    print("DriverTriage: wrote report to " + report_dir)


def _write_full_c(report_dir, name_base, result, decomp_all):
    import os
    total = result.get("functions_total") or 0
    unreached_n = result.get("functions_unreached") or 0
    unreached = [n for (n, a, r, c) in decomp_all if not r]
    out = []
    out.append("// FULL pseudo-C for %s" % result.get("program", name_base))
    out.append("// DriverEntry: %s" % result.get("driver_entry"))
    out.append("// functions: %d total, %d reached by walker, %d UNREACHED"
               % (total, total - unreached_n, unreached_n))
    out.append("//")
    out.append("// [REACHED]   on the DriverEntry call graph the (b)/(c) walker followed")
    out.append("// [UNREACHED] walker blind spot - if one of these references a symlink /")
    out.append("//             connect-IOCTL / class-callback primitive, the verdict missed it")
    if unreached:
        out.append("//")
        out.append("// UNREACHED (%d): %s" % (len(unreached), ", ".join(unreached[:80])))
    out.append("")
    for (nm, addr, reached, c) in decomp_all:
        tag = "REACHED" if reached else "UNREACHED"
        out.append("\n/* ===== %s  @%s  [%s] ===== */" % (nm, addr, tag))
        out.append(c or "// (decompilation unavailable)")
    _write_text(os.path.join(report_dir, name_base + ".c"), "\n".join(out))


def _write_summary_md(report_dir, name_base, result):
    import os
    mi = result.get("mouse_injection") or {}
    sl = result.get("symlink") or {}
    total = result.get("functions_total") or 0
    unreached_n = result.get("functions_unreached") or 0
    L = []
    L.append("# DriverTriage - %s" % result.get("program", name_base))
    L.append("")
    L.append("- DriverEntry: `%s`" % result.get("driver_entry"))
    L.append("- functions: %d total, %d reached, %d unreached"
             % (total, total - unreached_n, unreached_n))
    L.append("- artifacts: `%s.sys` (binary), `%s.c` (full pseudo-C), "
             "`disasm.txt` (raw asm)" % (name_base, name_base))
    if result.get("error"):
        L.append("")
        L.append("**ERROR:** %s" % result["error"])
    L.append("")
    L.append("## Verdicts")
    L.append("")
    L.append("| verdict | value |")
    L.append("|---|---|")
    L.append("| **(b) input injection** | **%s** |" % mi.get("verdict"))
    L.append("| &nbsp;&nbsp;mechanism | %s |" % mi.get("mechanism"))
    L.append("| **(c) symlink user-reachable** | **%s** |" % result.get("symlink_user_reachable"))
    L.append("")
    L.append("## (b) injection evidence")
    L.append("```")
    L.append("mechanism             : %s" % mi.get("mechanism"))
    L.append("class strings         : %s" % ", ".join(mi.get("class_strings") or []))
    L.append("connect apis          : %s" % ", ".join(mi.get("connect_apis") or []))
    L.append("connect ioctls        : %s" % ", ".join(mi.get("connect_ioctls") or []))
    L.append("sendclass strings     : %s" % ", ".join(mi.get("sendclass_strings") or []))
    L.append("vhid strings          : %s" % ", ".join(mi.get("vhid_strings") or []))
    L.append("indirect call present : %s" % mi.get("indirect_call_present"))
    L.append("filter_hook           : %s   # class-filter signature (NOT inject)"
             % mi.get("filter_hook"))
    L.append("```")
    L.append("")
    L.append("## (c) symlink reachability evidence")
    L.append("```")
    L.append("creates symlink           : %s" % sl.get("creates_symlink"))
    L.append("symlink strings           : %s" % ", ".join(sl.get("symlink_strings") or []))
    L.append("created by                : %s" % ", ".join(sl.get("created_by") or []))
    L.append("reachable from DriverEntry: %s" % sl.get("reachable_from_driver_entry"))
    L.append("pnp gated                 : %s" % sl.get("pnp_gated"))
    L.append("requires pnp enumeration  : %s" % sl.get("requires_pnp_enumeration"))
    L.append("hardware ids              : %s" % ", ".join(sl.get("hardware_ids") or []))
    L.append("pnp markers               : %s" % ", ".join(sl.get("pnp_markers") or []))
    L.append("is control device         : %s%s" % (
        sl.get("is_control_device"), " (inferred)" if sl.get("control_inferred") else ""))
    L.append("sddl [%s]               : %s" % (
        sl.get("sddl_source"), " ".join(sl.get("sddl") or [])))
    L.append("sddl grants user          : %s" % sl.get("sddl_grants_user"))
    L.append("```")

    ioctls = result.get("ioctls") or []
    if ioctls:
        user_io  = [it for it in ioctls if not it.get("internal_only")]
        kern_io  = [it for it in ioctls if     it.get("internal_only")]
        if user_io:
            L.append("")
            L.append("## Candidate IOCTLs (user-reachable) - probe sweep targets")
            L.append("")
            L.append("| code | device_type | function | method | access |")
            L.append("|---|---|---|---|---|")
            for it in user_io:
                L.append("| %s | %s | %s | %d | %d |" % (
                    it.get("code"), it.get("device_type"), it.get("function"),
                    it.get("method"), it.get("access")))
        if kern_io:
            L.append("")
            L.append("## Internal-only IOCTLs (kernel->kernel; probe will NOT reach)")
            L.append("")
            L.append("IRP_MJ_INTERNAL_DEVICE_CONTROL codes (mouse/kbd device_type + "
                     "METHOD_NEITHER + FILE_ANY_ACCESS). Sent by mouclass/kbdclass "
                     "to the filter; user CreateFile+DeviceIoControl cannot deliver "
                     "them (proven on 02f02ef3 ETD: err=1 on every one). Shown here "
                     "as filter-signature evidence, excluded from the probe sweep.")
            L.append("")
            L.append("| code | device_type | function | method | access |")
            L.append("|---|---|---|---|---|")
            for it in kern_io:
                L.append("| %s | %s | %s | %d | %d |" % (
                    it.get("code"), it.get("device_type"), it.get("function"),
                    it.get("method"), it.get("access")))

    rd = result.get("report_descriptor")
    if rd:
        L.append("")
        L.append("## HID report descriptor @ %s (%d bytes)"
                 % (rd.get("offset"), rd.get("length") or 0))
        L.append("")
        reps = rd.get("reports") or []
        if reps:
            L.append("| report_id | label | input_bytes | output_bytes |")
            L.append("|---|---|---|---|")
            for r in reps:
                L.append("| %s | %s | %s | %s |" % (
                    r.get("report_id"), r.get("label"),
                    r.get("input_bytes"), r.get("output_bytes")))
            L.append("")
        L.append("```")
        L.append(rd.get("hex") or "")
        L.append("```")

    cb = result.get("callbacks_analysed") or []
    if cb:
        L.append("")
        L.append("## WDF callbacks analysed")
        L.append("")
        L.append(", ".join("`%s`" % c for c in cb))

    wdf = result.get("wdf_calls") or {}
    if wdf:
        L.append("")
        L.append("## Resolved WDF function-table calls")
        L.append("")
        for name in sorted(wdf):
            L.append("- `%s` - called in: %s" % (name, ", ".join(wdf[name])))

    callers = result.get("callers_of_symlink_fn") or {}
    if callers:
        L.append("")
        L.append("## Callers of symlink-referencing functions")
        L.append("")
        for fn in sorted(callers):
            L.append("- `%s` <- %s" % (fn, ", ".join(callers[fn]) or "(none / DriverEntry)"))

    _write_text(os.path.join(report_dir, "summary.md"), "\n".join(L) + "\n")


main()
