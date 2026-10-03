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
#   <report_dir>/disassembly.txt            full report: verdicts + evidence +
#                                           pseudo-C of DriverEntry and every
#                                           reachable callee + resolved WDF calls
#   <report_dir>/<name_base>-driver-entry.c pseudo-C of DriverEntry alone
#
# (the runner drops <name_base>.sys next to them). The JSON carries the same
# verdicts plus the symlink-referencing functions and their callers.
#
# This is static reachability, not execution - strong evidence, not proof; final
# (c) confirmation is a dynamic load in an isolated VM. WDF index->name mapping
# is version-sensitive (see _WDF_FUNCTIONS); unknown indices are reported raw.
#
# @category DriverTriage
import json
import sys

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

MONITOR = ConsoleTaskMonitor()
MAX_DEPTH = 6          # callee depth from DriverEntry to decompile
MAX_FUNCS = 160        # cap decompiled functions (headless time budget)

# --- the real (b) signal: how a driver injects mouse movement ----------------
# Symbol/string tells a driver that hooks the mouse class service callback
# leaves behind, resolved from the class driver object at runtime.
_MOUSE_STRINGS = [
    "\\driver\\mouclass", "\\device\\pointerclass", "mouclass",
    "mouseclassservicecallback", "mouclassservicecallback",
]
_CONNECT_APIS = [
    "ObReferenceObjectByName", "IoGetDeviceObjectPointer",
    "ObReferenceObjectByPointer",
]
# IOCTL_INTERNAL_MOUSE_CONNECT (0x0f0023) / KEYBOARD_CONNECT (0x0b0203)
_CONNECT_IOCTLS = [0x0f0023, 0x0b0203]

# --- the real (c) signal: symbolic link + control device --------------------
_SYMLINK_APIS_WDM = ["IoCreateSymbolicLink", "IoCreateDevice",
                     "IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure"]
_PNP_GATES = ["AddDevice", "EvtDriverDeviceAdd", "EvtDevicePrepareHardware",
              "IoAttachDeviceToDeviceStack"]

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


def main():
    args = getScriptArgs()
    out_path = args[0] if args else "driver_triage.json"
    report_dir = args[1] if len(args) > 1 else None
    name_base = args[2] if len(args) > 2 else "driver"
    program = getCurrentProgram()
    result = {
        "program": program.getName(),
        "ok": False,
    }
    decomp = {}
    entry_c = ""
    try:
        dec = _decompiler(program)
        entry = _entry_function(program)
        if entry is None:
            result["error"] = "no DriverEntry / entry function found"
            _write(out_path, result)
            return
        result["driver_entry"] = str(entry.getEntryPoint())

        reach = _reachable(entry, MAX_DEPTH, MAX_FUNCS)
        for fn in reach:
            decomp[fn.getName()] = _decompile(dec, fn)
        entry_c = decomp.get(entry.getName(), _decompile(dec, entry))

        symbols = _symbol_names_in(program)
        strings = _defined_strings(program)
        wdf_calls = _scan_wdf_calls(decomp)
        all_c = "\n".join(v for v in decomp.values() if v)

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

        # is the symlink-creating function reachable from DriverEntry? Walk UP
        # the call graph (callers) from each symlink fn to the entry function —
        # more robust than a downward callee walk, which misses calls Ghidra
        # renders through a thunk or pointer.
        symlink_in_entry_path = any(_reaches(f, entry) for f in sym_funcs)

        # does the creation sit behind a PnP gate instead?
        pnp_gated = bool(_contains_any(all_c, _PNP_GATES)
                         or (symbols & set(_PNP_GATES)))

        is_control_device = ("WdfControlDeviceInitAllocate" in wdf_calls
                             or "WdfControlDeviceInitAllocate" in symbols)
        creates_symlink = bool(
            (symbols & set(_SYMLINK_APIS_WDM))
            or "WdfDeviceCreateSymbolicLink" in wdf_calls
            or "WdfDeviceCreateSymbolicLink" in symbols)

        # SDDL: literal security descriptors in the image
        sddl = sorted(s for s in strings if s.startswith("d:")
                      and "(a;" in s)
        sddl_grants_user = any(x in s for s in sddl
                               for x in (";;;wd)", ";;;au)", ";;;iu)", ";;;bu)"))

        result["symlink"] = {
            "creates_symlink": creates_symlink,
            "symlink_strings": sorted(set(sym_strings))[:20],
            "created_by": sym_func_names[:20],
            "reachable_from_driver_entry": symlink_in_entry_path,
            "pnp_gated": pnp_gated,
            "is_control_device": is_control_device,
            "sddl": [s.upper() for s in sddl][:10],
            "sddl_grants_user": sddl_grants_user,
        }
        # verdict: available right after sc start, no hardware, user-openable
        result["symlink_user_reachable"] = bool(
            creates_symlink and symlink_in_entry_path
            and (is_control_device or not pnp_gated)
            and sddl_grants_user)

        # ---- (b) mouse injection ---------------------------------------------
        mouse_str = _contains_any(all_c, _MOUSE_STRINGS) \
            or [s for s in strings if _contains_any(s, _MOUSE_STRINGS)]
        connect_apis = [a for a in _CONNECT_APIS if a in symbols]
        ioctl_hits = [hex(i) for i in _CONNECT_IOCTLS
                      if ("%x" % i) in all_c.lower()]
        # an indirect call near the class-service-callback material = the hook
        indirect_call = "(**" in all_c or "(*(code *)" in all_c
        inject = bool(mouse_str and (connect_apis or ioctl_hits) and indirect_call)
        result["mouse_injection"] = {
            "verdict": inject,
            "class_strings": sorted(set(mouse_str))[:10],
            "connect_apis": connect_apis,
            "connect_ioctls": ioctl_hits,
            "indirect_call_present": indirect_call,
        }

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
        result["ok"] = True
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)

    _write_json(out_path, result)
    if report_dir:
        try:
            _write_report(report_dir, name_base, result, entry_c, decomp)
        except Exception as exc:
            print("DriverTriage: report write failed: %s" % exc)


def _write_json(path, obj):
    f = open(path, "w")
    try:
        f.write(json.dumps(obj))
    finally:
        f.close()
    print("DriverTriage: wrote " + path)


def _sep(title):
    return "\n" + ("=" * 78) + "\n" + title + "\n" + ("=" * 78) + "\n"


def _write_report(report_dir, name_base, result, entry_c, decomp):
    """Human artifacts: disassembly.txt (full) + <name_base>-driver-entry.c."""
    import os
    try:
        os.makedirs(report_dir)
    except OSError:
        pass

    # DriverEntry pseudo-C on its own
    ec = open(os.path.join(report_dir, name_base + "-driver-entry.c"), "w")
    try:
        ec.write(entry_c or "// DriverEntry decompilation unavailable\n")
    finally:
        ec.close()

    # full report
    lines = []
    lines.append("DriverTriage report for %s" % result.get("program", name_base))
    lines.append("DriverEntry: %s   functions decompiled: %s"
                 % (result.get("driver_entry"), result.get("functions_decompiled")))
    if result.get("error"):
        lines.append("ERROR: %s" % result["error"])

    mi = result.get("mouse_injection") or {}
    sl = result.get("symlink") or {}
    lines.append(_sep("VERDICTS"))
    lines.append("(b) mouse injection            : %s" % mi.get("verdict"))
    lines.append("      class strings            : %s" % ", ".join(mi.get("class_strings") or []))
    lines.append("      connect apis             : %s" % ", ".join(mi.get("connect_apis") or []))
    lines.append("      connect ioctls           : %s" % ", ".join(mi.get("connect_ioctls") or []))
    lines.append("      indirect call present    : %s" % mi.get("indirect_call_present"))
    lines.append("(c) symlink user-reachable     : %s" % result.get("symlink_user_reachable"))
    lines.append("      creates symlink          : %s" % sl.get("creates_symlink"))
    lines.append("      symlink strings          : %s" % ", ".join(sl.get("symlink_strings") or []))
    lines.append("      created by               : %s" % ", ".join(sl.get("created_by") or []))
    lines.append("      reachable from DriverEntry: %s" % sl.get("reachable_from_driver_entry"))
    lines.append("      pnp gated                : %s" % sl.get("pnp_gated"))
    lines.append("      is control device        : %s" % sl.get("is_control_device"))
    lines.append("      sddl                     : %s" % " ".join(sl.get("sddl") or []))
    lines.append("      sddl grants user         : %s" % sl.get("sddl_grants_user"))

    wdf = result.get("wdf_calls") or {}
    if wdf:
        lines.append(_sep("RESOLVED WDF FUNCTION-TABLE CALLS"))
        for name in sorted(wdf):
            lines.append("  %-34s called in: %s" % (name, ", ".join(wdf[name])))

    callers = result.get("callers_of_symlink_fn") or {}
    if callers:
        lines.append(_sep("CALLERS OF SYMLINK-REFERENCING FUNCTIONS"))
        for fn in sorted(callers):
            lines.append("  %s  <-  %s" % (fn, ", ".join(callers[fn]) or "(none / DriverEntry)"))

    lines.append(_sep("PSEUDO-C: DriverEntry"))
    lines.append(entry_c or "(unavailable)")
    lines.append(_sep("PSEUDO-C: reachable callees"))
    for name in sorted(decomp):
        if name == "DriverEntry":
            continue
        lines.append("\n/* ---- %s ---- */\n" % name)
        lines.append(decomp[name] or "(decompilation unavailable)")

    dt = open(os.path.join(report_dir, "disassembly.txt"), "w")
    try:
        dt.write("\n".join(lines))
    finally:
        dt.close()
    print("DriverTriage: wrote report to " + report_dir)


main()
