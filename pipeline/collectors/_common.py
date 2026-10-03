"""Static-collection primitives shared by all collectors.

Design invariants:
- Downloads use HTTPS only; host allowlist is enforced per call.
- Binary magic is validated against the downloaded file's declared suffix,
  so an HTML challenge page cannot masquerade as a ZIP/EXE/MSI/CAB.
- urllib is tried first; on failure, Windows curl (IPv4, cert validation on)
  is the fallback. Certificate checking is never disabled.
- No installer or driver is ever executed; 7-Zip is used for every archive.
"""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .. import config
from .. import progress

# keep subprocess silent on Windows; 0 is a no-op (and the only valid value)
# on non-Windows platforms, where passing creationflags at all is an error.
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
UA = "Mozilla/5.0 PortableDriverTriage/0.1"
MAGIC = {
    ".exe": b"MZ",
    ".sys": b"MZ",
    ".dll": b"MZ",
    ".msi": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ".cab": b"MSCF",
    ".zip": b"PK",
    ".7z": b"7z\xbc\xaf\x27\x1c",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_now_compact() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _host_allowed(url: str, allowed_hosts: list[str]) -> None:
    host = (urlparse(url).hostname or "").lower()
    if not any(host == h or host.endswith("." + h) for h in allowed_hosts):
        raise ValueError(f"Download host outside source allowlist: {host}")


def _validate_magic(path: Path) -> None:
    expected = MAGIC.get(path.suffix.lower())
    if not expected:
        return
    with path.open("rb") as f:
        header = f.read(len(expected))
    if not header.startswith(expected):
        raise ValueError(
            f"Response is not a valid {path.suffix} (got {header!r}; "
            f"likely an HTML anti-bot challenge)"
        )


def fetch_text(url: str, allowed_hosts: list[str], timeout: int = 60) -> str:
    _host_allowed(url, allowed_hosts)
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as r:
        _host_allowed(r.geturl(), allowed_hosts)
        return r.read(32 << 20).decode("utf-8", errors="replace")


def download(
    url: str,
    target: Path,
    allowed_hosts: list[str],
    max_mb: int = 1500,
    timeout: int = 90,
    referer: str | None = None,
    opener=None,
) -> dict:
    """Download `url` to `target`. Returns a provenance dict.

    `referer`, when given, is sent as the `Referer` header on both the urllib
    attempt and the curl fallback. Some download hosts (e.g. an aggregator's
    file CDN that hands out a tokenized URL from a landing page) gate the file
    on the originating page; passing the landing URL as referer satisfies that
    without a real browser.

    `opener`, when given, is a urllib `OpenerDirector` used in place of the
    module default for the primary attempt — e.g. one carrying a cookie jar, so
    a file whose CDN checks the session cookie set during the landing POST is
    fetched with that session. The curl fallback has no cookies and will fail
    for such a host; that is fine, since the opener path is the one expected to
    succeed."""
    if urlparse(url).scheme != "https":
        raise ValueError("HTTPS required")
    _host_allowed(url, allowed_hosts)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")

    headers = {"User-Agent": UA}
    if referer:
        headers["Referer"] = referer
    _open = opener.open if opener is not None else urlopen
    fname = Path(urlparse(url).path).name or "download"
    try:
        req = Request(url, headers=headers)
        with _open(req, timeout=timeout) as r:
            _host_allowed(r.geturl(), allowed_hosts)
            final_url = r.geturl()
            clen = (r.headers.get("Content-Length") or "").strip()
            total_mb = int(clen) / (1 << 20) if clen.isdigit() else None
            written = 0
            last = 0.0
            with partial.open("wb") as f:
                while chunk := r.read(1 << 20):
                    written += len(chunk)
                    if written > max_mb * (1 << 20):
                        raise ValueError("Download exceeds size limit")
                    f.write(chunk)
                    now = time.monotonic()
                    if now - last > 0.2:
                        mb = written / (1 << 20)
                        bar = f"{mb:.0f}/{total_mb:.0f} MB" if total_mb else f"{mb:.0f} MB"
                        progress.report(f"downloading {fname} · {bar}")
                        last = now
        _validate_magic(partial)
        partial.replace(target)
    except Exception as exc:
        partial.unlink(missing_ok=True)
        progress.report(f"downloading {fname} · curl fallback")
        curl = shutil.which("curl.exe") or shutil.which("curl")
        if not curl:
            raise RuntimeError(f"urllib: {exc}; curl not found on PATH") from exc
        cmd = [
            curl, "--ipv4", "--location", "--fail", "--silent", "--show-error",
            "--proto", "=https", "--proto-redir", "=https",
            "--connect-timeout", "20",
            "--max-time", str(max(90, timeout * 3)),
            "--max-filesize", str(max_mb * (1 << 20)),
            "--user-agent", UA,
            *(["--referer", referer] if referer else []),
            "--output", str(partial),
            "--write-out", "%{url_effective}",
            url,
        ]
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=max(100, timeout * 3 + 10), creationflags=CREATE_NO_WINDOW,
        )
        if r.returncode:
            raise RuntimeError(f"urllib: {exc}; curl: {r.stderr.strip()}") from exc
        final_url = r.stdout.strip()
        _host_allowed(final_url, allowed_hosts)
        if partial.stat().st_size > max_mb * (1 << 20):
            raise ValueError("Download exceeds size limit")
        _validate_magic(partial)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)

    return {
        "url": url,
        "final_url": final_url,
        "path": str(target),
        "size": target.stat().st_size,
        "sha256": sha256_file(target),
        "downloaded_at": utc_now(),
    }


def prune_dir(path: Path) -> None:
    """Delete a collector's per-package working tree once its drivers have been
    copied into the content-addressed `drivers_dir`.

    The downloaded installer/archive and its extraction tree are disposable: the
    only durable output is the deduped `.sys` in `drivers_dir`, and all
    provenance (URLs, sizes, sha256) is already captured in the manifest. Keeping
    the raw packages wastes tens of GB for a handful of recovered drivers, so
    collectors prune after each package by default. Set `PDT_KEEP_PACKAGES=1` to
    retain them for debugging. Best-effort: a failure here never fails the run."""
    if os.environ.get("PDT_KEEP_PACKAGES", "") not in ("", "0", "false"):
        return
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


def sweep_stale_work(collector_dir: Path, keep_run_id: str, min_age_s: int = 60) -> None:
    """Remove orphaned run trees from this collector's prior runs.

    Per-package prune (`prune_dir`) runs only after a package is harvested, so a
    run that is interrupted (Ctrl-C, container kill, crash) before that leaves
    its in-flight package + extraction tree behind — over many interrupted runs
    these orphans accumulate to gigabytes.

    Orphan test: a sibling run_id dir is orphan iff it has NO `manifest.json`
    (the manifest is written only at the end of `Collector.run()`, in a
    `finally` block that covers both success and failure). A run with a
    manifest has already finished cleanly — keep it for debugging. A run
    without is either (a) killed and now orphan or (b) a concurrent run that
    hasn't finished yet. The `min_age_s` grace period on dir ctime distinguishes
    those: a dir created within the last 60s may be a concurrent run just
    starting up, so leave it alone; older than that, it's orphan.

    This replaces an earlier mtime-based heuristic that failed when the next
    run started within 10 minutes of a Ctrl-C — mtime of an active extraction
    bounces to "now" constantly, making stale trees look fresh and never
    sweeping. The manifest check is explicit and robust.

    Honors `PDT_KEEP_PACKAGES=1`. Best-effort."""
    if os.environ.get("PDT_KEEP_PACKAGES", "") not in ("", "0", "false"):
        return
    if not collector_dir.is_dir():
        return
    now = time.time()
    for run in collector_dir.iterdir():
        if not run.is_dir() or run.name == keep_run_id:
            continue
        try:
            # Finished runs carry a manifest.json written in Collector.run()'s
            # finally block. Its presence means the run exited cleanly (success
            # OR controlled failure) — preserve the tree so the user can inspect
            # errors / downloads / status without digging into a tombstone.
            if (run / "manifest.json").is_file():
                continue
            # No manifest → killed mid-run. But: a brand-new concurrent run
            # that hasn't yet produced a manifest looks identical. Protect it
            # with a short age guard against the dir's own creation time.
            try:
                age = now - run.stat().st_ctime
            except OSError:
                age = min_age_s + 1  # unknown age → assume safe to sweep
            if age < min_age_s:
                continue
            # Orphan confirmed: nuke the whole tree. The old implementation
            # only killed packages/ and extracted/, leaving an empty shell
            # dir that still took an inode and showed up in listings.
            shutil.rmtree(run, ignore_errors=True)
        except OSError:
            pass


def extract(package: Path, destination: Path, timeout: int = 240) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    progress.report(f"extracting {package.name}")
    r = subprocess.run(
        [str(config.sevenzip()), "x", str(package), "-o" + str(destination), "-y", "-bd"],
        capture_output=True, text=True, errors="replace",
        timeout=timeout, creationflags=CREATE_NO_WINDOW,
    )
    return {
        "package": str(package),
        "destination": str(destination),
        "exit_code": r.returncode,
        "output_tail": (r.stdout + r.stderr)[-8000:],
    }


def extract_pe_resources(package: Path, destination: Path, timeout: int = 180) -> dict:
    """Extract an app EXE's PE *resources* with 7-Zip's `-tPE` view.

    Some monitoring utilities (CPU-Z, HWMonitor, HWiNFO) ship their kernel driver
    embedded as a whole-PE resource inside the application binary. Plain `7z x`
    auto-unpacks the EXE and does not preserve that resource intact; forcing the
    PE view with `-tPE` does. Pair with `collect_sys_files(include_native_pe=True)`
    to recover the driver by content."""
    destination.mkdir(parents=True, exist_ok=True)
    progress.report(f"extracting PE resources {package.name}")
    r = subprocess.run(
        [str(config.sevenzip()), "x", "-tPE", str(package),
         "-o" + str(destination), "-y", "-bd"],
        capture_output=True, text=True, errors="replace",
        timeout=timeout, creationflags=CREATE_NO_WINDOW,
    )
    return {"package": str(package), "destination": str(destination),
            "method": "7z -tPE", "exit_code": r.returncode,
            "output_tail": (r.stdout + r.stderr)[-8000:]}


_NESTED_ARCHIVE_EXT = {".exe", ".msi", ".cab", ".zip", ".7z", ".msu"}


def extract_nested(root: Path, timeout: int = 300) -> list[dict]:
    """Extract every nested archive/installer found under `root` one level down.

    Used for installers wrapped in another installer (e.g. an NSIS setup `.exe`
    inside a distribution `.zip`). Each candidate is extracted into a sibling
    `<name>.unpacked/`; files 7-Zip cannot open as archives fail harmlessly.
    Returns per-extraction records. Call after the first pass if it found no
    drivers, to keep the common (single-stage) case noise-free."""
    results: list[dict] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _NESTED_ARCHIVE_EXT:
            continue
        out = p.with_suffix(p.suffix + ".unpacked")
        if out.exists():
            continue
        try:
            results.append(extract(p, out, timeout))
        except Exception as e:
            results.append({"package": str(p), "error": str(e)})
    return results


def pe_identity(path: Path) -> dict | None:
    """Return machine/subsystem of a PE, or None if not a PE."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        if head[:2] != b"MZ":
            return None
        off = struct.unpack_from("<I", head, 0x3C)[0]
        if off + 96 > len(head):
            with open(path, "rb") as f:
                f.seek(off)
                head = f.read(256)
            off = 0
        if head[off:off + 4] != b"PE\0\0":
            return None
        machine = struct.unpack_from("<H", head, off + 4)[0]
        subsystem = struct.unpack_from("<H", head, off + 24 + 68)[0]
        return {
            "machine": hex(machine),
            "subsystem": subsystem,
            "native": subsystem == 1,
        }
    except (OSError, struct.error):
        return None


# Lean collector: no signature verification, no L0 gate, no fingerprint. Every
# .sys that lands in `extracted_root` is stored. If you later need triage, feed
# the corpus into the parent `hid-driver-triage` repo.


_PROVENANCE_LOCK = threading.Lock()


def record_provenance(drivers_dir: Path, record: dict) -> None:
    """Append one durable provenance line for a stored binary.

    The content-addressed store (`drivers/<sha256>.sys`) is otherwise opaque, and
    the full per-driver metadata (original name, provenance) lives only in the run
    `manifest.json`, which is written once at the very end of a run: an interrupted
    long run (the touslesdrivers input collector downloads thousands of packages
    over hours) leaves the binaries on disk with no way to tell what they are or
    where they came from. `original_name` in particular is not derivable from the
    bytes and is lost for good.

    So, as each binary is stored, we append a line to `drivers/_provenance.jsonl`.
    It is append-only and guarded by a lock (collectors run worker threads), which
    keeps it cheap and interruption-safe — no read-modify-write of a growing file
    on the hot path. The heavy, byte-derived report (PE info, imports, strings) is
    built separately by `python -m pipeline.index`, which joins this log to produce
    the single `drivers/index.json`. A given sha256 may appear on several lines
    (minimal at store time, enriched with provenance afterwards, once per package it
    ships in); the index builder merges them by sha256.
    """
    digest = record.get("sha256")
    if not digest:
        return
    row = dict(record)
    row["ts"] = utc_now()
    line = json.dumps(row, ensure_ascii=False)
    path = drivers_dir / "_provenance.jsonl"
    with _PROVENANCE_LOCK:
        drivers_dir.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def collect_sys_files(
    extracted_root: Path,
    drivers_dir: Path,
    *,
    include_native_pe: bool = False,
    **_ignored,
) -> list[dict]:
    """Walk `extracted_root`, find driver binaries, dedup by sha256, and copy
    survivors to `drivers_dir/<sha256>.sys`. Returns per-driver records.

    By default only `*.sys` files are collected. With `include_native_pe=True`,
    any file whose *content* is a native-subsystem PE (IMAGE_SUBSYSTEM_NATIVE)
    is collected too — recovers drivers that an MSI (`fil<hex>` stream names)
    or a PE-resource extraction (`107`, `725`) leaves without a `.sys` suffix.

    `**_ignored` swallows legacy kwargs (`verify`, `catalogs`) so callers written
    for the parent repo keep working against this lean implementation."""
    candidates = [p for p in extracted_root.rglob("*")
                  if p.is_file() and p.suffix.lower() == ".sys"]
    if include_native_pe:
        seen_paths = {p.resolve() for p in candidates}
        for p in extracted_root.rglob("*"):
            if not p.is_file() or p.resolve() in seen_paths:
                continue
            ident = pe_identity(p)
            if ident and ident.get("native"):
                candidates.append(p)
    files = sorted(candidates)
    progress.report(f"scanning {len(files)} candidate(s) for drivers")
    rows: list[dict] = []
    seen: set[str] = set()
    for p in files:
        progress.report(f"hashing {p.name}")
        digest = sha256_file(p)
        if digest in seen:
            continue
        seen.add(digest)
        target = drivers_dir / f"{digest}.sys"
        is_new = not target.exists()
        if is_new:
            shutil.copy2(p, target)
        row = {
            "sha256": digest,
            "original_name": p.name,
            "size": p.stat().st_size,
            "pe": pe_identity(p),
            "extraction_path": str(p.relative_to(extracted_root)),
            "stored_path": str(target),
        }
        rows.append(row)
        # Log identity now so the binary is never anonymous, even if the run dies
        # before its manifest is written; the collector appends provenance after
        # acquire() returns. original_name is not recoverable from the bytes.
        record_provenance(drivers_dir, {
            "sha256": digest, "original_name": row["original_name"],
            "size": row["size"], "extraction_path": row["extraction_path"],
        })
        if is_new:
            # Count only drivers NEW to the content-addressed corpus so the live
            # total tracks corpus growth and re-downloads do not inflate it.
            progress.add_count(1)
    return rows


# ── embedded-driver carving ───────────────────────────────────────────────────
def _embedded_driver_len(data: bytes, mz: int) -> int | None:
    """If an intact native-subsystem (kernel-driver) PE begins at `mz` in `data`,
    return its exact on-disk length, else None.

    Length is the greatest section end (PointerToRawData + SizeOfRawData),
    extended by the Authenticode security directory when present, so a *signed*
    driver is carved whole. Only `IMAGE_SUBSYSTEM_NATIVE` (1) PEs qualify, which
    is what lets the carve run over a whole application binary without mistaking
    its user-mode EXE/DLL bytes for a driver."""
    try:
        if data[mz:mz + 2] != b"MZ":
            return None
        pe = mz + struct.unpack_from("<I", data, mz + 0x3C)[0]
        if pe + 24 + 68 + 2 > len(data) or data[pe:pe + 4] != b"PE\0\0":
            return None
        if struct.unpack_from("<H", data, pe + 24 + 68)[0] != 1:  # subsystem
            return None
        num_sec = struct.unpack_from("<H", data, pe + 6)[0]
        size_opt = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        end = 0
        sec = opt + size_opt
        for k in range(num_sec):
            base = sec + k * 40
            if base + 24 > len(data):
                return None
            sraw = struct.unpack_from("<I", data, base + 16)[0]
            praw = struct.unpack_from("<I", data, base + 20)[0]
            if praw and sraw:
                end = max(end, praw + sraw)
        # data-directory entry 4 (security): its VirtualAddress is a FILE offset
        # relative to this PE's own start, so the signed file ends at off+size.
        ddir = opt + (112 if magic == 0x20b else 96)
        if ddir + 4 * 8 + 8 <= len(data):
            cert_off, cert_sz = struct.unpack_from("<II", data, ddir + 4 * 8)
            if cert_off and cert_sz:
                end = max(end, cert_off + cert_sz)
        return end if end and mz + end <= len(data) else None
    except struct.error:
        return None


def _carve_native_pes(data: bytes) -> list[tuple[int, int]]:
    """Return (offset, length) of every intact native-subsystem PE embedded in
    `data`, skipping past each hit so a driver's own internal `MZ` (its DOS stub,
    an embedded cert, …) cannot produce a false second hit."""
    out: list[tuple[int, int]] = []
    i = 0
    while True:
        i = data.find(b"MZ", i)
        if i < 0:
            break
        ln = _embedded_driver_len(data, i)
        if ln:
            out.append((i, ln))
            i += ln
        else:
            i += 2
    return out


def collect_carved_drivers(
    extracted_root: Path,
    drivers_dir: Path,
    *,
    max_scan_mb: int = 256,
    **_ignored,
) -> list[dict]:
    """Recover kernel drivers embedded *inside* application binaries.

    Some monitoring/diagnostic utilities (CPU-Z, RW-Everything, HWiNFO, …) carry
    their `.sys` as a PE resource or an appended blob inside the app `.exe`, which
    `collect_sys_files` cannot see: the driver is not a standalone file on disk,
    and 7-Zip neither reconstructs it from the resource nor splits a blob that
    concatenates several driver PEs. This walks every file under `extracted_root`,
    byte-scans for intact native-subsystem PEs, slices each out, dedups by
    sha256, and stores survivors exactly like `collect_sys_files` — same row
    shape, same live counting — tagging each row `carved`.

    Files larger than `max_scan_mb` are skipped to bound memory (driver-bearing
    app binaries are tens of MB at most). Carving is opt-in per collector: it is
    the fallback for PE-resource sources, not run over the bulk driver-pack
    collectors where every file would be needlessly byte-scanned."""
    rows: list[dict] = []
    seen: set[str] = set()
    cap = max_scan_mb * (1 << 20)
    files = [p for p in sorted(extracted_root.rglob("*"))
             if p.is_file() and 0 < p.stat().st_size <= cap]
    progress.report(f"carving {len(files)} file(s) for embedded drivers")
    for p in files:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        for off, ln in _carve_native_pes(data):
            blob = data[off:off + ln]
            digest = hashlib.sha256(blob).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            target = drivers_dir / f"{digest}.sys"
            is_new = not target.exists()
            if is_new:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(blob)
            row = {
                "sha256": digest,
                "original_name": f"{p.name}@{off}",
                "size": len(blob),
                "pe": pe_identity(target),
                "extraction_path": f"{p.relative_to(extracted_root)}@{off}",
                "stored_path": str(target),
                "carved": True,
            }
            rows.append(row)
            record_provenance(drivers_dir, {
                "sha256": digest, "original_name": row["original_name"],
                "size": row["size"], "extraction_path": row["extraction_path"],
                "carved": True,
            })
            if is_new:
                progress.add_count(1)
    return rows
