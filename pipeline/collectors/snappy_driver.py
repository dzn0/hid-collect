"""Snappy Driver Installer (SDIO) — input driverpacks via BitTorrent.

SDIO publishes the entire Windows driver corpus as a single torrent of ~410
files: per-category driverpacks (`drivers/DP_*.7z`) plus small index blobs.
It is the one community source with scale comparable to the Microsoft Update
Catalog and, being BitTorrent, is immune to the HTTP rate-limiting that blocks
the web archives. Mice and keyboards there use the in-box HID stack, so every
pointing-device driver that ships a real `.sys` lives under `DP_Touchpad_*`:

    drivers/DP_Touchpad_Alps_*.7z
    drivers/DP_Touchpad_Cypress_*.7z
    drivers/DP_Touchpad_Elan_*.7z
    drivers/DP_Touchpad_Others_*.7z
    drivers/DP_Touchpad_Synaptics_*.7z

Flow:

  1. `discover()` — HTTP-fetch `SDIO_Update.torrent`, bencode-parse its file
     list, and pick the input driverpacks (default: the DP_Touchpad_* set),
     recording each file's 1-based index in the torrent. No torrent client is
     needed for this step, so discovery runs anywhere.

  2. `acquire()` — drive **aria2c** to download *only* the selected files from
     the torrent (`--select-file=<indices>`), then 7-Zip-extract each pack and
     harvest `.sys`. aria2c is installed **only in the Docker image** (the host
     is never expected to have it); if it is missing, acquisition raises with a
     clear message instead of trying to download.

Everything is static downstream — binaries are parsed as bytes in pipeline.index,
never executed. Same content-addressed store, resume ledger and provenance path
as the other collectors; `drivers/<sha256>.sys` dedupes across all sources.

Environment knobs:
- `PDT_SDI_TORRENT`      (url)     default: glenn.delahoy.com SDIO_Update.torrent
- `PDT_SDI_CATEGORIES`   (csv)     default: "touchpad" (which DP_* families)
- `PDT_SDI_ARIA2`        (path)    default: "aria2c"
- `PDT_SDI_BT_TIMEOUT`   (int s)   default: 300 (abort a stalled swarm)
- `PDT_SDI_MAX_PACKS`    (int)     default: 0 (unlimited)
- `PDT_SDI_SEED_TIME`    (int s)   default: 0 (don't seed after download)
- `PDT_SDI_REFRESH=1`              re-extract packs already in the ledger
- `PDT_SDI_REFRESH_DISCOVERY=1`    re-fetch + re-parse the torrent
"""
from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from .. import config
from .. import progress
from .base import Collector
from . import _common as C


DEFAULT_TORRENT = "https://www.glenn.delahoy.com/downloads/sdio/SDIO_Update.torrent"

# Map a friendly category to the driverpack filename stem it selects.
CATEGORY_PATTERNS = {
    "touchpad": r"DP_Touchpad_",
    "mouse": r"DP_Mouse_",
    "keyboard": r"DP_Keyboard_",
    "hid": r"DP_HID",
}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


# ---- minimal bencode decoder (torrent metadata is bencoded) ----

def _bdecode(data: bytes, i: int = 0):
    c = data[i:i + 1]
    if c == b"i":
        j = data.index(b"e", i)
        return int(data[i + 1:j]), j + 1
    if c == b"l":
        i += 1
        out = []
        while data[i:i + 1] != b"e":
            v, i = _bdecode(data, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while data[i:i + 1] != b"e":
            k, i = _bdecode(data, i)
            v, i = _bdecode(data, i)
            out[k] = v
        return out, i + 1
    j = data.index(b":", i)
    n = int(data[i:j])
    s = data[j + 1:j + 1 + n]
    return s, j + 1 + n


class SnappyDriverCollector(Collector):
    name = "snappy-driver"
    role = "Snappy Driver Installer input driverpacks (BitTorrent, no rate limit)"
    # BitTorrent peers are arbitrary; host allow-listing does not apply to the
    # swarm. The only HTTP fetch is the torrent file itself.
    allowed_hosts = ["glenn.delahoy.com", "www.glenn.delahoy.com"]

    def __init__(self) -> None:
        self.torrent_url = os.environ.get("PDT_SDI_TORRENT", DEFAULT_TORRENT)
        raw = os.environ.get("PDT_SDI_CATEGORIES", "touchpad")
        self.categories = [c.strip().lower() for c in raw.split(",") if c.strip()]
        self.aria2 = os.environ.get("PDT_SDI_ARIA2", "aria2c")
        self.bt_timeout = _env_int("PDT_SDI_BT_TIMEOUT", 300)
        self.seed_time = _env_int("PDT_SDI_SEED_TIME", 0)
        self.max_packs = _env_int("PDT_SDI_MAX_PACKS", 0)
        self._ledger_lock = threading.Lock()
        self._torrent_path: Path | None = None
        self._torrent_name = ""
        self._targets: list[dict] = []  # {index, path, size}

    # ----- discovery -----

    def _select_re(self) -> re.Pattern:
        pats = [CATEGORY_PATTERNS[c] for c in self.categories if c in CATEGORY_PATTERNS]
        if not pats:
            pats = [CATEGORY_PATTERNS["touchpad"]]
        return re.compile("|".join(pats))

    def discover(self) -> dict:
        d = config.collectors_dir() / self.name / "_torrent"
        d.mkdir(parents=True, exist_ok=True)
        tpath = d / "SDIO_Update.torrent"
        refresh = os.environ.get("PDT_SDI_REFRESH_DISCOVERY", "") not in ("", "0", "false")
        if refresh or not tpath.exists():
            progress.report("fetching SDIO_Update.torrent")
            C.download(self.torrent_url, tpath, self.allowed_hosts,
                       max_mb=50, timeout=120)
        self._torrent_path = tpath

        meta, _ = _bdecode(tpath.read_bytes())
        info = meta[b"info"]
        self._torrent_name = info.get(b"name", b"").decode("utf-8", "replace")
        files = info.get(b"files") or []
        sel = self._select_re()
        targets: list[dict] = []
        # aria2's --select-file index is 1-based in torrent file order.
        for idx, f in enumerate(files, 1):
            path = "/".join(p.decode("utf-8", "replace") for p in f[b"path"])
            if not path.lower().endswith(".7z"):
                continue
            if not sel.search(path):
                continue
            targets.append({"index": idx, "path": path, "size": f[b"length"]})
        if self.max_packs:
            targets = targets[: self.max_packs]
        self._targets = targets
        total = sum(t["size"] for t in targets)
        for t in targets:
            progress.report(f"select: {t['path']} ({t['size']/1e6:.0f} MB)")
        return {
            "discovery_page": self.torrent_url,
            "installer_url": None,
            "torrent_name": self._torrent_name,
            "categories": list(self.categories),
            "packs_selected": len(targets),
            "bytes_selected": total,
            "targets": targets,
        }

    # ----- acquisition -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        if not self._targets:
            info["stats"] = {"found": 0, "packages": 0, "sys": 0}
            return []
        if shutil.which(self.aria2) is None:
            raise RuntimeError(
                f"snappy-driver acquisition needs aria2c (torrent client), not "
                f"found as {self.aria2!r}. It is installed in the Docker image "
                f"only; run this collector via `docker compose run --rm "
                f"snappy-driver`, or set PDT_SDI_ARIA2 to an aria2c path.")

        refresh = os.environ.get("PDT_SDI_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()

        dl_root = work_dir / "torrent"
        dl_root.mkdir(parents=True, exist_ok=True)
        self._aria2_download(dl_root)

        rows: list[dict] = []
        errors: list[dict] = []
        stats = {"found": len(self._targets), "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0, "missing": 0}

        for t in self._targets:
            name = t["path"].split("/")[-1]
            if name in processed:
                stats["skipped_seen"] += 1
                continue
            pack = self._find_downloaded(dl_root, t["path"])
            if pack is None or not pack.exists():
                stats["missing"] += 1
                errors.append({"pack": name, "error": "not downloaded"})
                continue
            progress.set_slot(f"sdi-{name}", name[:18])
            progress.report(f"extracting {name}")
            try:
                got = self._extract_pack(work_dir, pack, name)
            except Exception as exc:
                errors.append({"pack": name, "error": str(exc)})
                self._record(name, status="failed", sys_shas=[])
                stats["failed"] += 1
                progress.clear_slot()
                continue
            rows.extend(got)
            stats["packages"] += 1
            stats["sys"] += len(got)
            if not got:
                stats["no_sys"] += 1
            self._record(name, status="ok" if got else "no_sys",
                         sys_shas=[r["sha256"] for r in got])
            progress.clear_slot()

        info["stats"] = stats
        info["errors"] = errors[:500]
        info["error_count"] = len(errors)
        info["ledger_at_start"] = len(processed)
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    def _aria2_download(self, dl_root: Path) -> None:
        indices = ",".join(str(t["index"]) for t in self._targets)
        cmd = [
            self.aria2,
            "--dir", str(dl_root),
            "--select-file", indices,
            "--seed-time", str(self.seed_time),
            "--bt-stop-timeout", str(self.bt_timeout),
            "--summary-interval", "10",
            "--console-log-level", "warn",
            "--enable-dht", "true",
            "--bt-enable-lpd", "true",
            "--check-integrity", "true",
            str(self._torrent_path),
        ]
        progress.report(
            f"torrent: downloading {len(self._targets)} pack(s) via aria2 "
            f"({sum(t['size'] for t in self._targets)/1e6:.0f} MB)")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace")
        assert proc.stdout is not None
        last = ""
        for line in proc.stdout:
            line = line.strip()
            # aria2 progress lines look like: [#abc 1.2GiB/1.3GiB(93%) ...]
            if line.startswith("[#") and "%" in line:
                last = line
                progress.report(f"torrent: {line[:70]}")
        proc.wait()
        if proc.returncode not in (0,):
            # aria2 returns nonzero on partial/stop-timeout; surface it but let
            # acquire() still harvest whatever completed.
            progress.report(f"aria2 exit {proc.returncode} (last: {last[:50]})")

    def _find_downloaded(self, dl_root: Path, rel_path: str) -> Path | None:
        # aria2 lays the torrent out under <dir>/<torrent name>/<path>.
        cand = dl_root / self._torrent_name / rel_path
        if cand.exists():
            return cand
        cand2 = dl_root / rel_path
        if cand2.exists():
            return cand2
        name = rel_path.split("/")[-1]
        hits = list(dl_root.rglob(name))
        return hits[0] if hits else None

    def _extract_pack(self, work_dir: Path, pack: Path, name: str) -> list[dict]:
        folder = work_dir / "packages" / name.rsplit(".", 1)[0]
        extracted = folder / "extracted"
        C.extract(pack, extracted)
        got = C.collect_sys_files(folder, config.drivers_dir(),
                                  include_native_pe=True)
        if not got and C.extract_nested(extracted):
            got = C.collect_sys_files(folder, config.drivers_dir(),
                                      include_native_pe=True)
        for r in got:
            r["provenance"] = {
                "source_kind": "snappy-driver-installer",
                "aggregator": "sdio (bittorrent)",
                "trust_note": "community driverpack aggregate; signatures vary, "
                              "verified downstream in pipeline.index",
                "driverpack": name,
                "torrent": self._torrent_name,
                "torrent_url": self.torrent_url,
            }
            C.append_index(config.drivers_dir(),
                           {"sha256": r["sha256"], "provenance": r["provenance"]})
        C.prune_dir(folder)
        return got

    # ----- resume ledger (per driverpack) -----

    def _ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_ledger(self) -> set[str]:
        p = self._ledger_path()
        seen: set[str] = set()
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                if entry.get("pack") and entry.get("status") in ("ok", "no_sys"):
                    seen.add(entry["pack"])
        return seen

    def _record(self, pack: str, *, status: str, sys_shas: list[str]) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"pack": pack, "status": status,
                                    "sys": sys_shas, "ts": C.utc_now()},
                                   ensure_ascii=False) + "\n")


def collector() -> SnappyDriverCollector:
    return SnappyDriverCollector()
