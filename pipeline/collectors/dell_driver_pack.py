"""Dell enterprise driver pack catalog — one `.cab` or `.exe` per model/OS.

Dell publishes a second, higher-leverage catalog alongside `CatalogPC.cab`:

    https://downloads.dell.com/catalog/DriverPackCatalog.cab

(334 KB; wraps `DriverPackCatalog.xml`, ~3.3 MB.) The XML lists ~1130
`<DriverPackage>` entries — one *enterprise driver pack* per model+OS, median
~949 MB, total ~1353 GB. Each pack is a direct downloadable CAB (`format="cab"`)
or SFX EXE (`format="exe"`); when unpacked, each yields a whole model's
WHQL-signed driver tree (chipset, HID, net, video, audio, …).

This is the Dell analogue of HP's `HPClientDriverPackCatalog.cab`, with two
practical advantages: packs are already content-addressed by their `hashMD5`,
and the CAB-format packs skip the SFX unwrap layer entirely.

Flow:

  1. `discover()`:
       - download `DriverPackCatalog.cab` (334 KB).
       - 7-Zip extract -> `DriverPackCatalog.xml`.
       - stream-parse `<DriverPackage>` -> {path, size, md5, format, type,
         osCodes[], osArchs[], name, release_date, vendor_version, release_id}.
       - keep rows where `type="win"` and at least one supported OS declares
         `osArch="x64"`.
       - dedupe by relative `path`.
       - rank newest-first by `dateTime`.
       - cache the resolved URL universe for reuse.

  2. `acquire()`:
       - download each pack under `PDT_DDP_MAX_MB` (default 4000).
       - 7-Zip extract. CAB packs unpack directly; EXE packs are SFX and the
         existing `extract_nested` pass handles the inner tree.

Everything static: no pack is executed, host allowlist enforced, cert check
never disabled, magic validated. HTTPS only. Transient disk per worker ~=
pack + its extraction, so `PDT_DDP_JOBS` defaults to 2.

Environment knobs:
- `PDT_DDP_CATALOG_URL`     (str)      default: official downloads.dell.com URL
- `PDT_DDP_JOBS`            (int)      default: 2
- `PDT_DDP_MAX_PACKS`       (int)      default: 0 (unlimited)
- `PDT_DDP_MAX_MB`          (int)      default: 4000 (per pack)
- `PDT_DDP_MIN_DATE`        (YYYY-MM)  default: unset — drop packs older than
                                       this
- `PDT_DDP_REFRESH=1`                  ignore download ledger
- `PDT_DDP_REFRESH_DISCOVERY=1`        ignore discovery cache
- `PDT_DDP_DISCOVERY_TTL_DAYS` (int)   default: 7
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .. import config
from .. import progress
from .base import Collector
from . import _common as C


CATALOG_URL = "https://downloads.dell.com/catalog/DriverPackCatalog.cab"
ALLOWED_HOSTS = ["downloads.dell.com", "dl.dell.com", "ftp.dell.com"]

RX_NS = re.compile(r"^\{[^}]+\}")


def _localtag(tag: str) -> str:
    return RX_NS.sub("", tag)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _parse_driver_package(elem) -> dict | None:
    """Pull per-pack fields from a `<DriverPackage>` element. Returns None if
    required fields are missing or shape is wrong.

    Dell DriverPackCatalog schema (relevant subset):

      <DriverPackage format="cab|exe" path="FOLDER.../pack.cab"
                     size="..." hashMD5="..." dateTime="2024-..."
                     vendorVersion="1.0" dellVersion="A01" releaseID="..."
                     type="win|linux">
        <Name><Display lang="en">...</Display></Name>
        <SupportedOperatingSystems>
          <OperatingSystem osCode="Windows10" osArch="x64" .../>
          ...
        </SupportedOperatingSystems>
        <SupportedSystems>
          <Brand prefix="LAT"><Model systemID="..."/></Brand>
        </SupportedSystems>
      </DriverPackage>
    """
    attrs = elem.attrib
    rel = attrs.get("path") or ""
    fmt = (attrs.get("format") or "").lower()
    typ = (attrs.get("type") or "").lower()
    if not rel or fmt not in ("cab", "exe") or typ != "win":
        return None
    # Walk once; collect name + OS codes/archs
    name_en = ""
    os_codes: list[str] = []
    os_archs: list[str] = []
    for child in elem.iter():
        tag = _localtag(child.tag)
        if tag == "Name" and not name_en:
            for d in child.iter():
                if _localtag(d.tag) == "Display":
                    txt = (d.text or "").strip()
                    if (d.attrib.get("lang") or "").lower().startswith("en"):
                        name_en = txt
                        break
                    if not name_en:
                        name_en = txt
        elif tag == "OperatingSystem":
            if c := child.attrib.get("osCode"):
                os_codes.append(c)
            if a := child.attrib.get("osArch"):
                os_archs.append(a.lower())
    try:
        size_bytes = int(attrs.get("size") or "0")
    except ValueError:
        size_bytes = 0
    return {
        "path": rel.replace("\\", "/"),
        "format": fmt,
        "type": typ,
        "size_bytes": size_bytes,
        "md5": (attrs.get("hashMD5") or "").lower(),
        "date_time": attrs.get("dateTime") or "",
        "vendor_version": attrs.get("vendorVersion") or "",
        "dell_version": attrs.get("dellVersion") or "",
        "release_id": attrs.get("releaseID") or "",
        "name": name_en,
        "os_codes": os_codes,
        "os_archs": os_archs,
    }


def _is_x64_windows(row: dict) -> bool:
    return "x64" in (row.get("os_archs") or ())


class DellDriverPackCollector(Collector):
    name = "dell-driver-pack"
    role = "Dell enterprise driver pack catalog (downloads.dell.com)"
    allowed_hosts = list(ALLOWED_HOSTS)

    def __init__(self) -> None:
        self.catalog_url = os.environ.get("PDT_DDP_CATALOG_URL", CATALOG_URL)
        self.jobs = _env_int("PDT_DDP_JOBS", 2)
        self.max_packs = _env_int("PDT_DDP_MAX_PACKS", 0)
        self.max_mb = _env_int("PDT_DDP_MAX_MB", 4000)
        self.min_date = (os.environ.get("PDT_DDP_MIN_DATE") or "").strip()
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._url_source: dict[str, dict] = {}

    # ----- discovery -----

    def _url_for(self, rel_path: str) -> str:
        return "https://downloads.dell.com/" + rel_path.lstrip("/")

    def _config_fingerprint(self) -> str:
        payload = json.dumps(
            {"catalog": self.catalog_url, "min_date": self.min_date},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def _discovery_cache_path(self) -> Path:
        return (config.collectors_dir() / self.name /
                f"discovery_cache_{self._config_fingerprint()}.json")

    def _load_discovery_cache(self) -> dict | None:
        if os.environ.get("PDT_DDP_REFRESH_DISCOVERY", "") not in ("", "0", "false"):
            return None
        p = self._discovery_cache_path()
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        ttl_days = _env_int("PDT_DDP_DISCOVERY_TTL_DAYS", 7)
        age = time.time() - float(data.get("saved_at_epoch", 0))
        if age > ttl_days * 86400:
            return None
        return data

    def _save_discovery_cache(self, info: dict, urls: list[str],
                              url_source: dict[str, dict]) -> None:
        p = self._discovery_cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "saved_at": C.utc_now(),
            "saved_at_epoch": time.time(),
            "config_fingerprint": self._config_fingerprint(),
            "catalog_url": self.catalog_url,
            "min_date": self.min_date,
            "info": info,
            "urls": urls,
            "url_source": url_source,
        }
        p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    def discover(self) -> dict:
        cached = self._load_discovery_cache()
        if cached is not None:
            self._urls = list(cached["urls"])
            self._url_source = dict(cached["url_source"])
            if self.max_packs:
                self._urls = self._urls[: self.max_packs]
            info = dict(cached["info"])
            info["discovery_cache"] = {
                "hit": True, "saved_at": cached.get("saved_at"),
                "cached_url_count": len(cached["urls"]),
                "used_url_count": len(self._urls),
                "path": str(self._discovery_cache_path()),
            }
            progress.report(f"discovery cache hit: {len(self._urls)} pack URLs")
            return info

        work_dir = config.collectors_dir() / self.name / "_discovery"
        work_dir.mkdir(parents=True, exist_ok=True)

        cab = work_dir / "DriverPackCatalog.cab"
        progress.report("downloading DriverPackCatalog.cab")
        rec = C.download(self.catalog_url, cab, self.allowed_hosts,
                         max_mb=50, timeout=90)

        xml_dir = work_dir / "xml"
        for p in xml_dir.glob("*"):
            try:
                p.unlink()
            except OSError:
                pass
        xml_dir.mkdir(parents=True, exist_ok=True)
        C.extract(cab, xml_dir, timeout=240)
        xml_path = next(xml_dir.rglob("DriverPackCatalog.xml"), None)
        if xml_path is None:
            raise RuntimeError("catalog CAB did not contain DriverPackCatalog.xml")
        progress.report(f"parsing {xml_path.stat().st_size // (1<<20)} MB XML")

        rows: dict[str, dict] = {}  # keyed by path (dedupe)
        considered = 0
        kept = 0
        try:
            ctx = ET.iterparse(str(xml_path), events=("end",))
            for _, elem in ctx:
                if _localtag(elem.tag) != "DriverPackage":
                    continue
                considered += 1
                row = _parse_driver_package(elem)
                elem.clear()
                if row is None:
                    continue
                if not _is_x64_windows(row):
                    continue
                if self.min_date and (row.get("date_time") or "") < self.min_date:
                    continue
                if row["path"] in rows:
                    continue
                rows[row["path"]] = row
                kept += 1
        except ET.ParseError as e:
            raise RuntimeError(f"DriverPackCatalog.xml parse failed: {e}") from e

        progress.report(f"catalog scan: {considered} packs · {kept} x64/win kept")

        kept_rows = sorted(
            rows.values(),
            key=lambda r: (r.get("date_time") or ""),
            reverse=True,
        )
        urls = [self._url_for(r["path"]) for r in kept_rows]
        url_source = {self._url_for(r["path"]): r for r in kept_rows}

        total_bytes = sum(r.get("size_bytes", 0) for r in kept_rows)
        info = {
            "discovery_page": self.catalog_url,
            "installer_url": None,
            "catalog_sha256": rec["sha256"],
            "catalog_size": rec["size"],
            "catalog_final_url": rec["final_url"],
            "packs_considered": considered,
            "packs_kept": kept,
            "total_bytes_advertised": total_bytes,
            "min_date_filter": self.min_date or None,
        }
        self._save_discovery_cache(info, urls, url_source)
        self._urls = urls[: self.max_packs] if self.max_packs else urls
        self._url_source = url_source
        info["discovery_cache"] = {
            "hit": False,
            "saved_at": C.utc_now(),
            "cached_url_count": len(urls),
            "used_url_count": len(self._urls),
            "path": str(self._discovery_cache_path()),
        }

        try:
            C.prune_dir(work_dir)
        except Exception:
            pass

        return info

    # ----- acquire -----

    def _processed_ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_processed(self) -> set[str]:
        if os.environ.get("PDT_DDP_REFRESH", "") not in ("", "0", "false"):
            return set()
        p = self._processed_ledger_path()
        if not p.exists():
            return set()
        done: set[str] = set()
        try:
            with p.open("r", encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                        if u := rec.get("url"):
                            done.add(u)
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
        return done

    def _mark_processed(self, url: str, status: str, extra: dict | None = None) -> None:
        p = self._processed_ledger_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        rec = {"url": url, "status": status, "ts": C.utc_now()}
        if extra:
            rec.update(extra)
        with self._ledger_lock:
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _acquire_one(self, work_dir: Path, url: str) -> list[dict]:
        src = self._url_source.get(url, {})
        adv_size = int(src.get("size_bytes") or 0)
        if adv_size and adv_size > self.max_mb * (1 << 20):
            self._mark_processed(url, "skipped_oversized",
                                 {"size": adv_size, "max_mb": self.max_mb})
            return []
        fname = Path(url.rsplit("/", 1)[-1]).name or "pack.cab"
        pkg_dir = work_dir / "packages" / hashlib.sha1(url.encode()).hexdigest()[:12]
        pkg_dir.mkdir(parents=True, exist_ok=True)
        pkg = pkg_dir / fname
        extracted = pkg_dir / "extracted"
        try:
            rec = C.download(url, pkg, self.allowed_hosts,
                             max_mb=self.max_mb, timeout=1800,
                             referer="https://www.dell.com/support/home/")
        except Exception as e:
            self._mark_processed(url, "download_failed", {"error": str(e)})
            C.prune_dir(pkg_dir)
            return []
        try:
            C.extract(pkg, extracted, timeout=1200)
        except Exception as e:
            self._mark_processed(url, "extract_failed",
                                 {"error": str(e), "sha256": rec["sha256"]})
            C.prune_dir(pkg_dir)
            return []
        rows = C.collect_sys_files(extracted, config.drivers_dir())
        # EXE packs (SFX) and some CABs wrap further installers inside — a
        # couple of nested passes picks those up without recursing forever.
        tries = 0
        while tries < 2:
            produced = C.extract_nested(extracted, timeout=600)
            if not produced:
                break
            new = C.collect_sys_files(extracted, config.drivers_dir())
            seen = {r["sha256"] for r in rows}
            rows.extend(r for r in new if r["sha256"] not in seen)
            tries += 1
        for r in rows:
            r["provenance"] = {
                "installer_sha256": rec["sha256"],
                "installer_size": rec["size"],
                "installer_final_url": rec["final_url"],
                "dell_path": src.get("path"),
                "dell_name": src.get("name"),
                "dell_format": src.get("format"),
                "dell_release_id": src.get("release_id"),
                "dell_version": src.get("vendor_version"),
                "dell_dell_version": src.get("dell_version"),
                "dell_date_time": src.get("date_time"),
                "dell_md5": src.get("md5"),
                "dell_os_codes": src.get("os_codes"),
            }
        self._mark_processed(url, "ok", {
            "sha256": rec["sha256"],
            "drivers": len(rows),
        })
        C.prune_dir(pkg_dir)
        return rows

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        if not self._urls:
            progress.report("discovery produced no pack URLs; nothing to acquire")
            return []
        done = self._load_processed()
        todo = [u for u in self._urls if u not in done]
        if not todo:
            progress.report(f"all {len(self._urls)} packs already processed; nothing new")
            return []
        progress.report(f"acquiring {len(todo)} pack(s) "
                        f"({len(done)} already in ledger)")

        rows: list[dict] = []
        workers = max(1, min(self.jobs, len(todo)))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self._acquire_one, work_dir, u): u for u in todo}
            done_count = 0
            for fut in as_completed(futs):
                done_count += 1
                try:
                    rows.extend(fut.result())
                except Exception as e:
                    self._mark_processed(futs[fut], "crash", {"error": str(e)})
                progress.report(
                    f"packs: {done_count}/{len(todo)} · "
                    f"{len(rows)} driver record(s) emitted"
                )
        return rows


def collector() -> DellDriverPackCollector:
    return DellDriverPackCollector()
