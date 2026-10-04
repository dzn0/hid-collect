"""HP enterprise driver pack collector.

HP publishes one catalog CAB:
    https://ftp.hp.com/pub/caps-softpaq/cmit/HPClientDriverPackCatalog.cab

(185 KB; wraps `HPClientDriverPackCatalog.xml`, ~2 MB.) The XML lists ~780
`<SoftPaq>` entries — one *enterprise driver pack* per model/OS. Each pack is
a self-extracting `.exe` on `ftp.hp.com/pub/softpaq/sp<N>-<M>/sp<ID>.exe`,
median ~1 GB, max ~4 GB, and when unpacked yields a whole model's WHQL-signed
driver tree (chipset, HID, net, video, audio, …). Catalog advertises ~860 GB
total.

For an input-driver corpus this is a honeypot: enterprise packs include
touchpad / keyboard / HID bus / HID OEM-specific stacks across many vendors
and generations, deduped by sha256 across every other collector. Yield per
pack is high (dozens of drivers, 5-15 new-to-corpus after dedup).

Flow:

  1. `discover()`:
       - download `HPClientDriverPackCatalog.cab` (185 KB; small).
       - 7-Zip extract -> `HPClientDriverPackCatalog.xml`.
       - stream-parse `<SoftPaq>` -> {id, name, version, category, date, url,
         size, md5, sha256}.
       - rank newest-first by DateReleased; dedupe by Url.
       - cache the resolved URL universe for reuse.

  2. `acquire()`:
       - download each pack `.exe` under `PDT_HP_MAX_MB` (default 4000).
       - 7-Zip extract. HP packs are SFX; a top-level DP root falls out with
         per-category subdirs (`Driver\...`). `collect_sys_files` walks the
         whole tree. One `extract_nested` round picks up any wrapped MSI/CAB.

Everything static: no pack is executed, host allowlist enforced, cert check
never disabled, magic validated. HTTPS only. Transient disk per worker ~=
pack + its extraction (~2-4x pack size), so `PDT_HP_JOBS` defaults to 2.

Environment knobs:
- `PDT_HP_CATALOG_URL`      (str)      default: official ftp.hp.com URL
- `PDT_HP_JOBS`             (int)      default: 2 (download+extract workers)
- `PDT_HP_MAX_PACKS`        (int)      default: 0 (unlimited)
- `PDT_HP_MAX_MB`           (int)      default: 4000 (per pack .exe)
- `PDT_HP_MIN_DATE`         (YYYY-MM)  default: unset — drop packs older than
                                       this (useful for a scoped run)
- `PDT_HP_REFRESH=1`                   ignore download ledger
- `PDT_HP_REFRESH_DISCOVERY=1`         ignore discovery cache
- `PDT_HP_DISCOVERY_TTL_DAYS` (int)    default: 7
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


CATALOG_URL = "https://ftp.hp.com/pub/caps-softpaq/cmit/HPClientDriverPackCatalog.cab"
ALLOWED_HOSTS = ["ftp.hp.com", "hpia.hpcloud.hp.com", "hpdlc.hpcloud.hp.com"]

RX_NS = re.compile(r"^\{[^}]+\}")


def _localtag(tag: str) -> str:
    return RX_NS.sub("", tag)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _parse_softpaq(elem) -> dict | None:
    """Pull {id, name, version, category, date, url, size, md5, sha256} from a
    `<SoftPaq>` element. Returns None if required fields missing."""
    fields: dict[str, str] = {}
    for ch in elem:
        fields[_localtag(ch.tag)] = (ch.text or "").strip()
    url = fields.get("Url") or ""
    sp_id = fields.get("Id") or ""
    if not url or not sp_id:
        return None
    try:
        size_bytes = int(fields.get("Size") or "0")
    except ValueError:
        size_bytes = 0
    return {
        "id": sp_id,
        "name": fields.get("Name") or "",
        "version": fields.get("Version") or "",
        "category": fields.get("Category") or "",
        "release_date": fields.get("DateReleased") or "",
        "url": url,
        "size_bytes": size_bytes,
        "md5": (fields.get("MD5") or "").lower(),
        "sha256": (fields.get("SHA256") or "").lower(),
        "cva_url": fields.get("CvaFileUrl") or "",
    }


class HpDriverPackCollector(Collector):
    name = "hp-driver-pack"
    role = "HP enterprise driver pack catalog (ftp.hp.com)"
    allowed_hosts = list(ALLOWED_HOSTS)

    def __init__(self) -> None:
        self.catalog_url = os.environ.get("PDT_HP_CATALOG_URL", CATALOG_URL)
        self.jobs = _env_int("PDT_HP_JOBS", 2)
        self.max_packs = _env_int("PDT_HP_MAX_PACKS", 0)
        self.max_mb = _env_int("PDT_HP_MAX_MB", 4000)
        self.min_date = (os.environ.get("PDT_HP_MIN_DATE") or "").strip()
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._url_source: dict[str, dict] = {}

    # ----- discovery -----

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
        if os.environ.get("PDT_HP_REFRESH_DISCOVERY", "") not in ("", "0", "false"):
            return None
        p = self._discovery_cache_path()
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        ttl_days = _env_int("PDT_HP_DISCOVERY_TTL_DAYS", 7)
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

        # 1. Download catalog CAB
        cab = work_dir / "HPClientDriverPackCatalog.cab"
        progress.report("downloading HPClientDriverPackCatalog.cab")
        rec = C.download(self.catalog_url, cab, self.allowed_hosts,
                         max_mb=50, timeout=90)

        # 2. Extract -> HPClientDriverPackCatalog.xml
        xml_dir = work_dir / "xml"
        for p in xml_dir.glob("*"):
            try:
                p.unlink()
            except OSError:
                pass
        xml_dir.mkdir(parents=True, exist_ok=True)
        C.extract(cab, xml_dir, timeout=240)
        xml_path = next(xml_dir.rglob("HPClientDriverPackCatalog.xml"), None)
        if xml_path is None:
            raise RuntimeError("catalog CAB did not contain HPClientDriverPackCatalog.xml")
        progress.report(f"parsing {xml_path.stat().st_size // (1<<20)} MB XML")

        # 3. Stream-parse. HP's root is <NewDataSet>-ish; each pack is a
        # <SoftPaq> under <SoftPaqList>. iterparse keeps memory flat even
        # though 2 MB is trivial — stay consistent with the Dell collector.
        rows: dict[str, dict] = {}  # keyed by Url (dedupe)
        considered = 0
        kept = 0
        try:
            ctx = ET.iterparse(str(xml_path), events=("end",))
            for _, elem in ctx:
                if _localtag(elem.tag) != "SoftPaq":
                    continue
                considered += 1
                row = _parse_softpaq(elem)
                elem.clear()
                if row is None:
                    continue
                if self.min_date and (row.get("release_date") or "") < self.min_date:
                    continue
                if row["url"] in rows:
                    continue
                rows[row["url"]] = row
                kept += 1
        except ET.ParseError as e:
            raise RuntimeError(f"HPClientDriverPackCatalog.xml parse failed: {e}") from e

        progress.report(f"catalog scan: {considered} softpaqs · {kept} kept")

        # 4. Sort newest-first by releaseDate
        kept_rows = sorted(
            rows.values(),
            key=lambda r: (r.get("release_date") or ""),
            reverse=True,
        )
        urls = [r["url"] for r in kept_rows]
        url_source = {r["url"]: r for r in kept_rows}

        total_bytes = sum(r.get("size_bytes", 0) for r in kept_rows)
        info = {
            "discovery_page": self.catalog_url,
            "installer_url": None,
            "catalog_sha256": rec["sha256"],
            "catalog_size": rec["size"],
            "catalog_final_url": rec["final_url"],
            "softpaqs_considered": considered,
            "softpaqs_kept": kept,
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

        # 5. Clean the catalog extraction tree
        try:
            C.prune_dir(work_dir)
        except Exception:
            pass

        return info

    # ----- acquire -----

    def _processed_ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_processed(self) -> set[str]:
        if os.environ.get("PDT_HP_REFRESH", "") not in ("", "0", "false"):
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
        # If the catalog says this pack is bigger than our cap, skip without
        # even opening a socket. Many HP packs are 2-4 GB and `max_mb` sets
        # the opt-in ceiling.
        adv_size = int(src.get("size_bytes") or 0)
        if adv_size and adv_size > self.max_mb * (1 << 20):
            self._mark_processed(url, "skipped_oversized",
                                 {"size": adv_size, "max_mb": self.max_mb})
            return []
        fname = Path(url.rsplit("/", 1)[-1]).name or "pack.exe"
        pkg_dir = work_dir / "packages" / hashlib.sha1(url.encode()).hexdigest()[:12]
        pkg_dir.mkdir(parents=True, exist_ok=True)
        pkg = pkg_dir / fname
        extracted = pkg_dir / "extracted"
        try:
            # Big packs can take tens of minutes on a slow link; raise the
            # per-download timeout from the base 90s default.
            rec = C.download(url, pkg, self.allowed_hosts,
                             max_mb=self.max_mb, timeout=1800)
        except Exception as e:
            self._mark_processed(url, "download_failed", {"error": str(e)})
            C.prune_dir(pkg_dir)
            return []
        try:
            # Extraction of a 1-2 GB SFX can take minutes.
            C.extract(pkg, extracted, timeout=1200)
        except Exception as e:
            self._mark_processed(url, "extract_failed",
                                 {"error": str(e), "sha256": rec["sha256"]})
            C.prune_dir(pkg_dir)
            return []
        rows = C.collect_sys_files(extracted, config.drivers_dir())
        # Driver packs ship CABs/MSIs inside — one nested pass picks them up.
        tries = 0
        while tries < 2:
            produced = C.extract_nested(extracted, timeout=600)
            if not produced:
                break
            new = C.collect_sys_files(extracted, config.drivers_dir())
            # dedupe by sha256 against what we've already emitted this call
            seen = {r["sha256"] for r in rows}
            rows.extend(r for r in new if r["sha256"] not in seen)
            tries += 1
        for r in rows:
            r["provenance"] = {
                "installer_sha256": rec["sha256"],
                "installer_size": rec["size"],
                "installer_final_url": rec["final_url"],
                "hp_softpaq_id": src.get("id"),
                "hp_name": src.get("name"),
                "hp_category": src.get("category"),
                "hp_version": src.get("version"),
                "hp_release_date": src.get("release_date"),
                "hp_md5": src.get("md5"),
                "hp_sha256_advertised": src.get("sha256"),
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


def collector() -> HpDriverPackCollector:
    return HpDriverPackCollector()
