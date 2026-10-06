"""OEM driver-catalog collector — Dell + HP input-device drivers.

Dell and HP publish machine-readable driver catalogs built for mass enterprise
deployment (SCCM/MDT). They share the properties that make the Microsoft Update
Catalog worth crawling — **no rate limiting** (the CDNs are designed for fleet
downloads) and **real kernel `.sys`** inside each package — but they are plain
XML with direct CDN URLs, so no browser/pagination is needed at all.

Two component-level sources (whole-machine "driver packs" are deliberately NOT
used — they are gigabytes each and overlap massively):

  * Dell  — `downloads.dell.com/catalog/CatalogPC.cab` → `CatalogPC.xml`
            (UTF-16). Each `<SoftwareComponent path=… >` with
            `<Category value="IN">` (Input) and `<ComponentType value="DRVR">`
            is a Dell Update Package (.EXE, self-extracting). Download URL is
            `downloads.dell.com/` + `path`.
  * HP    — `hpia.hpcloud.hp.com/downloads/sccmcatalog/HpCatalogForSms.latest.cab`
            → `HpCatalogForSms.xml` (SCCM SDP schema). Each
            `<smc:SoftwareDistributionPackage>` whose `<sdp:Title>` matches the
            input shape carries a direct `ftp.hp.com/pub/softpaq/…​.exe` SoftPaq.

Lenovo is intentionally omitted: its catalog (`catalogv2.xml`) is model-level
only (one whole-machine pack per laptop), with no component granularity.

Acquisition reuses the shared content-addressed store, resume ledger and 7-Zip
extraction. Every package is a self-extracting installer; `.sys` are harvested
after extraction (with one nested pass for installer-in-installer). Nothing is
executed — binaries are parsed as bytes downstream in pipeline.index.

Environment knobs:
- `PDT_VC_SOURCES`           (`,` separated)   default: "dell,hp"
- `PDT_VC_JOBS`              (int)             default: 8 (download workers)
- `PDT_VC_MAX_PACKS`         (int)             default: 0 (unlimited)
- `PDT_VC_MAX_MB`            (int)             default: 300 (per package)
- `PDT_VC_REFRESH=1`                           ignore download ledger
- `PDT_VC_REFRESH_DISCOVERY=1`                 ignore discovery cache
- `PDT_VC_DISCOVERY_TTL_DAYS` (int)            default: 7
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import config
from .. import progress
from .base import Collector
from . import _common as C


DELL_CATALOG = "https://downloads.dell.com/catalog/CatalogPC.cab"
DELL_BASE = "https://downloads.dell.com/"
HP_CATALOG = "https://hpia.hpcloud.hp.com/downloads/sccmcatalog/HpCatalogForSms.latest.cab"

ALLOWED = ["downloads.dell.com", "dl.dell.com", "ftp.hp.com", "hpia.hpcloud.hp.com"]

# Input-device shape for keyword filtering. Dell's Category="IN" already scopes
# well; this also drops the occasional miscategorized camera/IR entry, and it is
# the primary filter for HP (which we match on package title).
RX_INPUT = re.compile(
    r"touchpad|clickpad|trackpad|trackball|point(?:ing|stick)|\bmouse\b|"
    r"keyboard|\bHID\b|digitizer|stylus|\bpen\b|touchscreen|glidepoint|"
    r"precision\s*touchpad|synaptics|elan|alps|cirque",
    re.I,
)
# Things that ride the Input category but are not input drivers.
RX_INPUT_DENY = re.compile(r"camera|webcam|\bIR\b|fingerprint|audio|realtek\s+ir", re.I)

# Dell CatalogPC.xml
RX_DELL_COMP = re.compile(r"<SoftwareComponent\b.*?</SoftwareComponent>", re.S)
RX_DELL_PATH = re.compile(r'\bpath="([^"]+)"')
RX_DELL_SIZE = re.compile(r'\bsize="(\d+)"')
RX_DELL_VER = re.compile(r'\bvendorVersion="([^"]*)"')
RX_DELL_CAT = re.compile(r'<Category value="IN"')
RX_DELL_DRVR = re.compile(r'<ComponentType value="DRVR"')
RX_DELL_NAME = re.compile(r"<Name>\s*<Display[^>]*><!\[CDATA\[([^\]]+)")

# HP SCCM SDP
RX_HP_SDP = re.compile(
    r"<smc:SoftwareDistributionPackage\b.*?</smc:SoftwareDistributionPackage>", re.S)
RX_HP_TITLE = re.compile(r"<sdp:Title>([^<]+)</sdp:Title>")
RX_HP_URL = re.compile(r'(https?://ftp\.hp\.com/[^\s"<]+?\.exe)', re.I)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _decode(raw: bytes) -> str:
    enc = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
    return raw.decode(enc, "replace")


class VendorCatalogCollector(Collector):
    name = "vendor-catalog"
    role = "Dell/HP OEM input-device driver catalogs (SCCM/MDT CDNs)"
    allowed_hosts = list(ALLOWED)

    def __init__(self) -> None:
        raw = os.environ.get("PDT_VC_SOURCES", "dell,hp")
        self.sources = [s.strip().lower() for s in raw.split(",") if s.strip()]
        self.jobs = _env_int("PDT_VC_JOBS", 8)
        self.max_packs = _env_int("PDT_VC_MAX_PACKS", 0)
        self.max_mb = _env_int("PDT_VC_MAX_MB", 300)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._url_source: dict[str, dict] = {}

    # ----- catalog fetch -----

    def _catalog_xml(self, url: str, slug: str) -> str:
        """Download a catalog .cab and return its extracted .xml text."""
        d = config.collectors_dir() / self.name / "_catalogs" / slug
        cab = d / "catalog.cab"
        C.download(url, cab, self.allowed_hosts, max_mb=200, timeout=120)
        out = d / "x"
        C.extract(cab, out)
        xmls = sorted(out.rglob("*.xml"), key=lambda p: p.stat().st_size, reverse=True)
        if not xmls:
            raise RuntimeError(f"{slug}: no .xml inside {url}")
        return _decode(xmls[0].read_bytes())

    # ----- discovery -----

    def _discover_dell(self) -> list[dict]:
        progress.report("dell: fetching CatalogPC.cab")
        xml = self._catalog_xml(DELL_CATALOG, "dell")
        out: list[dict] = []
        for comp in RX_DELL_COMP.finditer(xml):
            c = comp.group(0)
            if not (RX_DELL_CAT.search(c) and RX_DELL_DRVR.search(c)):
                continue
            nm = RX_DELL_NAME.search(c)
            name = nm.group(1) if nm else ""
            if not RX_INPUT.search(name) or RX_INPUT_DENY.search(name):
                continue
            p = RX_DELL_PATH.search(c)
            if not p:
                continue
            url = DELL_BASE + p.group(1)
            sz = RX_DELL_SIZE.search(c)
            ver = RX_DELL_VER.search(c)
            out.append({"url": url, "vendor": "dell", "title": name,
                        "version": ver.group(1) if ver else None,
                        "size_bytes": int(sz.group(1)) if sz else 0})
        progress.report(f"dell: {len(out)} input driver package(s)")
        return out

    def _discover_hp(self) -> list[dict]:
        progress.report("hp: fetching HpCatalogForSms.latest.cab")
        xml = self._catalog_xml(HP_CATALOG, "hp")
        out: list[dict] = []
        for blk in RX_HP_SDP.finditer(xml):
            b = blk.group(0)
            t = RX_HP_TITLE.search(b)
            title = t.group(1) if t else ""
            if not RX_INPUT.search(title) or RX_INPUT_DENY.search(title):
                continue
            u = RX_HP_URL.search(b)
            if not u:
                continue
            out.append({"url": u.group(1), "vendor": "hp", "title": title,
                        "version": None, "size_bytes": 0})
        progress.report(f"hp: {len(out)} input driver package(s)")
        return out

    def _config_fingerprint(self) -> str:
        payload = json.dumps({"sources": sorted(self.sources)}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def _discovery_cache_path(self) -> Path:
        return (config.collectors_dir() / self.name /
                f"discovery_cache_{self._config_fingerprint()}.json")

    def _load_discovery_cache(self) -> dict | None:
        if os.environ.get("PDT_VC_REFRESH_DISCOVERY", "") not in ("", "0", "false"):
            return None
        p = self._discovery_cache_path()
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        ttl_days = _env_int("PDT_VC_DISCOVERY_TTL_DAYS", 7)
        if time.time() - float(data.get("saved_at_epoch", 0)) > ttl_days * 86400:
            return None
        return data

    def _save_discovery_cache(self, urls: list[str], url_source: dict) -> None:
        p = self._discovery_cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "schema_version": 1, "saved_at": C.utc_now(),
            "saved_at_epoch": time.time(), "sources": list(self.sources),
            "urls": urls, "url_source": url_source,
        }, ensure_ascii=False), encoding="utf-8")

    def discover(self) -> dict:
        cached = self._load_discovery_cache()
        if cached is not None:
            self._urls = list(cached["urls"])
            self._url_source = dict(cached["url_source"])
            if self.max_packs:
                self._urls = self._urls[: self.max_packs]
            progress.report(f"discovery cache hit: {len(self._urls)} package URLs")
            return {"discovery_page": None, "installer_url": None,
                    "sources": list(self.sources), "packs_resolved": len(self._urls),
                    "discovery_cache": {"hit": True, "saved_at": cached.get("saved_at")}}

        rows: list[dict] = []
        if "dell" in self.sources:
            rows += self._discover_dell()
        if "hp" in self.sources:
            rows += self._discover_hp()

        seen: set[str] = set()
        urls: list[str] = []
        url_source: dict[str, dict] = {}
        for r in rows:
            u = r["url"]
            if u in seen:
                continue
            seen.add(u)
            urls.append(u)
            url_source[u] = r
        self._urls = urls[: self.max_packs] if self.max_packs else urls
        self._url_source = url_source
        self._save_discovery_cache(urls, url_source)
        return {"discovery_page": None, "installer_url": None,
                "sources": list(self.sources), "packs_resolved": len(urls),
                "jobs": self.jobs, "max_mb": self.max_mb,
                "discovery_cache": {"hit": False, "saved_at": C.utc_now()}}

    # ----- acquisition -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_VC_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(self._urls), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}
        rep_fn, cnt_fn, slot_fn = progress.current_reporters()

        def key_of(url: str) -> str:
            return urllib.parse.unquote(urllib.parse.urlparse(url).path)

        def handle(url: str) -> None:
            progress.set_reporter(rep_fn)
            progress.set_count_reporter(cnt_fn)
            if slot_fn is not None:
                progress.set_slot_reporter(slot_fn)
            slot_id = f"vc-{threading.get_ident()}"
            src = self._url_source.get(url, {})
            progress.set_slot(slot_id, (src.get("title") or "pkg")[:18])
            try:
                key = key_of(url)
                if key in processed:
                    with self._lock:
                        stats["skipped_seen"] += 1
                    return
                with self._lock:
                    processed.add(key)
                    stats["attempted"] += 1
                got, rec = self._fetch(work_dir, url)
                if got is None:
                    self._record(key, url, [], status="failed")
                    with self._lock:
                        stats["failed"] += 1
                        errors.append({"url": url, "error": rec})
                    return
                with self._lock:
                    if rec:
                        downloads.append(rec)
                    rows.extend(got)
                    stats["packages"] += 1
                    stats["sys"] += len(got)
                    if not got:
                        stats["no_sys"] += 1
                self._record(key, url, [r["sha256"] for r in got],
                             status="ok" if got else "no_sys")
            finally:
                progress.clear_slot()

        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            list(pool.map(handle, self._urls))

        info["stats"] = stats
        info["errors"] = errors[:500]
        info["error_count"] = len(errors)
        info["downloads_top"] = downloads
        info["ledger_at_start"] = len(processed)
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    def _fetch(self, work_dir: Path, url: str):
        src = self._url_source.get(url, {})
        name = Path(urllib.parse.urlparse(url).path).name
        slug = hashlib.sha1(url.encode()).hexdigest()[:16]
        folder = work_dir / "packages" / slug
        pkg = folder / name
        progress.report(f"pack: {name[:48]}")
        try:
            rec = C.download(url, pkg, self.allowed_hosts, max_mb=self.max_mb,
                             timeout=240)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        extracted = folder / "extracted"
        try:
            C.extract(pkg, extracted)
            try:
                pkg.unlink()
            except OSError:
                pass
            got = C.collect_sys_files(folder, config.drivers_dir(),
                                      include_native_pe=True)
            if not got and C.extract_nested(extracted):
                got = C.collect_sys_files(folder, config.drivers_dir(),
                                          include_native_pe=True)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        vendor = src.get("vendor", "")
        aggregator = {"dell": "downloads.dell.com",
                      "hp": "ftp.hp.com"}.get(vendor, vendor)
        for r in got:
            r["provenance"] = {
                "source_kind": f"oem-catalog-{vendor}" if vendor else "oem-catalog",
                "aggregator": aggregator,
                "trust_note": "vendor-signed driver package from the OEM's "
                              "enterprise deployment CDN",
                "vendor": vendor,
                "update_title": src.get("title"),
                "update_version": src.get("version"),
                "package_name": name,
                "package_url": url,
                "package_final_url": rec["final_url"],
                "package_sha256": rec["sha256"],
                "package_size": rec["size"],
            }
            C.append_index(config.drivers_dir(),
                           {"sha256": r["sha256"], "provenance": r["provenance"]})
        C.prune_dir(folder)
        return got, rec

    # ----- resume ledger -----

    def _ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_ledger(self) -> set[str]:
        retry_failed = os.environ.get("PDT_VC_RETRY_FAILED", "") \
            not in ("", "0", "false")
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
                if retry_failed and entry.get("status") == "failed":
                    continue
                if entry.get("key"):
                    seen.add(entry["key"])
        return seen

    def _record(self, key: str, url: str, sys_shas: list[str], *, status: str) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"key": key, "url": url, "status": status,
                                    "sys": sys_shas, "ts": C.utc_now()},
                                   ensure_ascii=False) + "\n")


def collector() -> VendorCatalogCollector:
    return VendorCatalogCollector()
