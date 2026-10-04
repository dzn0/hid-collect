"""Dell driver catalog — HID / mouse / keyboard / touchpad DUP collector.

Dell publishes a single CAB (`https://downloads.dell.com/catalog/CatalogPC.cab`)
whose `CatalogPC.xml` is a structured manifest of every DUP (Dell Update
Package) Dell has ever shipped: per-model, per-OS, with category taxonomy, size,
MD5, and the relative download path on `dl.dell.com`. ~3 MB compressed,
~1-2 GB XML uncompressed; we stream-parse with `iterparse` so memory stays flat.

Flow:

  1. `discover()`:
       - download `CatalogPC.cab` (small; validated by magic).
       - 7-Zip extract -> `CatalogPC.xml`.
       - stream-parse: for every `<SoftwareComponent>`, read `path`, `size`,
         `hashMD5`, `vendorVersion`, `releaseDate`, Category/Display, and
         SupportedOperatingSystems. Keep rows whose Category matches the HID
         shape (Input, Mouse, Keyboard, Pointing, Touchpad, Human Interface
         Device) AND whose OS set includes a Windows x64 release.
       - dedupe by relative `path` (same DUP binds to many systemIDs).
       - cache the resolved URL universe for reuse.

  2. `acquire()`:
       - download each DUP `.exe` under `PDT_DELL_MAX_MB` (default 100).
       - 7-Zip extract. Dell DUPs are self-extracting; a nested `.cab` /
         `.msi` usually falls out. The existing `extract_nested` helper
         handles the second stage. `.sys` files land in the content-addressed
         store exactly like every other collector.

Everything static: no DUP is executed, host allowlist enforced, cert check never
disabled, magic validated. HTTPS only.

Environment knobs:
- `PDT_DELL_CATALOG_URL`     (str)      default: official downloads.dell.com URL
- `PDT_DELL_CATEGORIES`      (`;` sep)  default: curated HID category set
- `PDT_DELL_JOBS`            (int)      default: 6 (download workers)
- `PDT_DELL_MAX_PACKS`       (int)      default: 0 (unlimited)
- `PDT_DELL_MAX_MB`          (int)      default: 100 (per DUP .exe)
- `PDT_DELL_REFRESH=1`                  ignore download ledger
- `PDT_DELL_REFRESH_DISCOVERY=1`        ignore discovery cache
- `PDT_DELL_DISCOVERY_TTL_DAYS` (int)   default: 7
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


CATALOG_URL = "https://downloads.dell.com/catalog/CatalogPC.cab"
ALLOWED_HOSTS = ["downloads.dell.com", "dl.dell.com", "ftp.dell.com"]

# Dell category Display text we care about. Match is case-insensitive substring
# against the <Category><Display> text (and we also check SoftwareComponent's
# @type attribute for "DRVR"). Keep this list broad: Dell has reshuffled the
# category taxonomy multiple times.
DEFAULT_CATEGORIES = (
    "Input",
    "Mouse",
    "Keyboard",
    "Pointing",
    "Touchpad",
    "ClickPad",
    "Trackpad",
    "Human Interface Device",
    "HID",
    "Chipset",            # some Dell TP filter drivers live in Chipset
    "Mobile Broadband",   # excluded by Windows x64 OS gate below if irrelevant
)

# Dell DUPs declare their payload shape via the `packageType` attribute on
# <SoftwareComponent>, not via osCode (which uses a confusing per-generation
# shorthand: W10P4, W21H4, W7HP6, …). The two values that ship a Windows x86/x64
# payload are `LW64` (pure x64 DUP) and `LWXP` (legacy universal DUP that holds
# both x86 and x64 trees). Both yield .sys worth looking at; the pipeline
# naturally gates on `arch=x64` later via triage. Anything else (`LCA`, …) is
# Linux / firmware and ships no .sys.
WIN_PACKAGE_TYPES = frozenset({"LW64", "LWXP"})

# Dell catalog uses an XML namespace; strip it uniformly on tag lookup.
RX_NS = re.compile(r"^\{[^}]+\}")

# Fallback name heuristic for the few DUPs that live in oddball categories
# (Communications, Camera, …) but ship HID stacks. Word-boundary matching to
# avoid substring false positives like "openmanage" matching "pen".
RX_HID_NAME = re.compile(
    r"\b("
    r"mouse|mice|keyboard|kbd|touchpad|clickpad|trackpad|"
    r"pointing|stylus|digitizer|hid|"
    r"precision\s*touchpad|input\s*device|human\s*interface"
    r")\b",
    re.I,
)


def _localtag(tag: str) -> str:
    return RX_NS.sub("", tag)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_str_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    items = [s.strip() for s in raw.split(";") if s.strip()]
    return tuple(items) if items else default


def _text_of(elem, local: str) -> str:
    """Return the first descendant's text whose local tag == `local`, else ""."""
    for ch in elem.iter():
        if _localtag(ch.tag) == local:
            return (ch.text or "").strip()
    return ""


def _parse_component(elem) -> dict | None:
    """Extract {path, size, md5, name, categories, os_codes, vendor_version}
    from a `<SoftwareComponent>` XML element, or None if the shape is wrong.

    Dell catalog layout (relevant subset):

      <SoftwareComponent path="FOLDER_XXX/foo.exe" size="12345" hashMD5="..."
                         vendorVersion="1.2.3" releaseDate="..." packageType="LWXP">
        <Name><Display lang="en">Dell Touchpad Driver</Display></Name>
        <Category><Display lang="en">Input</Display></Category>
        <SupportedOperatingSystems>
          <OperatingSystem osCode="WT64" osVendor="Microsoft" .../>
          ...
        </SupportedOperatingSystems>
        <SupportedSystems>
          <Brand><Model systemID="07AB" .../> ...</Brand>
        </SupportedSystems>
      </SoftwareComponent>
    """
    attrs = elem.attrib
    rel = attrs.get("path") or ""
    if not rel or not rel.lower().endswith((".exe", ".cab", ".msi", ".zip")):
        return None
    # Name display (English preferred, else first available)
    name_en = ""
    for child in elem.iter():
        if _localtag(child.tag) != "Name":
            continue
        for d in child.iter():
            if _localtag(d.tag) == "Display":
                if (d.attrib.get("lang") or "").lower().startswith("en"):
                    name_en = (d.text or "").strip()
                    break
                if not name_en:
                    name_en = (d.text or "").strip()
        break
    # Category display (English preferred)
    cat_en = ""
    for child in elem.iter():
        if _localtag(child.tag) != "Category":
            continue
        for d in child.iter():
            if _localtag(d.tag) == "Display":
                if (d.attrib.get("lang") or "").lower().startswith("en"):
                    cat_en = (d.text or "").strip()
                    break
                if not cat_en:
                    cat_en = (d.text or "").strip()
        break
    # Supported OS codes
    os_codes: list[str] = []
    for os_elem in elem.iter():
        if _localtag(os_elem.tag) == "OperatingSystem":
            code = os_elem.attrib.get("osCode") or ""
            if code:
                os_codes.append(code)
    size_bytes = 0
    try:
        size_bytes = int(attrs.get("size") or "0")
    except ValueError:
        pass
    return {
        "path": rel.replace("\\", "/"),
        "size_bytes": size_bytes,
        "md5": (attrs.get("hashMD5") or "").lower(),
        "vendor_version": attrs.get("vendorVersion") or "",
        "release_date": attrs.get("releaseDate") or "",
        "package_type": attrs.get("packageType") or "",
        "name": name_en,
        "category": cat_en,
        "os_codes": os_codes,
    }


def _matches_hid_shape(row: dict, wanted_cats: tuple[str, ...]) -> bool:
    cat = (row.get("category") or "").lower()
    name = (row.get("name") or "")
    # Category match (substring, case-insensitive)
    for wc in wanted_cats:
        if wc.lower() in cat:
            return True
    # Fallback: HID-shaped keyword in the DUP's display name, with word
    # boundaries so "openmanage" does not pretend to be a pen driver.
    return bool(RX_HID_NAME.search(name))


def _is_windows_payload(row: dict) -> bool:
    """True iff Dell marks this DUP as a Windows installer (x86 and/or x64).

    Dell's `packageType` is the authoritative payload-shape flag; osCode is a
    per-generation shorthand that is messy to pattern-match (W10P4, W21H4,
    W7HP6, …) and misleads: a DUP flagged for a single modern osCode is
    always x64 even when nothing in the osCode string literally contains '64'.
    """
    return (row.get("package_type") or "") in WIN_PACKAGE_TYPES


class DellCatalogPcCollector(Collector):
    name = "dell-catalog-pc"
    role = "Dell CatalogPC — HID / mouse / keyboard / touchpad DUPs"
    allowed_hosts = list(ALLOWED_HOSTS)

    def __init__(self) -> None:
        self.catalog_url = os.environ.get("PDT_DELL_CATALOG_URL", CATALOG_URL)
        self.wanted_cats = _env_str_list("PDT_DELL_CATEGORIES", DEFAULT_CATEGORIES)
        self.jobs = _env_int("PDT_DELL_JOBS", 6)
        self.max_packs = _env_int("PDT_DELL_MAX_PACKS", 0)
        self.max_mb = _env_int("PDT_DELL_MAX_MB", 100)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._url_source: dict[str, dict] = {}

    # ----- discovery -----

    def _url_for(self, rel_path: str) -> str:
        # Dell catalog path is relative; the manifest's baseLocation is
        # downloads.dell.com, but Dell silently serves the same tree on
        # dl.dell.com too. Use downloads.dell.com (matches the HEAD / HTTPS
        # cert of the catalog host) so the allowlist check stays tight.
        return "https://downloads.dell.com/" + rel_path.lstrip("/")

    def _config_fingerprint(self) -> str:
        payload = json.dumps(
            {"catalog": self.catalog_url,
             "cats": sorted(c.lower() for c in self.wanted_cats)},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def _discovery_cache_path(self) -> Path:
        return (config.collectors_dir() / self.name /
                f"discovery_cache_{self._config_fingerprint()}.json")

    def _load_discovery_cache(self) -> dict | None:
        if os.environ.get("PDT_DELL_REFRESH_DISCOVERY", "") not in ("", "0", "false"):
            return None
        p = self._discovery_cache_path()
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        ttl_days = _env_int("PDT_DELL_DISCOVERY_TTL_DAYS", 7)
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
            "wanted_categories": list(self.wanted_cats),
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
            progress.report(f"discovery cache hit: {len(self._urls)} DUP URLs")
            return info

        work_dir = config.collectors_dir() / self.name / "_discovery"
        work_dir.mkdir(parents=True, exist_ok=True)

        # 1. Download CatalogPC.cab
        cab = work_dir / "CatalogPC.cab"
        progress.report("downloading CatalogPC.cab")
        rec = C.download(self.catalog_url, cab, self.allowed_hosts,
                         max_mb=50, timeout=90)

        # 2. Extract -> CatalogPC.xml
        xml_dir = work_dir / "xml"
        for p in xml_dir.glob("*"):
            try:
                p.unlink()
            except OSError:
                pass
        xml_dir.mkdir(parents=True, exist_ok=True)
        C.extract(cab, xml_dir, timeout=240)
        xml_path = next(xml_dir.rglob("CatalogPC.xml"), None)
        if xml_path is None:
            raise RuntimeError("CatalogPC.cab did not contain CatalogPC.xml")
        progress.report(f"parsing {xml_path.stat().st_size // (1<<20)} MB XML")

        # 3. Stream-parse. Dell's root element is <Manifest>, and each DUP is a
        # <SoftwareComponent>. We iterparse on "end", process + clear each
        # component to keep memory flat.
        rows: dict[str, dict] = {}  # keyed by relative path (dedupe)
        considered = 0
        kept = 0
        try:
            ctx = ET.iterparse(str(xml_path), events=("end",))
            for _, elem in ctx:
                if _localtag(elem.tag) != "SoftwareComponent":
                    continue
                considered += 1
                row = _parse_component(elem)
                elem.clear()
                if row is None:
                    continue
                if not _is_windows_payload(row):
                    continue
                if not _matches_hid_shape(row, self.wanted_cats):
                    continue
                if row["path"] in rows:
                    # keep highest vendorVersion / newest release — but
                    # since we dedupe later by sha256 across all collectors,
                    # first-wins is fine.
                    continue
                rows[row["path"]] = row
                kept += 1
                if kept % 50 == 0:
                    progress.report(
                        f"catalog scan: {considered} components · "
                        f"{kept} HID-shaped kept"
                    )
        except ET.ParseError as e:
            raise RuntimeError(f"CatalogPC.xml parse failed: {e}") from e

        progress.report(f"catalog scan: {considered} components · {kept} HID-shaped kept")

        # 4. Build URL list, preserving the newest-first ordering by releaseDate
        kept_rows = sorted(
            rows.values(),
            key=lambda r: (r.get("release_date") or ""),
            reverse=True,
        )
        urls = [self._url_for(r["path"]) for r in kept_rows]
        url_source = {self._url_for(r["path"]): r for r in kept_rows}

        info = {
            "discovery_page": self.catalog_url,
            "installer_url": None,
            "catalog_sha256": rec["sha256"],
            "catalog_size": rec["size"],
            "catalog_final_url": rec["final_url"],
            "components_considered": considered,
            "components_kept": kept,
            "wanted_categories": list(self.wanted_cats),
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

        # 5. Clean the extraction tree — the CAB and XML are big and already
        # digested into the discovery cache.
        try:
            C.prune_dir(work_dir)
        except Exception:
            pass

        return info

    # ----- acquire -----

    def _processed_ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_processed(self) -> set[str]:
        if os.environ.get("PDT_DELL_REFRESH", "") not in ("", "0", "false"):
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
        fname = Path(url.rsplit("/", 1)[-1]).name or "dup.exe"
        pkg_dir = work_dir / "packages" / hashlib.sha1(url.encode()).hexdigest()[:12]
        pkg_dir.mkdir(parents=True, exist_ok=True)
        pkg = pkg_dir / fname
        extracted = pkg_dir / "extracted"
        try:
            rec = C.download(url, pkg, self.allowed_hosts,
                             max_mb=self.max_mb, timeout=180,
                             referer="https://www.dell.com/support/home/")
        except Exception as e:
            self._mark_processed(url, "download_failed", {"error": str(e)})
            C.prune_dir(pkg_dir)
            return []
        try:
            C.extract(pkg, extracted, timeout=300)
        except Exception as e:
            self._mark_processed(url, "extract_failed",
                                 {"error": str(e), "sha256": rec["sha256"]})
            C.prune_dir(pkg_dir)
            return []
        rows = C.collect_sys_files(extracted, config.drivers_dir())
        tries = 0
        while not rows and tries < 2:
            produced = C.extract_nested(extracted, timeout=300)
            if not produced:
                break
            rows = C.collect_sys_files(extracted, config.drivers_dir())
            tries += 1
        for r in rows:
            r["provenance"] = {
                "installer_sha256": rec["sha256"],
                "installer_size": rec["size"],
                "installer_final_url": rec["final_url"],
                "dell_path": src.get("path"),
                "dell_name": src.get("name"),
                "dell_category": src.get("category"),
                "dell_version": src.get("vendor_version"),
                "dell_release_date": src.get("release_date"),
                "dell_md5": src.get("md5"),
            }
        self._mark_processed(url, "ok", {
            "sha256": rec["sha256"],
            "drivers": len(rows),
        })
        C.prune_dir(pkg_dir)
        return rows

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        if not self._urls:
            progress.report("discovery produced no DUP URLs; nothing to acquire")
            return []
        done = self._load_processed()
        todo = [u for u in self._urls if u not in done]
        if not todo:
            progress.report(f"all {len(self._urls)} DUPs already processed; nothing new")
            return []
        progress.report(f"acquiring {len(todo)} DUP(s) "
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
                    # _acquire_one captures its own errors; this is belt+braces
                    self._mark_processed(futs[fut], "crash", {"error": str(e)})
                progress.report(
                    f"DUPs: {done_count}/{len(todo)} · "
                    f"{len(rows)} driver record(s) emitted"
                )
        return rows


def collector() -> DellCatalogPcCollector:
    return DellCatalogPcCollector()
