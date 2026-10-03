"""TousLesDrivers.com — HID / input-peripheral collector.

Narrower than the general-purpose touslesdrivers collector in the parent
project. Instead of harvesting the home page of a hand-picked brand set, this
one enumerates **every brand** that the aggregator itself has indexed under an
input category (keyboard, mouse, graphics tablet, gamepad), then walks each
brand's **archives** (drivers + applications) and resolves direct download URLs.

Discovery flow (verified against the live site, 2026-10):

  v_page=10 & v_categorie=<N>                 → brand index for category N
                                                  10=Clavier, 11=Souris,
                                                  17=Tablette graphique, 19=Manette
  v_page=26 & v_code=<brand> & v_type=<T>     → brand archive (all packages)
                                                  T=1 drivers, T=4 applications
  v_page=23 & v_code=<pkg_id>                 → package detail page (JS-only DL)
  /php/constructeurs/telechargement.php
      ?v_code=<pkg_id>&v_langue=fr            → popup HTML, carries direct
                                                  https://fichiersN.touslesdrivers.com
                                                  archive URL

The archive page is a flat <br/>-separated list — v_categorie is accepted
on v_page=26 but *silently ignored*, so we trust the brand-level filter
and take every archived package the brand has. A webcam driver that leaks
through will get a zero scope-match at L1 and cost only its bytes.

Charset: the site declares UTF-8 (<meta charset=UTF-8>) even though some
accented strings are HTML-entity encoded; URLs themselves are ASCII, so the
regexes don't care, but brand names must be decoded as UTF-8 (unlike the
parent collector, which decodes as latin-1 and corrupts them).

Shape mirrors `base.Collector`:
  1. discover():
       - fetch 4 brand indexes (one per category) → union of brand v_codes
       - for each brand × type, fetch archive → union of package IDs
       - for each package ID, resolve popup → direct CDN URL (thread pool)
  2. acquire():
       - thread pool downloads each archive, 7z-extracts, harvests .sys
       - resume ledger keyed on URL path survives interrupted runs

Provenance: 'touslesdrivers-aggregator-input' (third-party aggregator; no
catalog (.cat) trust path assumed — authenticity left to L0 / DrvEye).

Environment knobs:
- `PDT_HID_CATEGORIES` (`,`/`;` v_categorie ints) default: `10,11,17,19`
- `PDT_HID_TYPES`      (`,`/`;` v_type ints)      default: `1,4`
- `PDT_HID_MAX_BRANDS` (int)                      default: 0 (unlimited)
- `PDT_HID_MAX_PACKS`  (int)                      default: 0 (unlimited)
- `PDT_HID_JOBS`       (int)                      default: 6
- `PDT_HID_CRAWL_JOBS` (int)                      default: 8
- `PDT_HID_MAX_MB`     (int)                      default: 60
- `PDT_HID_REFRESH=1`                             ignore download resume ledger
- `PDT_HID_DISCOVERY_TTL_DAYS` (int)              default: 7 (cache discovery)
- `PDT_HID_REFRESH_DISCOVERY=1`                   ignore discovery cache, re-walk
"""
from __future__ import annotations
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

from .. import config
from .. import progress
from .base import Collector
from . import _common as C

BASE = "https://www.touslesdrivers.com"

# Input-adjacent categories on the aggregator (verified from the archive page's
# category navigator). Keep ordering stable so manifest discovery is reproducible.
#   10 Clavier (keyboard)
#   11 Souris (mouse)
#   17 Tablette graphique (graphics tablet; HID-stylus adjacent)
#   19 Manette de jeu (gamepad)
DEFAULT_CATEGORIES = (10, 11, 17, 19)

# v_type on the archive page: 1=Drivers, 4=Applications. We take both because the
# kernel .sys often ships bundled inside the Application installer (G HUB,
# Synapse, iCUE, etc.) rather than as a standalone driver download.
DEFAULT_TYPES = (1, 4)

# Width of the brand label in each worker sub-row. Keep it compact so the
# detail (download/extract progress) has room on an 80-col terminal too.
_SLOT_LABEL_WIDTH = 18

# Extensions whose source file can be deleted once a sibling `.unpacked/` dir
# exists. Mirrors _common._NESTED_ARCHIVE_EXT. The source archive is redundant
# with its .unpacked/ sibling, so keeping both inflates the per-package working
# set 2-3× during a deep extraction chain.
_INTERMEDIATE_ARCHIVE_EXT = {".exe", ".msi", ".cab", ".zip", ".7z", ".msu"}

# Extensions we attempt to recurse into. `.exe` is included but gated by a
# fast 7z list-probe (see _careful_nested_extract) — most .exes inside an
# unpacked installer are app binaries, not self-extractors.
_NESTED_RECURSE_EXT = _INTERMEDIATE_ARCHIVE_EXT

# Extensions we always keep in the extraction tree between harvest rounds:
# .sys (durable harvest target, copied to the store) and nested-archive sources
# (may still need recursion). Everything else is aux-leaf and gets pruned.
_KEEP_EXT_IN_TREE = _NESTED_RECURSE_EXT | {".sys"}

_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _probe_is_archive(path: Path, timeout: int = 10) -> bool:
    """Return True iff `7z l` recognizes this file as an archive with content.

    Used before extracting .exe files found inside an already-unpacked
    installer: most are plain application binaries (ffprobe.exe, GUI launcher,
    etc.) that 7z will probe for ~240s only to produce nothing. The list probe
    takes <1s on a non-archive and ~1-3s on a real self-extractor. Return False
    on timeout, non-zero exit, or near-empty listing — all treated as 'skip'.
    """
    try:
        r = subprocess.run(
            [str(config.sevenzip()), "l", "-slt", "-ba", str(path)],
            capture_output=True, text=True, errors="replace",
            timeout=timeout, creationflags=_CREATE_NO_WINDOW,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    if r.returncode != 0:
        return False
    # -slt -ba emits a block of `Path = ...` lines per entry. Require ≥2 to
    # avoid false-positives from signed .exes where 7z sees only the PE itself.
    return r.stdout.count("Path = ") >= 2


def _careful_nested_extract(root: Path, timeout: int = 300) -> list[dict]:
    """Nested extraction with .exe pre-filtered via a 7z list probe.

    Drop-in replacement for C.extract_nested that avoids the pathological
    "extract 50 bundled utility exes for 240s each" blow-up. .msi/.cab/.zip/
    .7z/.msu are guaranteed-archive extensions and go straight through; .exe
    gets a <1s list probe first, skipped if 7z doesn't recognize payload.
    """
    results: list[dict] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _NESTED_RECURSE_EXT:
            continue
        out = p.with_suffix(p.suffix + ".unpacked")
        if out.exists():
            continue
        if p.suffix.lower() == ".exe" and not _probe_is_archive(p):
            results.append({"package": str(p), "skipped": "probe-not-archive"})
            continue
        try:
            results.append(C.extract(p, out, timeout))
        except Exception as e:
            results.append({"package": str(p), "error": str(e)})
    return results


def _prune_aux_leaves(root: Path) -> int:
    """Delete every file in the tree that isn't a .sys or a nested-archive.

    Runs after each harvest round. Removes DLLs, INFs, CATs, INIs, XMLs,
    images, data blobs, MSI `!metadata` streams, and anything else that cannot
    produce a .sys on further recursion. The remaining tree holds only:
      • pending-to-recurse archives (.msi/.cab/.zip/.7z/.msu/probed .exe)
      • .sys files that collect_sys_files already copied to the store
      • the directory skeleton needed to drive the next extract_nested pass
    Peak per-package working set drops from ~500MB-1GB to ~50-200MB on big
    installers (G HUB, iCUE, Synapse).
    """
    pruned = 0
    for p in list(root.rglob("*")):
        if not p.is_file():
            continue
        suffix = p.suffix.lower()
        if suffix in _KEEP_EXT_IN_TREE:
            continue
        try:
            p.unlink()
            pruned += 1
        except OSError:
            pass
    return pruned


def _round_robin_by_brand(urls: list[str], url_source: dict[str, dict]) -> list[str]:
    """Reorder a flat URL list so consecutive items alternate brands.

    With N download workers consuming this ordering FIFO, the first N URLs
    in flight span N distinct brands (whenever ≥N brands have pending work).
    This breaks the "big-brand monopoly" of a naive flat queue — Logitech's
    ~800 packages no longer dominate the first 100 slots, so:
      • working set stays diverse (12 vendors ≠ 12 Logitech-sized installers)
      • dedup kicks in sooner (SHA256 collisions across versions caught early)
      • interrupting the run leaves a corpus sampled across all 540 brands
        instead of 100% of ~20 brands and 0% of the rest.
    Preserves per-brand version order (newest first, as the archive page
    returns them).
    """
    queues: dict[str, collections.deque] = {}
    for url in urls:
        brand = url_source.get(url, {}).get("brand_v_code") or "_unknown"
        queues.setdefault(brand, collections.deque()).append(url)
    ordered: list[str] = []
    while queues:
        empty: list[str] = []
        for brand, q in queues.items():
            ordered.append(q.popleft())
            if not q:
                empty.append(brand)
        for brand in empty:
            del queues[brand]
    return ordered


def _prune_intermediate_archives(root: Path) -> int:
    """Delete archive source files whose .unpacked/ sibling exists.

    Reduces the per-package working set during the .exe → .msi → .cab → payload
    chain, where each stage leaves both the source and the unpacked tree on
    disk. Safe: a .unpacked/ sibling means 7z already successfully opened it,
    so the source is dead weight.
    Returns the count of files pruned (for progress reporting).
    """
    pruned = 0
    for p in list(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _INTERMEDIATE_ARCHIVE_EXT:
            continue
        sibling = p.with_suffix(p.suffix + ".unpacked")
        if sibling.is_dir():
            try:
                p.unlink()
                pruned += 1
            except OSError:
                pass
    return pruned


RX_BRAND = re.compile(r'v_page=12&(?:amp;)?v_code=(\d+)[^>]*>([^<]+)</a>', re.I)
RX_PKG   = re.compile(r'v_page=23&(?:amp;)?v_code=(\d+)')
RX_FILE  = re.compile(
    r'href="(https://fichiers\d*\.touslesdrivers\.com/[^"<> ]+?'
    r'\.(?:zip|7z|cab|msi|exe))"', re.I)
# Common linux/mac/cleaner junk inside aggregator archives for input vendors.
JUNK = re.compile(r"(linux|cleaner|setup_cleaner|mac_?os|android|chromeos)", re.I)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_int_list(name: str, default: tuple[int, ...]) -> tuple[int, ...]:
    raw = os.environ.get(name)
    if not raw:
        return default
    out: list[int] = []
    for s in re.split(r"[;,]", raw):
        s = s.strip()
        if not s:
            continue
        try:
            out.append(int(s))
        except ValueError:
            continue
    return tuple(out) if out else default


class TousLesDriversInputCollector(Collector):
    name = "touslesdrivers-input"
    role = "TousLesDrivers.com HID / input-peripheral archives (keyboard, mouse, tablet, gamepad)"
    allowed_hosts = ["touslesdrivers.com"]  # covers www. and fichiers*.

    def __init__(
        self,
        categories: tuple[int, ...] | None = None,
        types: tuple[int, ...] | None = None,
        *,
        max_brands: int | None = None,
        max_packs: int | None = None,
        jobs: int | None = None,
        crawl_jobs: int | None = None,
        max_mb: int | None = None,
    ) -> None:
        self.categories = categories or _env_int_list("PDT_HID_CATEGORIES", DEFAULT_CATEGORIES)
        self.types = types or _env_int_list("PDT_HID_TYPES", DEFAULT_TYPES)
        self.max_brands = max_brands if max_brands is not None else _env_int("PDT_HID_MAX_BRANDS", 0)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_HID_MAX_PACKS", 0)
        self.jobs = jobs or _env_int("PDT_HID_JOBS", 6)
        self.crawl_jobs = crawl_jobs or _env_int("PDT_HID_CRAWL_JOBS", 8)
        self.max_mb = max_mb or _env_int("PDT_HID_MAX_MB", 60)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._brands: list[tuple[str, str]] = []  # (v_code, display_name)

    # ----- HTTP helper -----

    def _get_text(self, url: str, timeout: int = 30) -> str:
        req = Request(url, headers={"User-Agent": C.UA})
        with urlopen(req, timeout=timeout) as r:
            return r.read(8 << 20).decode("utf-8", "replace")

    # ----- discovery -----

    def _brands_for_category(self, cat: int) -> list[tuple[str, str]]:
        """Return [(v_code, display_name)] for every brand indexed under v_categorie=<cat>."""
        url = f"{BASE}/index.php?v_page=10&v_categorie={cat}"
        try:
            html = self._get_text(url)
        except Exception:
            return []
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        for code, name in RX_BRAND.findall(html):
            if code in seen:
                continue
            seen.add(code)
            # strip the "(long formal name)" tail browsers show after the brand
            display = name.strip()
            out.append((code, display))
        return out

    def _package_ids_for_brand(self, brand: str, vtype: int) -> list[str]:
        """Return the set of v_page=23 package IDs in brand's archive of this v_type."""
        url = (f"{BASE}/index.php?v_page=26&v_code={brand}"
               f"&v_ordre=0&v_systeme=0&v_type={vtype}")
        try:
            html = self._get_text(url)
        except Exception:
            return []
        return list(dict.fromkeys(RX_PKG.findall(html)))

    def _package_url(self, pkg_id: str) -> str | None:
        """Resolve one package ID's direct CDN archive URL via the download popup."""
        popup = (f"{BASE}/php/constructeurs/telechargement.php"
                 f"?v_code={pkg_id}&v_langue=fr")
        try:
            html = self._get_text(popup)
        except Exception:
            return None
        for link in RX_FILE.findall(html):
            if JUNK.search(link):
                continue
            return link
        return None

    def _config_fingerprint(self) -> str:
        """Stable id of the discovery configuration — cache key component."""
        payload = json.dumps({"categories": sorted(self.categories),
                              "types": sorted(self.types)}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def _discovery_cache_path(self) -> Path:
        return (config.collectors_dir() / self.name /
                f"discovery_cache_{self._config_fingerprint()}.json")

    def _load_discovery_cache(self) -> dict | None:
        """Return the cached discovery payload if present and fresh, else None.

        Cache is invalidated by: (a) TTL expiry, (b) config change (fingerprint
        is in the filename), (c) PDT_HID_REFRESH_DISCOVERY=1.
        """
        if os.environ.get("PDT_HID_REFRESH_DISCOVERY", "") not in ("", "0", "false"):
            return None
        p = self._discovery_cache_path()
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        ttl_days = _env_int("PDT_HID_DISCOVERY_TTL_DAYS", 7)
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
            "categories": list(self.categories),
            "types": list(self.types),
            "info": info,
            "urls": urls,
            "url_source": url_source,
        }
        p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    def discover(self) -> dict:
        # Fast path: load cached discovery if fresh.
        cached = self._load_discovery_cache()
        if cached is not None:
            all_urls = list(cached["urls"])
            self._url_source = dict(cached["url_source"])
            # Re-apply brand-stratified ordering even on cache hit: older cache
            # entries may have been saved flat (before the stratification fix),
            # and the ordering costs nothing to recompute.
            all_urls = _round_robin_by_brand(all_urls, self._url_source)
            self._urls = all_urls[: self.max_packs] if self.max_packs else all_urls
            info = dict(cached["info"])
            info["discovery_cache"] = {
                "hit": True,
                "saved_at": cached.get("saved_at"),
                "cached_url_count": len(all_urls),
                "used_url_count": len(self._urls),
                "path": str(self._discovery_cache_path()),
            }
            progress.report(f"discovery cache hit: {len(self._urls)}/{len(all_urls)} pkg URLs loaded")
            return info

        # --- Step 1: brand pool from the 4 category indexes --------------------
        progress.report("enumerating brands per input category")
        brands: dict[str, str] = {}   # v_code -> display_name (first seen wins)
        brand_cat: dict[str, list[int]] = {}  # which categories flagged each brand
        for cat in self.categories:
            for code, name in self._brands_for_category(cat):
                brands.setdefault(code, name)
                brand_cat.setdefault(code, []).append(cat)
        brand_list = list(brands.items())
        if self.max_brands:
            brand_list = brand_list[: self.max_brands]
        self._brands = brand_list
        progress.report(f"{len(brand_list)} brand(s) in input pool")

        # --- Step 2: archive-page sweep → package IDs --------------------------
        pkg_ids: list[str] = []
        seen_ids: set[str] = set()
        pkg_source: dict[str, tuple[str, int]] = {}  # pkg_id -> (brand, vtype)

        def sweep(args: tuple[str, int]) -> list[tuple[str, str, int]]:
            brand, vtype = args
            found = self._package_ids_for_brand(brand, vtype)
            return [(pid, brand, vtype) for pid in found]

        work = [(b, t) for b, _ in brand_list for t in self.types]
        total = len(work)
        workers = max(1, min(self.crawl_jobs, total or 1))
        done = 0
        progress.report(f"archives: 0/{total}")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(sweep, w): w for w in work}
            for fut in as_completed(futs):
                done += 1
                for pid, brand, vtype in fut.result():
                    if pid not in seen_ids:
                        seen_ids.add(pid)
                        pkg_ids.append(pid)
                        pkg_source[pid] = (brand, vtype)
                # Every tick is cheap; the pool races ahead of the reporter so
                # intermediate ticks aren't missed when many archives finish fast.
                progress.report(f"archives: {done}/{total} · {len(pkg_ids)} pkg ids so far")

        # --- Step 3: popup resolution → direct CDN URLs ------------------------
        urls: list[str] = []
        seen_urls: set[str] = set()
        url_source: dict[str, dict] = {}   # url -> {pkg_id, brand, vtype}
        total_pkgs = len(pkg_ids)
        done = 0
        progress.report(f"popups: 0/{total_pkgs}")

        def resolve_one(pkg_id: str) -> tuple[str, str | None]:
            return pkg_id, self._package_url(pkg_id)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(resolve_one, pid): pid for pid in pkg_ids}
            for fut in as_completed(futs):
                done += 1
                pkg_id, url = fut.result()
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    urls.append(url)
                    brand, vtype = pkg_source[pkg_id]
                    url_source[url] = {
                        "pkg_id": pkg_id,
                        "brand_v_code": brand,
                        "brand_name": brands.get(brand, ""),
                        "brand_categories": brand_cat.get(brand, []),
                        "v_type": vtype,
                    }
                progress.report(f"popups: {done}/{total_pkgs} · {len(urls)} direct URLs so far")
        # Stratify by brand so download workers don't cluster on one vendor's
        # fat-installer monoculture — see _round_robin_by_brand docstring.
        urls = _round_robin_by_brand(urls, url_source)
        self._urls = urls
        self._url_source = url_source
        progress.report(f"discovered {len(urls)} package(s)")

        info = {
            "discovery_page": BASE + "/",
            "installer_url": None,
            "categories": list(self.categories),
            "types": list(self.types),
            "brands_in_pool": len(brand_list),
            "brands_per_category": {str(c): sum(1 for v in brand_cat.values() if c in v)
                                    for c in self.categories},
            "package_ids_found": len(pkg_ids),
            "packs_resolved": len(urls),
            "jobs": self.jobs,
            "max_mb": self.max_mb,
        }
        # Persist for next run (resumable discovery). Save BEFORE max_packs
        # trimming so caps are reapplied per-run without poisoning the cache.
        self._save_discovery_cache(info, urls, url_source)
        if self.max_packs:
            self._urls = urls[: self.max_packs]
        info["discovery_cache"] = {
            "hit": False,
            "saved_at": C.utc_now(),
            "path": str(self._discovery_cache_path()),
        }
        return info

    # ----- acquisition (download → extract → harvest) ----------------------

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_HID_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        urls = self._urls

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(urls), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}

        # Capture the main thread's reporters (incl. the slot reporter installed
        # by pipeline.collect._worker), so each download worker can re-register
        # them on its own thread — slot activity reaches the renderer that way.
        rep_fn, cnt_fn, slot_fn = progress.current_reporters()

        def key_of(url: str) -> str:
            return urllib.parse.unquote(urllib.parse.urlparse(url).path)

        def handle(url: str) -> None:
            progress.set_reporter(rep_fn)
            progress.set_count_reporter(cnt_fn)
            if slot_fn is not None:
                progress.set_slot_reporter(slot_fn)
            # Per-worker slot keyed on thread id → stable sub-row position across
            # successive packages this worker handles. The label is the brand
            # name resolved during discovery; detail (download progress, extract
            # phase) comes from the primitives in collectors._common via report().
            slot_id = f"tld-{threading.get_ident()}"
            src = self._url_source.get(url, {})
            brand_label = (src.get("brand_name") or f"brand {src.get('brand_v_code','?')}").strip()
            progress.set_slot(slot_id, brand_label[:_SLOT_LABEL_WIDTH])
            try:
                key = key_of(url)
                if key in processed:
                    with self._lock:
                        stats["skipped_seen"] += 1
                    return
                with self._lock:
                    stats["attempted"] += 1
                got, rec = self._fetch(work_dir, url)
                if got is None:
                    # Record the URL as "failed" so a subsequent run does not
                    # re-download the same package only to fail again.
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
            list(pool.map(handle, urls))

        info["stats"] = stats
        info["errors"] = errors[:500]
        info["error_count"] = len(errors)
        info["downloads_top"] = downloads
        info["ledger_at_start"] = len(processed)
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    def _fetch(self, work_dir: Path, url: str):
        name = Path(urllib.parse.unquote(urllib.parse.urlparse(url).path)).name
        folder = work_dir / "packages" / (str(abs(hash(url)) % (10 ** 9)) + "__" + Path(name).stem)
        pkg = folder / name
        progress.report(f"pack: {name[:44]}")
        try:
            rec = C.download(url, pkg, self.allowed_hosts, max_mb=self.max_mb,
                             timeout=180, referer=f"{BASE}/")
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        extracted = folder / "extracted"
        try:
            C.extract(pkg, extracted)
            # Delete the downloaded installer immediately — extraction tree
            # above has everything we need, keeping the source inflates disk
            # 2× for 150MB installers. Safe: _fetch never re-extracts.
            try:
                pkg.unlink()
            except OSError:
                pass
            # First post-outer prune: drop .dll/.ini/.cat/.inf/data blobs that
            # the outer extract scattered. Then harvest any loose .sys the
            # outer stage exposed directly.
            _prune_aux_leaves(extracted)
            got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
            tries = 0
            while not got and tries < 2:
                # Careful nested extract: .exe files get a <1s list-probe
                # instead of a 240s blind extract — kills the ffprobe-style
                # overhead on packages that bundle utility exes.
                nested = _careful_nested_extract(extracted)
                if not nested:
                    break
                # Delete each archive source we just unpacked (its .unpacked/
                # sibling now holds the content); then kill all non-.sys non-
                # archive leaves. Together these cap the per-package working
                # set near the size of pending-recurse archives + harvested
                # .sys, not the cumulative extraction output.
                _prune_intermediate_archives(extracted)
                _prune_aux_leaves(extracted)
                got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
                tries += 1
            if not got:
                # last resort: driver embedded inside an app/self-extractor binary
                got = C.collect_carved_drivers(extracted, config.drivers_dir())
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        src = self._url_source.get(url, {})
        for r in got:
            r["provenance"] = {
                "source_kind": "touslesdrivers-aggregator-input",
                "aggregator": "touslesdrivers.com",
                "trust_note": ("third-party aggregator, not the original vendor "
                               "domain; no catalog (.cat) trust path assumed — "
                               "authenticity left to the L0 gate / DrvEye"),
                "brand_v_code": src.get("brand_v_code"),
                "brand_name": src.get("brand_name"),
                "brand_categories": src.get("brand_categories", []),
                "aggregator_v_type": src.get("v_type"),
                "aggregator_package_id": src.get("pkg_id"),
                "package_name": name,
                "package_url": url,
                "package_final_url": rec["final_url"],
                "package_sha256": rec["sha256"],
                "package_size": rec["size"],
            }
            # Append provenance now that it is attached, so the store index carries
            # origin per binary even if this long, resumable run is interrupted
            # before its manifest is written.
            C.append_index(config.drivers_dir(),
                           {"sha256": r["sha256"], "provenance": r["provenance"]})
        C.prune_dir(folder)
        return got, rec

    # ----- resume ledger (shared across worker threads) -----

    def _ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_ledger(self) -> set[str]:
        """Return the set of URL path keys we should NOT re-download.

        By default this includes every status (`ok`, `no_sys`, `failed`) —
        failed packages are kept out of the retry pool because re-downloading
        a 150MB installer only to have 7z choke on the same byte again wastes
        bandwidth. Set PDT_HID_RETRY_FAILED=1 to drop `failed` entries from
        the skip set so the next run tries them again (useful after a bug fix
        in the extraction chain).
        """
        retry_failed = os.environ.get("PDT_HID_RETRY_FAILED", "") not in ("", "0", "false")
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
                key = entry.get("key")
                if key:
                    seen.add(key)
        return seen

    def _record(self, key: str, url: str, sys_shas: list[str], *, status: str) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "key": key,
                    "url": url,
                    "status": status,
                    "sys": sys_shas,
                    "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


def collector() -> TousLesDriversInputCollector:
    return TousLesDriversInputCollector()
