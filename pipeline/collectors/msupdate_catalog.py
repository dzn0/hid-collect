"""Microsoft Update Catalog — HID / mouse / keyboard driver collector.

Walks `catalog.update.microsoft.com` with a bank of narrow, mouse/kbd/HID-shaped
search queries and resolves each result's direct CDN `.cab` URL via the catalog's
`DownloadDialog.aspx` POST. Every binary is a WHQL-signed Windows driver — the
richest source of HID peripherals in the field, where strings like
`MouseClassServiceCallback` actually ship.

Flow:

  1. `discover()`:
       - for each query in `PDT_MSC_QUERIES` (default: a curated HID set), GET
         `Search.aspx?q=<query>` (first page, up to 25 hits — no ASP.NET
         postback pagination; we lean on query diversity instead for speed).
       - parse `<tr id=\"<UID>_R<N>\">` rows into {uid, title, product,
         classification, date, version, size}.
       - keep only rows whose title or classification matches the HID shape
         (mouse, keyboard, pointer, HID, touchpad, stylus, gamepad).
       - POST `DownloadDialog.aspx` for each kept UID (thread pool) to resolve
         the direct `catalog.s.download.windowsupdate.com` CDN URL.
       - cache the resolved universe for reuse across runs.

  2. `acquire()`:
       - download each `.cab` in parallel (small, usually 10-500 KB), extract
         with 7-Zip, harvest `.sys`. Same content-addressed store + resume
         ledger as the other collectors — `drivers/<sha256>.sys` dedupes
         across sources naturally.

Everything runs static: no driver is executed, every file is validated by magic
before extraction, and no HTTPS cert check is ever disabled.

Environment knobs:
- `PDT_MSC_QUERIES`         (`;` separated)         default: curated HID set
- `PDT_MSC_JOBS`            (int)                   default: 8 (download workers)
- `PDT_MSC_CRAWL_JOBS`      (int)                   default: 12 (search/resolve)
- `PDT_MSC_MAX_PACKS`       (int)                   default: 0 (unlimited)
- `PDT_MSC_MAX_MB`          (int)                   default: 100 (per .cab)
- `PDT_MSC_REFRESH=1`                               ignore download ledger
- `PDT_MSC_REFRESH_DISCOVERY=1`                     ignore discovery cache
- `PDT_MSC_DISCOVERY_TTL_DAYS` (int)                default: 7
- `PDT_MSC_MAX_PAGES`       (int)                   default: 1 (urllib, no paging)
                                                    `>1` activates Playwright
                                                    pagination (requires `playwright`
                                                    + `chromium` in the image)
- `PDT_MSC_BROWSER_WORKERS` (int)                   default: 3 (parallel browsers
                                                    for pagination; each is ~300MB
                                                    RAM when active)
"""
from __future__ import annotations
import collections
import hashlib
import json
import os
import re
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


BASE = "https://www.catalog.update.microsoft.com"
CDN_HOSTS = ("catalog.s.download.windowsupdate.com",
             "download.windowsupdate.com", "catalog.update.microsoft.com")

# Width of the per-browser slot label in the live progress UI. Keep it compact
# so the per-page detail (q 7/18 · p 12/20 · 311 rows) has room on the same
# line even on an 80-col terminal.
_SLOT_LABEL_WIDTH = 18

# Narrow, non-overlapping queries targeting the mouse/keyboard/HID slice. One
# page per query (25 hits max), so query diversity substitutes for pagination —
# the catalog's ASP.NET WebForms postback is heavy and slower in aggregate than
# just asking a few more well-shaped questions in parallel. Picks are biased
# toward brands where MouseClassServiceCallback-style primitives commonly ship.
DEFAULT_QUERIES: tuple[str, ...] = (
    # Generic class queries
    "mouse driver",
    "keyboard driver",
    "HID driver",
    "pointer driver",
    "touchpad driver",
    # Brand-specific — HID peripheral vendors
    "logitech mouse", "logitech keyboard", "logitech wireless",
    "logitech options", "logitech g hub",
    "razer mouse", "razer keyboard", "razer synapse",
    "razer basilisk", "razer deathadder", "razer naga",
    "corsair mouse", "corsair keyboard", "corsair icue",
    "steelseries mouse", "steelseries keyboard", "steelseries engine",
    "hyperx mouse", "hyperx keyboard", "hyperx ngenuity",
    "roccat mouse", "roccat keyboard",
    "microsoft mouse", "microsoft keyboard", "microsoft sidewinder",
    "microsoft arc", "microsoft surface keyboard",
    "wooting", "ducky keyboard", "cherry keyboard",
    "glorious mouse", "mountain keyboard", "akko keyboard",
    "cooler master mouse", "cooler master keyboard",
    "mad catz mouse", "mad catz keyboard",
    "a4tech mouse", "bloody mouse",
    "zowie mouse", "endgame gear",
    "redragon mouse", "redragon keyboard",
    "gaming mouse", "gaming keyboard",
    # Touchpad vendors (laptop HID — relevant for the input-stack target)
    "synaptics touchpad", "elan touchpad", "alps touchpad",
    # Stylus / tablet HID
    "wacom stylus", "surface pen",
)

# Keep only results whose title or classification contains any of these — the
# catalog returns a lot of adjacent/unrelated drivers for broad brand queries.
HID_SHAPE_PATTERNS = re.compile(
    r"\b(mouse|mice|keyboard|kbd|pointer|hid|touchpad|clickpad|trackpad|"
    r"stylus|pen\s+driver|synapse|icue|g\s*hub|ngenuity|ducky|cherry|"
    r"glorious|mountain|akko|wooting|redragon|bloody|zowie|endgame|"
    r"basilisk|deathadder|naga|sidewinder|arc\s*mouse)\b",
    re.I,
)

# <tr id="<UID>_R<N>"> ... </tr>
RX_ROW = re.compile(r'<tr id="([0-9a-f-]{36})_R\d+"[^>]*>(.*?)</tr>', re.S | re.I)
# column text extractor
RX_CELL = re.compile(r'<td[^>]*>(.*?)</td>', re.S | re.I)
RX_TAGS = re.compile(r"<[^>]+>")
# DownloadDialog response: downloadInformation[N].files[M].url = '…'
RX_DL_URL = re.compile(r"downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=\s*'([^']+)'")


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


def _clean(cell: str) -> str:
    """Strip HTML tags and collapse whitespace in a table cell."""
    text = RX_TAGS.sub("", cell)
    text = text.replace("&amp;", "&").replace("&nbsp;", " ")
    return " ".join(text.split())


def _parse_row(uid: str, inner: str) -> dict:
    cells = [_clean(c) for c in RX_CELL.findall(inner)]
    # Column order on the current catalog: 0 icon · 1 title · 2 product ·
    # 3 classification · 4 date · 5 version · 6 size · 7 button
    def get(i: int) -> str:
        return cells[i] if i < len(cells) else ""
    size_bytes = 0
    # a hidden <span id="<uid>_originalSize"> holds the real byte count
    m = re.search(r'id="' + re.escape(uid) + r'_originalSize"[^>]*>\s*(\d+)',
                  inner, re.I)
    if m:
        size_bytes = int(m.group(1))
    return {
        "uid": uid,
        "title": get(1),
        "product": get(2),
        "classification": get(3),
        "date": get(4),
        "version": get(5),
        "size_bytes": size_bytes,
    }


def _hid_shaped(row: dict) -> bool:
    hay = f"{row.get('title','')} {row.get('product','')} {row.get('classification','')}"
    return bool(HID_SHAPE_PATTERNS.search(hay))


class MsUpdateCatalogCollector(Collector):
    name = "msupdate-catalog"
    role = "Microsoft Update Catalog HID / mouse / keyboard drivers (WHQL)"
    allowed_hosts = list(CDN_HOSTS)

    def __init__(self) -> None:
        self.queries = _env_str_list("PDT_MSC_QUERIES", DEFAULT_QUERIES)
        self.jobs = _env_int("PDT_MSC_JOBS", 8)
        self.crawl_jobs = _env_int("PDT_MSC_CRAWL_JOBS", 12)
        self.max_packs = _env_int("PDT_MSC_MAX_PACKS", 0)
        self.max_mb = _env_int("PDT_MSC_MAX_MB", 100)
        self.max_pages = max(1, _env_int("PDT_MSC_MAX_PAGES", 1))
        self.browser_workers = max(1, _env_int("PDT_MSC_BROWSER_WORKERS", 3))
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._url_source: dict[str, dict] = {}

    # ----- discovery -----

    def _get_text(self, url: str, timeout: int = 30) -> str:
        req = Request(url, headers={"User-Agent": C.UA})
        with urlopen(req, timeout=timeout) as r:
            return r.read(16 << 20).decode("utf-8", "replace")

    def _search(self, query: str) -> list[dict]:
        url = f"{BASE}/Search.aspx?q=" + urllib.parse.quote(query)
        try:
            html = self._get_text(url)
        except Exception:
            return []
        rows = [_parse_row(uid, inner) for uid, inner in RX_ROW.findall(html)]
        for r in rows:
            r["query"] = query
        return rows

    def _search_paged_chunk(self, queries: list[str],
                            rep_fn, cnt_fn, slot_fn) -> list[dict]:
        """Walk N pages per query via Playwright. One browser per chunk, serial.

        The catalog's ASP.NET postback (ctl00$catalogBody$nextPageLinkText) is
        blocked for urllib — it returns a generic 500 error page after one hop.
        A real browser passes through fine, so we drive Chromium headless when
        `PDT_MSC_MAX_PAGES > 1`. Fallback to urllib when Playwright is missing.

        `rep_fn`/`cnt_fn`/`slot_fn` are the reporters captured on the main
        thread; we re-register them on this worker thread so per-query /
        per-page progress still reaches the live renderer (progress is
        thread-local — see pipeline.progress).
        """
        # Re-register thread-local progress reporters on this worker thread so
        # a sub-row shows up live for each browser.
        progress.set_reporter(rep_fn)
        progress.set_count_reporter(cnt_fn)
        if slot_fn is not None:
            progress.set_slot_reporter(slot_fn)
        slot_id = f"msc-browser-{threading.get_ident()}"
        progress.set_slot(slot_id, "browser")

        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except ImportError:
            # Playwright not installed: silently fall back to the 1-page urllib
            # path so a slim image without browsers still works.
            out = []
            for i, q in enumerate(queries, 1):
                progress.set_slot(slot_id, q[:_SLOT_LABEL_WIDTH])
                progress.report(f"q {i}/{len(queries)} (urllib fallback)")
                out.extend(self._search(q))
            progress.clear_slot()
            return out
        out: list[dict] = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    for i, q in enumerate(queries, 1):
                        progress.set_slot(slot_id, q[:_SLOT_LABEL_WIDTH])
                        progress.report(f"q {i}/{len(queries)} starting")
                        out.extend(self._paginate_one(browser, q, i, len(queries)))
                finally:
                    browser.close()
        finally:
            progress.clear_slot()
        return out

    def _paginate_one(self, browser, query: str,
                      q_idx: int, q_total: int) -> list[dict]:
        """Click through up to `self.max_pages` pages of one query."""
        rows: list[dict] = []
        seen_uids: set[str] = set()
        page = browser.new_page(user_agent=C.UA)
        try:
            url = f"{BASE}/Search.aspx?q=" + urllib.parse.quote(query)
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            for page_i in range(1, self.max_pages + 1):
                try:
                    page.wait_for_selector('tr[id$="_R0"]', timeout=15000)
                except Exception:
                    # no results on this query
                    break
                html = page.content()
                new_uids: list[str] = []
                for uid, inner in RX_ROW.findall(html):
                    if uid in seen_uids:
                        continue
                    seen_uids.add(uid)
                    r = _parse_row(uid, inner)
                    r["query"] = query
                    r["page"] = page_i
                    rows.append(r)
                    new_uids.append(uid)
                progress.report(
                    f"q {q_idx}/{q_total} · p {page_i}/{self.max_pages} · "
                    f"{len(rows)} rows")
                if not new_uids:
                    break
                if page_i == self.max_pages:
                    break
                nxt = page.locator('#ctl00_catalogBody_nextPageLinkText')
                if not nxt.count():
                    break
                cls = nxt.get_attribute("class") or ""
                if "disabled" in cls:
                    break
                # Pivot: wait for the current first row to disappear so we don't
                # re-parse the same page before the postback finishes rendering.
                pivot = new_uids[0]
                try:
                    nxt.click(timeout=5000)
                    page.wait_for_function(
                        f'() => !document.getElementById("{pivot}_R0")',
                        timeout=20000)
                except Exception:
                    break
        finally:
            try:
                page.close()
            except Exception:
                pass
        return rows

    def _resolve_url(self, uid: str) -> str | None:
        payload = urllib.parse.quote(json.dumps(
            [{"size": 0, "languages": "", "uidInfo": uid, "updateID": uid}]))
        body = ("updateIDs=" + payload).encode("ascii")
        req = Request(
            f"{BASE}/DownloadDialog.aspx",
            data=body,
            headers={"User-Agent": C.UA,
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Referer": f"{BASE}/Search.aspx"},
        )
        try:
            with urlopen(req, timeout=30) as r:
                text = r.read(2 << 20).decode("utf-8", "replace")
        except Exception:
            return None
        m = RX_DL_URL.search(text)
        return m.group(1) if m else None

    def _config_fingerprint(self) -> str:
        payload = json.dumps(
            {"queries": sorted(self.queries), "max_pages": self.max_pages},
            sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def _discovery_cache_path(self) -> Path:
        return (config.collectors_dir() / self.name /
                f"discovery_cache_{self._config_fingerprint()}.json")

    def _load_discovery_cache(self) -> dict | None:
        if os.environ.get("PDT_MSC_REFRESH_DISCOVERY", "") not in ("", "0", "false"):
            return None
        p = self._discovery_cache_path()
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        ttl_days = _env_int("PDT_MSC_DISCOVERY_TTL_DAYS", 7)
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
            "queries": list(self.queries),
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
            progress.report(f"discovery cache hit: {len(self._urls)} pkg URLs")
            return info

        # Step 1 — fan out searches. Two paths:
        #   * max_pages == 1: urllib, one GET per query, up to crawl_jobs
        #     workers (very fast — ~60 GETs in parallel).
        #   * max_pages > 1 : Playwright, one browser per worker, each worker
        #     walks a chunk of queries serially (each query clicks through up
        #     to max_pages pages). Fewer workers (default 3) because every
        #     browser is RAM-heavy.
        rows_by_uid: dict[str, dict] = {}

        def _ingest(rows: list[dict]) -> None:
            for row in rows:
                if not _hid_shaped(row):
                    continue
                r = rows_by_uid.setdefault(row["uid"], row)
                r.setdefault("queries", [])
                if row["query"] not in r["queries"]:
                    r["queries"].append(row["query"])

        if self.max_pages <= 1:
            progress.report(f"searching {len(self.queries)} queries (1 page each)")
            workers = max(1, min(self.crawl_jobs, len(self.queries) or 1))
            done = 0
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(self._search, q): q for q in self.queries}
                for fut in as_completed(futs):
                    done += 1
                    _ingest(fut.result())
                    progress.report(
                        f"searches: {done}/{len(self.queries)} · "
                        f"{len(rows_by_uid)} hid-shaped candidate(s)")
        else:
            progress.report(
                f"searching {len(self.queries)} queries × up to {self.max_pages} "
                f"pages via Playwright ({self.browser_workers} browsers)")
            # Capture the main thread's reporters so each browser worker can
            # re-register them on its own thread — per-query/per-page progress
            # otherwise never reaches the live renderer (channel is thread-local).
            rep_fn, cnt_fn, slot_fn = progress.current_reporters()
            # Split queries evenly across browser workers.
            k = max(1, min(self.browser_workers, len(self.queries)))
            chunks: list[list[str]] = [[] for _ in range(k)]
            for i, q in enumerate(self.queries):
                chunks[i % k].append(q)
            done = 0
            with ThreadPoolExecutor(max_workers=k) as pool:
                futs = {pool.submit(self._search_paged_chunk, c,
                                    rep_fn, cnt_fn, slot_fn): c
                        for c in chunks}
                for fut in as_completed(futs):
                    _ingest(fut.result())
                    done += 1
                    progress.report(
                        f"browser chunks: {done}/{k} · "
                        f"{len(rows_by_uid)} hid-shaped candidate(s)")
        uids = list(rows_by_uid.keys())

        # Step 2 — resolve each UID's direct CDN URL in parallel.
        progress.report(f"resolving {len(uids)} download URLs")
        urls: list[str] = []
        seen: set[str] = set()
        url_source: dict[str, dict] = {}
        done = 0
        rworkers = max(1, min(self.crawl_jobs, len(uids) or 1))

        def resolve_one(uid: str) -> tuple[str, str | None]:
            return uid, self._resolve_url(uid)

        with ThreadPoolExecutor(max_workers=rworkers) as pool:
            futs = {pool.submit(resolve_one, u): u for u in uids}
            for fut in as_completed(futs):
                done += 1
                uid, url = fut.result()
                if url and url not in seen:
                    seen.add(url)
                    urls.append(url)
                    url_source[url] = {
                        "uid": uid,
                        **{k: rows_by_uid[uid].get(k)
                           for k in ("title", "product", "classification",
                                     "date", "version", "size_bytes",
                                     "queries")},
                    }
                progress.report(
                    f"resolve: {done}/{len(uids)} · {len(urls)} direct URLs")

        self._urls = urls[: self.max_packs] if self.max_packs else urls
        self._url_source = url_source
        info = {
            "discovery_page": BASE + "/",
            "installer_url": None,
            "queries": list(self.queries),
            "hits": len(rows_by_uid),
            "packs_resolved": len(urls),
            "jobs": self.jobs,
            "max_mb": self.max_mb,
        }
        self._save_discovery_cache(info, urls, url_source)
        info["discovery_cache"] = {
            "hit": False, "saved_at": C.utc_now(),
            "path": str(self._discovery_cache_path()),
        }
        return info

    # ----- acquisition -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_MSC_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        urls = self._urls

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(urls), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}

        rep_fn, cnt_fn, slot_fn = progress.current_reporters()

        def key_of(url: str) -> str:
            return urllib.parse.unquote(urllib.parse.urlparse(url).path)

        def handle(url: str) -> None:
            progress.set_reporter(rep_fn)
            progress.set_count_reporter(cnt_fn)
            if slot_fn is not None:
                progress.set_slot_reporter(slot_fn)
            slot_id = f"msc-{threading.get_ident()}"
            src = self._url_source.get(url, {})
            title = (src.get("title") or "update")[:18]
            progress.set_slot(slot_id, title)
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
        name = Path(urllib.parse.urlparse(url).path).name
        # Catalog .cab names are 80+ chars (two concatenated GUIDs). Combined
        # with Windows's 260-char MAX_PATH that overflows even in a shallow
        # work_dir. Use the catalog UID as the folder slug (36 chars, stable
        # across runs) and a short hash prefix to stay unique.
        src = self._url_source.get(url, {})
        slug = (src.get("uid") or f"{abs(hash(url)) % (10 ** 9):09d}")[:36]
        folder = work_dir / "packages" / slug
        # Shorten the filename on disk too — the sha of the download is what
        # survives in the content-addressed store; the local filename is scratch.
        local_name = f"pkg_{hashlib.sha1(name.encode()).hexdigest()[:12]}.cab"
        pkg = folder / local_name
        progress.report(f"pack: {name[:48]}")
        try:
            rec = C.download(url, pkg, self.allowed_hosts, max_mb=self.max_mb,
                             timeout=120, referer=f"{BASE}/")
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
            # Catalog `.cab` is sometimes a wrapper over a child `.cab`/`.msi` —
            # one level of recursion is usually enough.
            if not got:
                if C.extract_nested(extracted):
                    got = C.collect_sys_files(folder, config.drivers_dir(),
                                              include_native_pe=True)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        src = self._url_source.get(url, {})
        for r in got:
            r["provenance"] = {
                "source_kind": "microsoft-update-catalog",
                "aggregator": "catalog.update.microsoft.com",
                "trust_note": ("WHQL-signed via Microsoft; catalog does not expose "
                               "the .cat file directly, but each .cab download is "
                               "served from a Microsoft-controlled CDN"),
                "catalog_uid": src.get("uid"),
                "update_title": src.get("title"),
                "update_product": src.get("product"),
                "update_classification": src.get("classification"),
                "update_date": src.get("date"),
                "update_version": src.get("version"),
                "matched_queries": src.get("queries") or [],
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
        retry_failed = os.environ.get("PDT_MSC_RETRY_FAILED", "") \
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
                key = entry.get("key")
                if key:
                    seen.add(key)
        return seen

    def _record(self, key: str, url: str, sys_shas: list[str], *,
                status: str) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "key": key, "url": url, "status": status,
                    "sys": sys_shas, "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


def collector() -> MsUpdateCatalogCollector:
    return MsUpdateCatalogCollector()
