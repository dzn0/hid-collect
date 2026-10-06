"""Microsoft Update Catalog — HID / mouse / keyboard driver collector.

Walks `catalog.update.microsoft.com` with a bank of narrow, mouse/kbd/HID-shaped
search queries and resolves each result's direct CDN `.cab` URL via the catalog's
`DownloadDialog.aspx` POST. Every binary is a WHQL-signed Windows driver — the
richest source of HID peripherals in the field, where strings like
`MouseClassServiceCallback` actually ship.

Flow:

  1. `discover()`:
       - for each query in `PDT_MSC_QUERIES` (default: a curated HID set), drive
         a headless Chromium through `Search.aspx?q=<query>` and click the
         "next page" postback until the query is exhausted or `PDT_MSC_MAX_PAGES`
         is hit — every page is 25 rows, the catalog caps a search at 1000.
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
- `PDT_MSC_MAX_PAGES`       (int)                   default: 40 (pages per query;
                                                    the catalog caps a search at
                                                    40 pages × 25 = 1000 results)
- `PDT_MSC_BROWSER_WORKERS` (int)                   default: 6 (parallel browsers
                                                    for pagination; each is ~300MB
                                                    RAM when active)
- `PDT_MSC_BATCH_QUERIES`   (int)                   default: browser_workers × 4
                                                    (queries discovered per round
                                                    before downloading what they
                                                    found; 0 = discover all, then
                                                    download all — old flow)

`run()` interleaves the two phases: it walks the queries in batches, and after
each batch downloads what that batch turned up before moving on — so drivers
start landing early instead of after all 595 queries finish. A discovery-cache
hit or `PDT_MSC_BATCH_QUERIES=0` falls back to the plain discover→acquire flow.

Discovery always drives a real headless Chromium (Playwright): the catalog's
"next page" is an ASP.NET `__doPostBack`, not a URL, and stdlib urllib cannot
follow it (it gets a generic 500 after one hop). `playwright` + its chromium
build must therefore be present in the image.
"""
from __future__ import annotations
import collections
import hashlib
import json
import os
import re
import threading
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

from .. import __version__ as PIPELINE_VERSION
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

# Default query bank. Composed programmatically so the groups are legible and
# easy to extend. Each query is "narrow enough that the first 20 pages (500
# hits max) stay on topic" and "broad enough that it is worth asking at all".
# Catalog's full-text search is implicit AND on tokens, case-insensitive;
# wildcards and boolean operators are ignored. See docstring at top.

def _build_default_queries() -> tuple[str, ...]:
    q: list[str] = []

    # ─── Generic class / category — the broad net ────────────────────────────
    q += [
        "mouse", "keyboard", "HID", "pointer", "touchpad", "clickpad",
        "trackpad", "trackball", "stylus", "digitizer", "pen",
        "mouse driver", "keyboard driver", "HID driver",
        "pointer driver", "touchpad driver", "stylus driver",
        "gaming mouse", "gaming keyboard", "wireless mouse",
        "wireless keyboard", "bluetooth mouse", "bluetooth keyboard",
        "mechanical keyboard", "USB HID", "I2C HID", "precision touchpad",
        "USB keyboard", "USB mouse", "PS/2 keyboard", "PS/2 mouse",
        "composite HID", "HID compliant", "HID-compliant",
    ]

    # ─── Peripheral HID vendors — exhaustive ─────────────────────────────────
    # For each brand we query both the brand alone (catches "brand driver
    # update", "brand mouse driver" etc) and a few focused variants.
    brands_core = [
        "Logitech", "Logi International", "Razer", "Corsair", "SteelSeries",
        "HyperX", "Kingston HyperX", "ROCCAT", "Turtle Entertainment",
        "Microsoft", "Mad Catz", "Saitek", "Thrustmaster", "Trust",
        "Wooting", "Mountain", "Glorious", "Mionix", "Zowie", "BenQ Zowie",
        "Endgame Gear", "Pulsar", "LAMZU", "VAXEE", "Fantech", "G-Wolves",
        "Finalmouse", "Ninjutso", "ATK", "AJAZZ", "Cooler Master", "COUGAR",
        "Thermaltake", "Tt eSPORTS", "ASUS ROG", "ASUS", "AORUS", "GIGABYTE",
        "MSI", "EVGA", "NZXT", "Lian Li", "ADATA XPG", "G.SKILL",
        "Patriot Viper", "Patriot", "Alienware", "HP OMEN", "HP",
        "Lenovo Legion", "Acer Predator", "Dell", "A4Tech", "Bloody",
        "Redragon", "HAVIT", "Riotoro", "Tt eSPORTS", "Tesoro", "Qpad",
        "QPAD", "DREVO", "Ducky", "DuckyChannel", "Cherry", "CHERRY MX",
        "Akko", "Keychron", "Royal Kludge", "Monsgeek", "MonsGeek",
        "GamaKay", "Darmoshark", "Attack Shark", "Vaxee", "Xtrfy", "Fnatic",
        "GamaKay", "Varmilo", "KBDFans", "YUNZII", "DAREU", "Ozone",
        "KEMOVE", "KLIM", "MelGeek", "Perixx", "Rapoo", "ELECOM",
        "Fujitsu", "NEC", "iRocks", "Lexip", "Kensington", "Logitech G",
        "GAMDIAS", "Dygma", "ENDORFY", "COOLKILLER", "Cool Killer",
        "FL.Esports", "RedThunder", "Battletron", "AULA", "Easars",
        "ProtoArc", "Fox Spirit", "Jelly Comb", "TMKB", "Xanova",
        "G4M3R", "Rantopad", "Matrix Keyboards", "MOJO TECH",
        "Spirit Of Gamer", "Art Lebedev", "Art. Lebedev",
    ]
    for b in brands_core:
        q.append(b)
        q.append(f"{b} mouse")
        q.append(f"{b} keyboard")

    # ─── Famous model families — one query each (narrow + diverse) ───────────
    models = [
        # Logitech
        "Logitech G502", "Logitech G Pro", "Logitech G Pro X", "Logitech G903",
        "Logitech G703", "Logitech G600", "Logitech G300", "Logitech G102",
        "Logitech MX Master", "Logitech MX Anywhere", "Logitech MX Keys",
        "Logitech K380", "Logitech K400", "Logitech K750", "Logitech K800",
        "Logitech Craft", "Logitech Options", "Logitech Options+",
        "Logitech Unifying", "Logitech LightSpeed", "Logitech G Hub",
        "Logitech Lift", "Logitech Signature", "Logitech Pop",
        "Logitech Pebble", "Logitech ERGO", "Logitech Harmony",
        # Razer
        "Razer DeathAdder", "Razer Basilisk", "Razer Viper", "Razer Naga",
        "Razer Mamba", "Razer Lancehead", "Razer Krait", "Razer Abyssus",
        "Razer Diamondback", "Razer Orochi", "Razer Pro Click",
        "Razer BlackWidow", "Razer Huntsman", "Razer Cynosa",
        "Razer Ornata", "Razer Tartarus", "Razer Pro Type",
        "Razer Synapse", "Razer Kraken", "Razer Chroma",
        # Corsair
        "Corsair Katar", "Corsair Harpoon", "Corsair Ironclaw",
        "Corsair Dark Core", "Corsair Scimitar", "Corsair Nightsword",
        "Corsair Sabre", "Corsair M65", "Corsair M55",
        "Corsair K70", "Corsair K95", "Corsair K63", "Corsair K55",
        "Corsair K57", "Corsair K60", "Corsair Vengeance",
        "Corsair Strafe", "Corsair iCUE",
        # SteelSeries
        "SteelSeries Aerox", "SteelSeries Prime", "SteelSeries Rival",
        "SteelSeries Sensei", "SteelSeries Kana", "SteelSeries Apex",
        "SteelSeries Engine", "SteelSeries GG",
        # HyperX
        "HyperX Pulsefire", "HyperX Alloy", "HyperX NGenuity",
        "HyperX Haste", "HyperX Cloud",
        # ROCCAT
        "ROCCAT Kone", "ROCCAT Kain", "ROCCAT Burst", "ROCCAT Vulcan",
        "ROCCAT Pyro", "ROCCAT Suora", "ROCCAT Nyth",
        # Microsoft
        "Microsoft IntelliMouse", "Microsoft Pro IntelliMouse",
        "Microsoft Classic IntelliMouse", "Microsoft Precision Mouse",
        "Microsoft Explorer Mouse", "Microsoft Sculpt",
        "Microsoft Wedge", "Microsoft Ergonomic",
        "Microsoft Sidewinder", "Microsoft Arc", "Microsoft Modern",
        "Microsoft Surface Pen", "Microsoft Surface Dial",
        "Microsoft Surface Keyboard", "Microsoft Surface Mouse",
        "Microsoft Bluetooth Mouse", "Microsoft Bluetooth Keyboard",
        "Microsoft Mobile Mouse", "Microsoft Comfort",
        "Microsoft All-in-One",
        # Mad Catz, Saitek, Thrustmaster, Fanatec
        "Mad Catz R.A.T.", "Mad Catz Strike", "Saitek Cyborg",
        "Saitek Eclipse", "Saitek Pro Flight",
        # ASUS / AORUS gaming
        "ASUS Strix", "ASUS TUF Gaming", "ASUS Armoury", "ASUS ROG Chakram",
        "ASUS ROG Gladius", "ASUS ROG Keris", "ASUS ROG Pugio",
        "ASUS ROG Claymore", "AORUS Thunder",
        # Alienware / HP OMEN
        "Alienware Mouse", "Alienware Keyboard", "HP OMEN Mouse",
        "HP OMEN Keyboard", "Dell Alienware",
        # Chinese boutique boards
        "Akko MOD", "Keychron K", "Keychron Q", "Royal Kludge RK",
        "Monsgeek M", "Darmoshark N", "Attack Shark R",
    ]
    q.extend(models)

    # ─── Touchpad OEMs — exhaustive ──────────────────────────────────────────
    touchpad = [
        "Synaptics touchpad", "Synaptics clickpad", "Synaptics pointing",
        "Synaptics SMBus", "Synaptics HID", "Synaptics Precision",
        "ELAN touchpad", "ELAN clickpad", "ELAN pointing", "ELAN HID",
        "ELAN I2C", "ELAN SmartPad", "Alps touchpad", "Alps pointing",
        "Alps HID", "ALPSALPINE touchpad", "ALPS ALPINE pointing",
        "Cypress trackpad", "Precision touchpad", "Intel precision touchpad",
    ]
    q.extend(touchpad)

    # ─── Stylus / tablet / pen ───────────────────────────────────────────────
    stylus = [
        "Wacom stylus", "Wacom Bamboo", "Wacom Intuos", "Wacom Cintiq",
        "Wacom One", "Wacom pen", "Wacom tablet", "Surface Pen",
        "Surface Slim Pen", "Surface Dial", "XPPen stylus", "XP-Pen",
        "Huion stylus", "Huion pen", "N-trig", "N-Trig DuoSense",
        "stylus driver", "digitizer driver", "digitizer HID",
    ]
    q.extend(stylus)

    # ─── Hardware IDs — major HID vendors on USB bus ─────────────────────────
    # These queries hit the catalog's indexed hardware ID fields; many drivers
    # ship as a USB\VID_XXXX&PID_YYYY row. Picks are the top-10 well-known
    # vendor IDs in the HID space.
    vids = [
        ("046D", "Logitech"), ("1532", "Razer"), ("1B1C", "CORSAIR"),
        ("1038", "SteelSeries"), ("0951", "HyperX / Kingston"),
        ("1E7D", "ROCCAT"), ("045E", "Microsoft"), ("0738", "Mad Catz"),
        ("06A3", "Saitek"), ("044F", "Thrustmaster"), ("05AC", "Apple"),
        ("04CA", "ELAN"), ("06CB", "Synaptics"), ("044E", "Alps"),
        ("056A", "Wacom"), ("28BD", "XP-Pen"), ("256C", "Huion"),
        ("29EA", "Kingston Technology"), ("4653", "Fanatec"),
        ("0C45", "Microdia / Chicony"),
    ]
    for hex4, _ in vids:
        q.append(f"USB VID_{hex4}")
        q.append(f"VID_{hex4}")

    # ─── Software / overlay drivers (where MouseClassServiceCallback ships) ──
    overlays = [
        "G HUB", "LGHUB", "SetPoint", "Logitech Options", "Options+",
        "Synapse", "Razer Chroma", "iCUE", "CUE", "NGenuity", "ARMOURY",
        "ARMOURY CRATE", "Armoury Crate", "ROG Pugio", "Mystic Light",
        "CORSAIR LINK", "LINK 6", "KeyRemap", "MousePro", "KeyPro",
        "Dragon Center", "iGame", "AURA", "AURA Creator",
    ]
    q.extend(overlays)

    # Dedupe while preserving order (first wins), case-insensitive.
    seen: set[str] = set()
    out: list[str] = []
    for item in q:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return tuple(out)


DEFAULT_QUERIES: tuple[str, ...] = _build_default_queries()

# Keep only results whose title or classification contains any of these — the
# catalog returns a lot of adjacent/unrelated drivers for broad brand queries.
# Expanded for the mass-query bank: also recognizes "input device", "composite",
# "digitizer" + a long tail of brand/model keywords.
HID_SHAPE_PATTERNS = re.compile(
    r"\b("
    r"mouse|mice|keyboard|kbd|pointer|hid|touchpad|clickpad|trackpad|"
    r"trackball|stylus|digitizer|pen\s+driver|input\s+device|"
    r"human\s+interface|composite\s+hid|"
    # vendor / brand / model keywords — mirror the query bank
    r"synapse|chroma|icue|cue|g\s*hub|lghub|setpoint|options\+?|"
    r"ngenuity|armoury|armoury\s*crate|mystic\s*light|dragon\s*center|"
    r"aura|aura\s*creator|"
    r"ducky|cherry|glorious|mountain|akko|keychron|wooting|redragon|"
    r"bloody|zowie|endgame|lamzu|pulsar|vaxee|fantech|finalmouse|"
    r"ninjutso|monsgeek|darmoshark|royal\s*kludge|"
    r"basilisk|deathadder|naga|mamba|lancehead|krait|abyssus|viper|"
    r"intellimouse|sidewinder|arc\s*mouse|precision\s*mouse|"
    r"ergonomic|modern\s*mobile|comfort\s*mouse|comfort\s*keyboard|"
    r"katar|harpoon|ironclaw|scimitar|nightsword|sabre|"
    r"aerox|prime|rival|sensei|kana|apex|"
    r"pulsefire|alloy|haste|"
    r"kone|kain|burst|vulcan|suora|pyro|"
    r"r\.a\.t\.|rat\s*mouse|strike|cyborg|eclipse|pro\s*flight|"
    r"strix|tuf\s*gaming|chakram|gladius|keris|pugio|claymore|thunder|"
    r"alienware|omen\s*mouse|omen\s*keyboard|"
    r"n-?trig|duosense|wacom|intuos|cintiq|bamboo|surface\s*pen|slim\s*pen|dial|"
    r"xp-?pen|huion|"
    r"synaptics|elan|alps(?:alpine)?|cypress|"
    r"gaming\s*mouse|gaming\s*keyboard|mechanical\s*keyboard|"
    r"wireless\s*(?:mouse|keyboard)|bluetooth\s*(?:mouse|keyboard)|"
    r"usb[\\\s_]*vid[\\\s_]*[0-9a-f]{4}"
    r")\b",
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
        self.max_pages = max(1, _env_int("PDT_MSC_MAX_PAGES", 40))
        self.browser_workers = max(1, _env_int("PDT_MSC_BROWSER_WORKERS", 6))
        # Interleave size: how many queries to discover before pausing to download
        # what they turned up (then loop back for the next batch). Default keeps
        # every browser busy for a few queries per round. 0 disables the loop —
        # discover everything, then download everything (the old two-phase flow).
        self.batch_queries = _env_int("PDT_MSC_BATCH_QUERIES",
                                      max(self.browser_workers * 4, 1))
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._url_source: dict[str, dict] = {}
        self._resolved_uids: set[str] = set()

    # ----- discovery -----

    def _search_paged_chunk(self, queries: list[str],
                            rep_fn, cnt_fn, slot_fn) -> list[dict]:
        """Walk up to `max_pages` pages per query via Playwright. One browser per
        chunk, serial.

        The catalog's ASP.NET postback (ctl00$catalogBody$nextPageLinkText) is
        blocked for urllib — it returns a generic 500 error page after one hop.
        A real browser passes through fine, so discovery always drives Chromium
        headless; Playwright + its chromium build must be present in the image.

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
        except ImportError as exc:
            progress.clear_slot()
            raise RuntimeError(
                "msupdate-catalog discovery requires Playwright + chromium "
                "(the catalog paginates via an ASP.NET postback urllib cannot "
                "follow). Install with `pip install playwright` and "
                "`playwright install chromium`.") from exc
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

    def _search_all(self, queries: list[str], rows_by_uid: dict[str, dict],
                    rep_fns=None) -> None:
        """Fan out `queries` over the browser pool, ingesting hid-shaped rows
        into `rows_by_uid` (deduped by UID, accumulating the matching queries).

        One headless Chromium per worker; each worker walks a chunk of queries
        serially, clicking through up to `max_pages` pages per query (the catalog
        paginates via an ASP.NET postback urllib cannot follow)."""
        if rep_fns is None:
            rep_fns = progress.current_reporters()
        rep_fn, cnt_fn, slot_fn = rep_fns

        def _ingest(rows: list[dict]) -> None:
            for row in rows:
                if not _hid_shaped(row):
                    continue
                r = rows_by_uid.setdefault(row["uid"], row)
                r.setdefault("queries", [])
                if row["query"] not in r["queries"]:
                    r["queries"].append(row["query"])

        k = max(1, min(self.browser_workers, len(queries)))
        chunks: list[list[str]] = [[] for _ in range(k)]
        for i, q in enumerate(queries):
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

    def _resolve_new(self, rows_by_uid: dict[str, dict], seen_urls: set[str]) -> list[str]:
        """Resolve direct CDN URLs for UIDs not yet resolved. Mutates
        `self._resolved_uids`, `self._url_source` and `seen_urls`; returns the
        newly-resolved URLs (deduped, in completion order)."""
        uids = [u for u in rows_by_uid if u not in self._resolved_uids]
        if not uids:
            return []
        new_urls: list[str] = []
        rworkers = max(1, min(self.crawl_jobs, len(uids)))
        done = 0

        def resolve_one(uid: str) -> tuple[str, str | None]:
            return uid, self._resolve_url(uid)

        with ThreadPoolExecutor(max_workers=rworkers) as pool:
            futs = {pool.submit(resolve_one, u): u for u in uids}
            for fut in as_completed(futs):
                done += 1
                uid, url = fut.result()
                self._resolved_uids.add(uid)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    new_urls.append(url)
                    self._url_source[url] = {
                        "uid": uid,
                        **{k: rows_by_uid[uid].get(k)
                           for k in ("title", "product", "classification",
                                     "date", "version", "size_bytes",
                                     "queries")},
                    }
                progress.report(
                    f"resolve: {done}/{len(uids)} · {len(new_urls)} new direct URLs")
        return new_urls

    def discover(self) -> dict:
        """Full two-phase discovery: walk every query, then resolve every UID.

        `run()` uses the interleaved batch loop instead; this standalone path is
        kept for direct callers and the discovery-cache-only flow."""
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

        progress.report(
            f"searching {len(self.queries)} queries × up to {self.max_pages} "
            f"pages via Playwright ({self.browser_workers} browsers)")
        rows_by_uid: dict[str, dict] = {}
        self._search_all(list(self.queries), rows_by_uid)
        progress.report(f"resolving {len(rows_by_uid)} download URLs")
        seen: set[str] = set()
        urls = self._resolve_new(rows_by_uid, seen)
        self._urls = urls[: self.max_packs] if self.max_packs else urls
        info = {
            "discovery_page": BASE + "/",
            "installer_url": None,
            "queries": list(self.queries),
            "hits": len(rows_by_uid),
            "packs_resolved": len(urls),
            "jobs": self.jobs,
            "max_mb": self.max_mb,
        }
        self._save_discovery_cache(info, self._urls, self._url_source)
        info["discovery_cache"] = {
            "hit": False, "saved_at": C.utc_now(),
            "path": str(self._discovery_cache_path()),
        }
        return info

    # ----- interleaved run: discover a batch → download it → next batch -----

    def run(self) -> dict:
        """Override the base one-shot discover→acquire with an interleaved loop.

        The default source has 595 queries; discovering all of them before any
        download means nothing lands for a long time. Instead we walk the queries
        in batches of `batch_queries`: discover a batch, resolve + download what
        it turned up, then loop to the next batch — so drivers start arriving
        early and discovery overlaps download. A discovery-cache hit or
        `batch_queries <= 0` falls back to the plain discover()+acquire() path."""
        run_id = C.utc_now_compact()
        work_dir = config.collectors_dir() / self.name / run_id
        work_dir.mkdir(parents=True, exist_ok=True)
        C.sweep_stale_work(work_dir.parent, run_id)
        manifest: dict = {
            "schema_version": 1, "collector": self.name,
            "collector_role": self.role, "pipeline_version": PIPELINE_VERSION,
            "run_id": run_id, "started_at": C.utc_now(),
            "allowed_hosts": list(self.allowed_hosts), "status": "pending",
            "discovery": None, "downloads": [], "drivers": [], "error": None,
        }
        try:
            cached = self._load_discovery_cache()
            if cached is not None or self.batch_queries <= 0:
                # Cache hit, or loop disabled: plain two-phase flow.
                info = self.discover()
                drivers = self.acquire(work_dir, info)
                manifest["downloads"].extend(info.pop("downloads_top", []))
                self._attach_and_index(drivers, info)
                manifest["drivers"] = drivers
                manifest["discovery"] = info
            else:
                drivers, info = self._run_interleaved(work_dir, manifest)
                manifest["drivers"] = drivers
                manifest["discovery"] = info
            manifest["status"] = "success" if manifest["drivers"] else "no_driver_extracted"
        except Exception as exc:
            manifest["status"] = "failed"
            manifest["error"] = {"type": type(exc).__name__, "message": str(exc),
                                 "traceback": traceback.format_exc()}
        finally:
            manifest["finished_at"] = C.utc_now()
            C.save_json(work_dir / "manifest.json", manifest)
            self._update_latest(work_dir)
        return manifest

    def _run_interleaved(self, work_dir: Path, manifest: dict) -> tuple[list[dict], dict]:
        refresh = os.environ.get("PDT_MSC_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        ledger_at_start = len(processed)

        rows_by_uid: dict[str, dict] = {}
        seen_urls: set[str] = set()
        all_rows: list[dict] = []
        downloads: list[dict] = []
        errors: list[dict] = []
        stats = {"found": 0, "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}

        queries = list(self.queries)
        bs = self.batch_queries
        batches = [queries[i:i + bs] for i in range(0, len(queries), bs)]
        n_batches = len(batches)
        progress.report(
            f"interleaved sweep: {len(queries)} queries in {n_batches} batch(es) "
            f"of {bs} × up to {self.max_pages} pages ({self.browser_workers} browsers)")

        for bi, batch in enumerate(batches, 1):
            if self.max_packs and len(self._urls) >= self.max_packs:
                break
            progress.report(f"batch {bi}/{n_batches}: discovering {len(batch)} queries")
            self._search_all(batch, rows_by_uid)
            new_urls = self._resolve_new(rows_by_uid, seen_urls)
            if self.max_packs:
                room = self.max_packs - len(self._urls)
                new_urls = new_urls[: max(0, room)]
            self._urls.extend(new_urls)
            stats["found"] = len(self._urls)
            if not new_urls:
                continue
            progress.report(f"batch {bi}/{n_batches}: downloading {len(new_urls)} pack(s)")
            batch_rows = self._download_batch(work_dir, new_urls, processed,
                                              downloads, errors, stats)
            if batch_rows:
                info_stub = {"discovery_page": BASE + "/", "installer_url": None}
                self._attach_and_index(batch_rows, info_stub)
                all_rows.extend(batch_rows)
                manifest["drivers"] = all_rows  # live-update for crash safety
            manifest["downloads"] = downloads

        # Persist the full discovered universe for next run's cache.
        info = {
            "discovery_page": BASE + "/", "installer_url": None,
            "queries": queries, "hits": len(rows_by_uid),
            "packs_resolved": len(self._urls), "jobs": self.jobs,
            "max_mb": self.max_mb, "batches": n_batches,
            "batch_queries": bs, "interleaved": True,
            "stats": stats, "errors": errors[:500], "error_count": len(errors),
            "ledger_at_start": ledger_at_start,
            "resumed": (not refresh) and stats["skipped_seen"] > 0,
        }
        self._save_discovery_cache(
            {k: info[k] for k in ("discovery_page", "installer_url", "queries",
                                  "hits", "packs_resolved", "jobs", "max_mb")},
            self._urls, self._url_source)
        info["discovery_cache"] = {
            "hit": False, "saved_at": C.utc_now(),
            "path": str(self._discovery_cache_path()),
        }
        return all_rows, info

    def _attach_and_index(self, drivers: list[dict], info: dict) -> None:
        """Mirror the base framework: stamp source provenance onto each driver and
        append it to the store index (the analysis line was written at store
        time; this adds origin)."""
        for d in drivers:
            d.setdefault("provenance", {}).update({
                "source": self.name,
                "discovery_page": info.get("discovery_page"),
                "installer_url": info.get("installer_url"),
            })
            C.append_index(config.drivers_dir(),
                           {"sha256": d["sha256"], "provenance": d.get("provenance")})

    # ----- acquisition -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_MSC_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()

        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(self._urls), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}

        rows = self._download_batch(work_dir, self._urls, processed,
                                    downloads, errors, stats)

        info["stats"] = stats
        info["errors"] = errors[:500]
        info["error_count"] = len(errors)
        info["downloads_top"] = downloads
        info["ledger_at_start"] = len(processed)
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    def _download_batch(self, work_dir: Path, urls: list[str], processed: set[str],
                        downloads: list[dict], errors: list[dict],
                        stats: dict) -> list[dict]:
        """Download + extract a set of resolved URLs in parallel. Shared by the
        interleaved loop and the standalone acquire(). Mutates `downloads`,
        `errors`, `stats` and `processed`; returns the driver rows collected."""
        rows: list[dict] = []
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
            list(pool.map(handle, urls))
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
