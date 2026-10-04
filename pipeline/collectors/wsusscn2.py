"""Microsoft WSUS offline scan catalog — driver update bulk enumerator.

Microsoft publishes a signed CAB that enumerates every Update ever shipped
through Windows Update, for use by WUA's offline scan mode (`wsusscn2.cab`,
~670 MB today). Of those ~137 k Updates, ~19 k are classified as drivers.
Each driver bundle is linked to child Updates whose `<PayloadFiles>` reference
CAB files on the `catalog.s.download.windowsupdate.com` CDN — those CABs
contain the actual WHQL-signed `.sys`.

This is the broadest public source of WHQL drivers that exists; it covers
every manufacturer, every architecture, every generation. For input-driver
research the HID-shape overlap is small (most are chipset/net/graphics) but
after the pipeline's existing HID bucket scoring, the tail of hits is still
large and includes many drivers the brand-oriented collectors miss.

Catalog URL: https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/
             wsusscan/wsusscn2.cab
Driver classification GUID (standard WSUS, constant): 0fa1201d-4330-4fa8-
             8ae9-b877473b6441

Flow:

  1. `discover()`:
       - download `wsusscn2.cab` (~670 MB) under the configured allowlist.
       - 7-Zip extract the outer -> `index.xml` + `package.cab`/.../
         `packageN.cab`. We only need `package.cab`.
       - 7-Zip extract `package.cab` -> `package.xml` (~110 MB).
       - stream-parse in one pass, holding a few compact dicts in RAM:
          * driver_bundles: RevisionId -> UpdateId  (parent bundles whose
            Categories include the Drivers classification GUID)
          * file_locations: FileId -> {Url, Size, DigestAlgorithm, Digest}
          * payloads: for every Update whose BundledBy.Revision.Id is in
            driver_bundles, record its PayloadFiles' FileIds.
       - resolve: for every bundle, collect the FileIds from its child
         payload Updates, map them to URLs via file_locations. Dedup by URL.
       - cache the resolved URL universe for reuse.

  2. `acquire()`:
       - download each driver CAB under `PDT_WSUS_MAX_MB` (default 100).
         Most are 50 KB - 5 MB; a long tail of graphics drivers can exceed
         50 MB.
       - 7-Zip extract; harvest `.sys` to the content-addressed store.

Everything static: no CAB is executed, host allowlist enforced, HTTPS only,
magic validated.

Environment knobs:
- `PDT_WSUS_CATALOG_URL`     (str)       default: official URL above
- `PDT_WSUS_JOBS`            (int)       default: 8
- `PDT_WSUS_MAX_PACKS`       (int)       default: 0 (unlimited)
- `PDT_WSUS_MAX_MB`          (int)       default: 100 (per driver CAB)
- `PDT_WSUS_REFRESH=1`                   ignore download ledger
- `PDT_WSUS_REFRESH_DISCOVERY=1`         ignore discovery cache
- `PDT_WSUS_DISCOVERY_TTL_DAYS` (int)    default: 7
- `PDT_WSUS_KEEP_CATALOG=1`              retain extracted wsusscn2 files
                                         (default is to prune after discovery)
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


CATALOG_URL = ("https://catalog.s.download.windowsupdate.com"
               "/microsoftupdate/v6/wsusscan/wsusscn2.cab")
ALLOWED_HOSTS = [
    # wsusscn2 publishes URLs on `download.windowsupdate.com` and
    # `www.download.windowsupdate.com`, both of which answer HTTP cleanly but
    # whose HTTPS cert chain only covers `catalog.s.download.windowsupdate.com`
    # — the same CDN origin. We rewrite the hostname on normalise, so the only
    # host we actually fetch from is the TLS-valid one.
    "catalog.s.download.windowsupdate.com",
    "catalog.update.microsoft.com",
]

# Hostnames in wsusscn2 whose paths resolve on the TLS-valid CDN origin above.
# The server content is identical; the Delivery Optimization CDN
# (`dl.delivery.mp.microsoft.com`) is NOT a mirror — it uses a different path
# layout and distinct TLS cert chain, so those URLs are dropped at discovery.
REWRITE_TO_TLS_ORIGIN = frozenset({
    "download.windowsupdate.com",
    "www.download.windowsupdate.com",
})
TLS_ORIGIN_HOST = "catalog.s.download.windowsupdate.com"

# Fixed WSUS taxonomy identifier for the "Drivers" classification.
DRIVERS_CLASSIFICATION_GUID = "0fa1201d-4330-4fa8-8ae9-b877473b6441"

RX_NS = re.compile(r"^\{[^}]+\}")


def _localtag(tag: str) -> str:
    return RX_NS.sub("", tag)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


# Filenames classified as "Drivers" by WSUS taxonomy that are nevertheless
# not driver bytes. Catching them at URL time avoids pulling tens of GB of
# language packs and update metadata into the pipeline for 0 .sys yield.
_RX_NON_DRIVER_FILENAME = re.compile(
    r"(?:"
    r"wsus\.aggregatedmetadata"      # per-update metadata rollup
    r"|^windows[-._]"                 # cumulative Windows updates (kb*)
    r"|-kb\d{6,}"                     # KB-articled servicing packs
    r"|wssmui-"                       # Windows Server Storage MUI
    r"|^[a-z]+mui-"                   # generic *mui- language packs
    r"|langpack|lxp[-_]|language"    # language-pack variants
    r"|baseless"                      # Progressive Sync Framework base
    r")",
    re.I,
)

# Extensions we skip even if WSUS claims they're driver payloads.
_SKIP_EXTENSIONS = {".psf", ".esd", ".wim"}


def _normalise_url(url: str) -> str | None:
    """Return the HTTPS form of a wsusscn2 URL on a TLS-valid host, or None
    if the URL cannot be served over HTTPS at all or clearly isn't a driver
    binary.

    wsusscn2's `Url` attributes are `http://` for backward compat with WUA's
    offline-scan client. Most point at CDN mirrors whose paths also resolve on
    `catalog.s.download.windowsupdate.com` (the TLS-valid host). URLs on the
    Delivery Optimization CDN use a different path layout and cannot be
    rehomed — we drop them (less than 3 % of the catalog). The driver
    classification in WSUS is also noisy: it bundles language packs, metadata
    rollups, cumulative Windows updates and Progressive Sync Framework
    deltas, so we reject obvious non-driver filename shapes up front rather
    than download them for 0 `.sys` yield.
    """
    from urllib.parse import urlparse, urlunparse
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if host == TLS_ORIGIN_HOST:
        pass
    elif host in REWRITE_TO_TLS_ORIGIN:
        parsed = parsed._replace(netloc=TLS_ORIGIN_HOST)
    else:
        return None  # unmirrored host
    parsed = parsed._replace(scheme="https")
    # Filename-shape blocklist
    fname = (parsed.path or "").rsplit("/", 1)[-1].lower()
    ext = ""
    if "." in fname:
        ext = "." + fname.rsplit(".", 1)[-1]
    if ext in _SKIP_EXTENSIONS:
        return None
    if _RX_NON_DRIVER_FILENAME.search(fname):
        return None
    return urlunparse(parsed)


def _date_sort_rank(iso: str) -> int:
    """Convert an ISO-8601 timestamp to a monotonic int for sort_key use.

    Returns 0 for empty / malformed strings (which then sink to the end when
    sorting newest-first via negation). Years ~1900-9999 fit easily."""
    if not iso or len(iso) < 10:
        return 0
    try:
        y = int(iso[:4]); m = int(iso[5:7]); d = int(iso[8:10])
        return y * 10000 + m * 100 + d
    except ValueError:
        return 0


class WsusScn2Collector(Collector):
    name = "wsusscn2"
    role = "Microsoft WSUS offline scan catalog — all WHQL drivers"
    allowed_hosts = list(ALLOWED_HOSTS)

    def __init__(self) -> None:
        self.catalog_url = os.environ.get("PDT_WSUS_CATALOG_URL", CATALOG_URL)
        self.jobs = _env_int("PDT_WSUS_JOBS", 8)
        self.max_packs = _env_int("PDT_WSUS_MAX_PACKS", 0)
        self.max_mb = _env_int("PDT_WSUS_MAX_MB", 100)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []
        self._url_source: dict[str, dict] = {}

    # ----- discovery -----

    def _config_fingerprint(self) -> str:
        payload = json.dumps({"catalog": self.catalog_url}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def _discovery_cache_path(self) -> Path:
        return (config.collectors_dir() / self.name /
                f"discovery_cache_{self._config_fingerprint()}.json")

    def _load_discovery_cache(self) -> dict | None:
        if os.environ.get("PDT_WSUS_REFRESH_DISCOVERY", "") not in ("", "0", "false"):
            return None
        p = self._discovery_cache_path()
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        ttl_days = _env_int("PDT_WSUS_DISCOVERY_TTL_DAYS", 7)
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
            "info": info,
            "urls": urls,
            "url_source": url_source,
        }
        p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    def _parse_package_xml(self, pxml: Path) -> tuple[list[str], dict[str, dict], dict]:
        """Walk the ~110 MB package.xml once, extracting driver-update CAB URLs.

        The WSUS schema puts the download URLs in a single trailing
        `<FileLocations>` block, keyed by File Id (a base64 hash). Each
        `<Update>` whose Categories include the Drivers classification GUID is
        a bundle; its child Updates (identified by `<BundledBy><Revision
        Id=...>`) carry the actual `<PayloadFiles>` referencing those File
        Ids. We collect everything in one streaming pass and resolve at the
        end.
        """
        progress.report(f"parsing {pxml.stat().st_size // (1<<20)} MB package.xml")

        # bundle_revisions: RevisionId -> parent UpdateId
        bundle_revisions: dict[str, dict] = {}
        # revision -> list of (file_id, ...)
        payload_by_revision: dict[str, list[str]] = {}
        # file_id -> {url, size, digest}
        file_locations: dict[str, dict] = {}

        # child_updates stashes (child_update_id, [file_ids], [bundled_by_revids])
        # — we resolve them at the end once bundle_revisions is complete.
        pending_children: list[tuple[str, list[str], list[str]]] = []
        considered = 0
        ctx = ET.iterparse(str(pxml), events=("end",))
        for _, el in ctx:
            tag = _localtag(el.tag)
            if tag == "FileLocation":
                fid = el.attrib.get("Id")
                url = el.attrib.get("Url")
                if fid and url and url.lower().startswith("http"):
                    url = _normalise_url(url)
                if fid and url:
                    file_locations[fid] = {
                        "url": url,
                        "size": int(el.attrib.get("Size") or 0),
                        "digest": el.attrib.get("Digest") or "",
                        "digest_algorithm": el.attrib.get("DigestAlgorithm") or "",
                        "modified": el.attrib.get("Modified") or "",
                    }
                el.clear()
                continue
            if tag != "Update":
                continue
            considered += 1
            update_id = el.attrib.get("UpdateId") or ""
            revision_id = el.attrib.get("RevisionId") or ""
            creation_date = el.attrib.get("CreationDate") or ""
            is_driver = False
            payload_file_ids: list[str] = []
            bundled_by_revids: list[str] = []
            superseded = False
            for ch in el:
                ctag = _localtag(ch.tag)
                if ctag == "Categories":
                    for c in ch:
                        if _localtag(c.tag) != "Category":
                            continue
                        if (c.attrib.get("Type") == "UpdateClassification" and
                                c.attrib.get("Id") == DRIVERS_CLASSIFICATION_GUID):
                            is_driver = True
                elif ctag == "PayloadFiles":
                    for f in ch:
                        if _localtag(f.tag) == "File":
                            fid = f.attrib.get("Id")
                            if fid:
                                payload_file_ids.append(fid)
                elif ctag == "BundledBy":
                    for r in ch:
                        if _localtag(r.tag) == "Revision":
                            rid = r.attrib.get("Id")
                            if rid:
                                bundled_by_revids.append(rid)
                elif ctag == "SupersededBy":
                    superseded = True
            if is_driver and revision_id:
                bundle_revisions[revision_id] = {
                    "update_id": update_id,
                    "creation_date": creation_date,
                    "superseded": superseded,
                }
            if payload_file_ids and bundled_by_revids:
                pending_children.append(
                    (update_id, payload_file_ids, bundled_by_revids)
                )
            el.clear()
            if considered % 20000 == 0:
                progress.report(
                    f"package.xml: {considered} updates seen · "
                    f"{len(bundle_revisions)} driver bundles · "
                    f"{len(file_locations)} file locations"
                )

        progress.report(
            f"package.xml: {considered} updates · "
            f"{len(bundle_revisions)} driver bundles · "
            f"{len(file_locations)} file locations · "
            f"{len(pending_children)} payload children"
        )

        # Resolve: for every pending child whose any parent revision is a
        # driver bundle, map its file_ids to URLs.
        url_source: dict[str, dict] = {}
        for child_update_id, file_ids, parent_revisions in pending_children:
            matching_parents = [
                bundle_revisions[rid]
                for rid in parent_revisions
                if rid in bundle_revisions
            ]
            if not matching_parents:
                continue
            # Pick the first matching parent as the "owner" for provenance;
            # a child can be bundled by several parents but one is enough to
            # trace back from (and the parent's UpdateId is the catalog UID).
            parent = matching_parents[0]
            superseded = all(p.get("superseded") for p in matching_parents)
            for fid in file_ids:
                loc = file_locations.get(fid)
                if not loc:
                    continue
                url = loc["url"]
                # dedupe by URL; first-wins preserves oldest UID,
                # but we track every parent we found via file_ids pointing to
                # the same URL (collisions are rare in practice).
                if url in url_source:
                    continue
                url_source[url] = {
                    "parent_update_id": parent.get("update_id"),
                    "parent_creation_date": parent.get("creation_date"),
                    "parent_superseded": parent.get("superseded"),
                    "all_parents_superseded": superseded,
                    "child_update_id": child_update_id,
                    "file_id": fid,
                    "file_size": loc.get("size"),
                    "file_digest": loc.get("digest"),
                    "file_digest_algorithm": loc.get("digest_algorithm"),
                    "file_modified": loc.get("modified"),
                    "url": url,
                }

        # Rank: live (not superseded) first, then newest first within each bucket.
        def _sortkey(u: str) -> tuple[int, int]:
            s = url_source[u]
            superseded_flag = 1 if s.get("all_parents_superseded") else 0
            return (superseded_flag, -_date_sort_rank(s.get("parent_creation_date") or ""))

        urls = sorted(url_source.keys(), key=_sortkey)

        info = {
            "updates_considered": considered,
            "driver_bundles": len(bundle_revisions),
            "driver_bundles_live": sum(
                1 for b in bundle_revisions.values() if not b.get("superseded")
            ),
            "file_locations": len(file_locations),
            "resolved_urls": len(url_source),
        }
        return urls, url_source, info

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
            progress.report(f"discovery cache hit: {len(self._urls)} driver URLs")
            return info

        work_dir = config.collectors_dir() / self.name / "_discovery"
        work_dir.mkdir(parents=True, exist_ok=True)

        # 1. Download wsusscn2.cab (big!)
        cab = work_dir / "wsusscn2.cab"
        progress.report("downloading wsusscn2.cab (~670 MB)")
        rec = C.download(self.catalog_url, cab, self.allowed_hosts,
                         max_mb=1500, timeout=3600)

        # 2. Extract outer
        outer_dir = work_dir / "outer"
        for p in outer_dir.glob("*"):
            try:
                p.unlink()
            except OSError:
                pass
        outer_dir.mkdir(parents=True, exist_ok=True)
        progress.report("extracting outer wsusscn2.cab")
        C.extract(cab, outer_dir, timeout=900)
        inner_cab = outer_dir / "package.cab"
        if not inner_cab.exists():
            raise RuntimeError(
                "wsusscn2.cab did not contain package.cab (unexpected schema)"
            )

        # 3. Extract package.cab -> package.xml
        inner_dir = work_dir / "inner"
        for p in inner_dir.glob("*"):
            try:
                p.unlink()
            except OSError:
                pass
        inner_dir.mkdir(parents=True, exist_ok=True)
        progress.report("extracting package.cab")
        C.extract(inner_cab, inner_dir, timeout=600)
        pxml = next(inner_dir.rglob("package.xml"), None)
        if pxml is None:
            raise RuntimeError("package.cab did not contain package.xml")

        urls, url_source, parse_info = self._parse_package_xml(pxml)

        info = {
            "discovery_page": self.catalog_url,
            "installer_url": None,
            "catalog_sha256": rec["sha256"],
            "catalog_size": rec["size"],
            "catalog_final_url": rec["final_url"],
            **parse_info,
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

        # 4. Clean the catalog extraction tree unless the caller asked to keep.
        if os.environ.get("PDT_WSUS_KEEP_CATALOG", "") in ("", "0", "false"):
            try:
                C.prune_dir(work_dir)
            except Exception:
                pass

        return info

    # ----- acquire -----

    def _processed_ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_processed(self) -> set[str]:
        if os.environ.get("PDT_WSUS_REFRESH", "") not in ("", "0", "false"):
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
        adv_size = int(src.get("file_size") or 0)
        if adv_size and adv_size > self.max_mb * (1 << 20):
            self._mark_processed(url, "skipped_oversized",
                                 {"size": adv_size, "max_mb": self.max_mb})
            return []
        fname = Path(url.rsplit("/", 1)[-1]).name or "update.cab"
        pkg_dir = work_dir / "packages" / hashlib.sha1(url.encode()).hexdigest()[:12]
        pkg_dir.mkdir(parents=True, exist_ok=True)
        pkg = pkg_dir / fname
        extracted = pkg_dir / "extracted"
        try:
            rec = C.download(url, pkg, self.allowed_hosts,
                             max_mb=self.max_mb, timeout=300)
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
                "wsus_parent_update_id": src.get("parent_update_id"),
                "wsus_parent_creation_date": src.get("parent_creation_date"),
                "wsus_parent_superseded": src.get("parent_superseded"),
                "wsus_child_update_id": src.get("child_update_id"),
                "wsus_file_id": src.get("file_id"),
                "wsus_file_size": src.get("file_size"),
                "wsus_file_digest": src.get("file_digest"),
                "wsus_file_digest_algorithm": src.get("file_digest_algorithm"),
            }
        self._mark_processed(url, "ok", {
            "sha256": rec["sha256"],
            "drivers": len(rows),
        })
        C.prune_dir(pkg_dir)
        return rows

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        if not self._urls:
            progress.report("discovery produced no driver URLs; nothing to acquire")
            return []
        done = self._load_processed()
        todo = [u for u in self._urls if u not in done]
        if not todo:
            progress.report(
                f"all {len(self._urls)} driver updates already processed; nothing new"
            )
            return []
        progress.report(f"acquiring {len(todo)} driver update(s) "
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
                if done_count % 25 == 0 or done_count == len(todo):
                    progress.report(
                        f"updates: {done_count}/{len(todo)} · "
                        f"{len(rows)} driver record(s) emitted"
                    )
        return rows


def collector() -> WsusScn2Collector:
    return WsusScn2Collector()
