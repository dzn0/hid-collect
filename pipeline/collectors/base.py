"""Collector base class.

A collector encapsulates: discovery (resolve the current download URL from a
vendor's public entry point) + acquisition (download + extract + emit drivers).

Each run writes `manifest.json` under `pipeline_out/collectors/<name>/<run_id>/`.
The manifest is the artifact the DrvEye adapter consumes; it is schema-stable
across collectors so the adapter can process any source uniformly.
"""
from __future__ import annotations
import traceback
from pathlib import Path
from urllib.parse import urlparse

from .. import __version__ as PIPELINE_VERSION
from .. import config
from .. import progress
from . import _common as C


class Collector:
    """Subclass contract:

    - `name`: short slug used in output paths and the manifest.
    - `allowed_hosts`: hostnames (and *.hostname) this collector may fetch from.
    - `discover()` -> dict{installer_url, discovery_page?, extras?} — resolve
      the current vendor-hosted URL.
    - `acquire(work_dir, info)` -> list[dict] — download, extract, and return
      the per-driver rows (shape from `collect_sys_files`).
    """

    name: str = ""
    allowed_hosts: list[str] = []
    role: str = ""  # free-text, e.g. "OEM" / "Monitoring utility" / etc.

    # ----- subclass API -----

    def discover(self) -> dict:
        raise NotImplementedError

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        raise NotImplementedError

    # ----- framework -----

    def run(self) -> dict:
        if not self.name:
            raise RuntimeError("Collector.name must be set")
        run_id = C.utc_now_compact()
        work_dir = config.collectors_dir() / self.name / run_id
        work_dir.mkdir(parents=True, exist_ok=True)
        # Reclaim orphaned package/extraction trees left by prior interrupted runs
        # of this collector before starting (per-package prune misses those).
        C.sweep_stale_work(work_dir.parent, run_id)
        manifest: dict = {
            "schema_version": 1,
            "collector": self.name,
            "collector_role": self.role,
            "pipeline_version": PIPELINE_VERSION,
            "run_id": run_id,
            "started_at": C.utc_now(),
            "allowed_hosts": list(self.allowed_hosts),
            "status": "pending",
            "discovery": None,
            "downloads": [],
            "drivers": [],
            "error": None,
        }
        try:
            progress.report("resolving source URL")
            info = self.discover()
            manifest["discovery"] = info
            progress.report("acquiring")
            drivers = self.acquire(work_dir, info)
            # Bubble per-collector downloads up to the top-level manifest so the
            # adapter has one canonical place to look.
            if "downloads_top" in info:
                manifest["downloads"].extend(info.pop("downloads_top"))
            for d in drivers:
                d.setdefault("provenance", {}).update({
                    "source": self.name,
                    "discovery_page": info.get("discovery_page"),
                    "installer_url": info.get("installer_url"),
                })
            manifest["drivers"] = drivers
            manifest["status"] = "success" if drivers else "no_driver_extracted"
        except Exception as exc:
            manifest["status"] = "failed"
            manifest["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            }
        finally:
            manifest["finished_at"] = C.utc_now()
            C.save_json(work_dir / "manifest.json", manifest)
            self._update_latest(work_dir)
        return manifest

    def _update_latest(self, run_dir: Path) -> None:
        """Write a sibling `latest.json` pointing at this run."""
        latest = run_dir.parent / "latest.json"
        C.save_json(latest, {"run_id": run_dir.name, "run_dir": str(run_dir)})


class SimpleArchiveCollector(Collector):
    """Base for the common case: one pinned vendor archive → 7-Zip → drivers.

    A subclass sets `name`, `role`, `allowed_hosts`, `installer_url`, and
    optionally `discovery_page`, `max_mb`, and `include_native_pe` (True for MSI
    / PE-resource sources whose drivers are not `.sys`-suffixed on disk). This
    mirrors the WinDivert reference collector; anything needing multi-stage
    extraction (CAB carving, innoextract, SoftPaq, PE-resource two-step) must
    subclass `Collector` directly instead.
    """

    installer_url: str = ""
    discovery_page: str | None = None
    max_mb: int = 300
    include_native_pe: bool = False
    recurse: bool = True  # extract a nested installer if the first pass finds none
    pe_resource: bool = False  # driver embedded as a PE resource in an app .exe

    def discover(self) -> dict:
        if not self.installer_url:
            raise RuntimeError(f"{self.name}: installer_url not set")
        return {"discovery_page": self.discovery_page,
                "installer_url": self.installer_url,
                "candidates": [self.installer_url]}

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        url = info["installer_url"]
        pkg = work_dir / "packages" / Path(urlparse(url).path).name
        extracted = work_dir / "extracted"
        rec = C.download(url, pkg, self.allowed_hosts, max_mb=self.max_mb)
        info.setdefault("downloads_top", []).append(rec)
        C.extract(pkg, extracted)

        if self.pe_resource:
            # driver lives as a PE resource inside the app .exe(s): 7z -tPE each.
            resources = work_dir / "resources"
            for exe in sorted(extracted.rglob("*.exe")):
                C.extract_pe_resources(exe, resources / exe.name)
            search_root = resources
        else:
            search_root = extracted

        rows = C.collect_sys_files(search_root, config.drivers_dir(),
                                   include_native_pe=self.include_native_pe)
        tries = 0
        while not rows and self.recurse and not self.pe_resource and tries < 2:
            # installer wrapped in another installer, up to a few levels deep
            # (NSIS setup.exe in a zip; WiX Burn exe -> CABs in a zip; …).
            # extract_nested skips already-unpacked dirs, so each pass only
            # touches newly-revealed archives.
            produced = C.extract_nested(extracted)
            if not produced:
                break
            rows = C.collect_sys_files(extracted, config.drivers_dir(),
                                       include_native_pe=self.include_native_pe)
            tries += 1
        for r in rows:
            r["provenance"] = {
                "installer_sha256": rec["sha256"],
                "installer_size": rec["size"],
                "installer_final_url": rec["final_url"],
            }
        return rows


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()
