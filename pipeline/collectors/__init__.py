"""Collector registry.

This project targets a single, narrowly-scoped corpus: Windows kernel drivers
shipped alongside input peripherals (keyboard, mouse). Both sources share the
properties the community archives (DriverGuide, Softpedia, DriverScape) lacked —
no rate limiting on a sustained single-IP sweep, and real kernel `.sys` inside:
  * msupdate-catalog — the Microsoft Update Catalog (WHQL-signed; Playwright).
  * vendor-catalog   — Dell + HP OEM driver catalogs (plain XML, direct CDNs).
"""
from __future__ import annotations
from typing import Callable

from .base import Collector
from .msupdate_catalog import collector as _msupdate_catalog
from .vendor_catalog import collector as _vendor_catalog


REGISTRY: dict[str, Callable[[], Collector]] = {
    "msupdate-catalog": _msupdate_catalog,
    "vendor-catalog": _vendor_catalog,
}


def available() -> list[str]:
    return sorted(REGISTRY.keys())


def get(name: str) -> Collector:
    if name not in REGISTRY:
        raise KeyError(f"unknown collector '{name}'. available: {available()}")
    return REGISTRY[name]()
