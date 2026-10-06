"""Collector registry.

This project targets a single, narrowly-scoped corpus: Windows kernel drivers
shipped alongside input peripherals (keyboard, mouse). The source is the
Microsoft Update Catalog — WHQL-signed, and, unlike the community archives tried
before (DriverGuide, Softpedia, DriverScape), it does not rate-limit or
bot-block a sustained sweep from a single IP.
"""
from __future__ import annotations
from typing import Callable

from .base import Collector
from .msupdate_catalog import collector as _msupdate_catalog


REGISTRY: dict[str, Callable[[], Collector]] = {
    "msupdate-catalog": _msupdate_catalog,
}


def available() -> list[str]:
    return sorted(REGISTRY.keys())


def get(name: str) -> Collector:
    if name not in REGISTRY:
        raise KeyError(f"unknown collector '{name}'. available: {available()}")
    return REGISTRY[name]()
