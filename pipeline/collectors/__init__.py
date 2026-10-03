"""Collector registry.

This project targets a single, narrowly-scoped corpus: Windows kernel drivers
shipped alongside input peripherals (keyboard, mouse, graphics tablet, gamepad)
collected via the TousLesDrivers.com aggregator. The upstream parent project
(portable-driver-triage) carries additional per-vendor collectors; they are
intentionally omitted here to keep the image lean and the corpus focused.
"""
from __future__ import annotations
from typing import Callable

from .base import Collector
from .touslesdrivers_input import collector as _touslesdrivers_input
from .msupdate_catalog import collector as _msupdate_catalog


REGISTRY: dict[str, Callable[[], Collector]] = {
    "touslesdrivers-input": _touslesdrivers_input,
    "msupdate-catalog": _msupdate_catalog,
}


def available() -> list[str]:
    return sorted(REGISTRY.keys())


def get(name: str) -> Collector:
    if name not in REGISTRY:
        raise KeyError(f"unknown collector '{name}'. available: {available()}")
    return REGISTRY[name]()
