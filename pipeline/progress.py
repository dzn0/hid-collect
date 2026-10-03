"""Thread-local progress channel.

Collectors run concurrently, one per thread (see `pipeline.collect`). Each
worker thread registers a reporter; the collection primitives in
`collectors._common` (download, extract, scan) call `report(...)` as they work,
and the live renderer picks the latest detail line up per collector.

Slots (opt-in, used by multi-worker collectors): a collector that fans work out
across its own worker threads can give each worker a slot_id + label. When a
slot is active on this thread, `report(detail)` routes to the slot reporter
instead of the collector's single detail — the renderer then draws one sub-row
per active slot. Collectors that don't use slots are unaffected.

This is best-effort telemetry only: when no reporter is registered (e.g. a unit
test, or the plain non-TTY path) `report` is a no-op, so instrumentation never
changes behavior.
"""
from __future__ import annotations
import threading
from typing import Callable

_local = threading.local()


def set_reporter(fn: Callable[[str], None]) -> None:
    _local.fn = fn


def set_count_reporter(fn: Callable[[int], None]) -> None:
    """Register this thread's running-total reporter (drivers stored so far)."""
    _local.count_fn = fn


def set_slot_reporter(fn: Callable[[str, str, str], None]) -> None:
    """Register this thread's slot reporter: fn(slot_id, label, detail).

    Called once in a fan-out worker thread (alongside set_reporter). Once set,
    any `report()` call made while a slot is active (see `set_slot`) is routed
    to this reporter instead of the single-string reporter. Clearing the slot
    reverts `report()` to the fallback.
    """
    _local.slot_fn = fn


def set_slot(slot_id: str, label: str = "") -> None:
    """Attach this thread to a logical slot (e.g. a per-brand worker lane).

    Subsequent `report(detail)` calls on this thread route to the slot reporter
    as (slot_id, label, detail), so the live renderer can show one sub-row per
    active worker instead of one noisy line of last-writer-wins."""
    _local.slot_id = slot_id
    _local.slot_label = label


def clear_slot() -> None:
    """Detach this thread's slot. The slot's sub-row disappears from the UI."""
    sid = getattr(_local, "slot_id", None)
    slot_fn = getattr(_local, "slot_fn", None)
    if sid and slot_fn is not None:
        try:
            # sentinel: empty label + empty detail → renderer removes the sub-row
            slot_fn(sid, "", "")
        except Exception:
            pass
    _local.slot_id = None
    _local.slot_label = None


def clear_reporter() -> None:
    _local.fn = None
    _local.count_fn = None
    _local.slot_fn = None
    _local.slot_id = None
    _local.slot_label = None


def current_reporters() -> tuple:
    """Return this thread's (reporter, count_reporter, slot_reporter) triple.

    A collector that fans its work out across its own worker threads captures
    these on its main thread and re-registers them inside each worker (the
    channel is thread-local), so sub-steps, the running driver total, and slot
    activity still reach the live renderer from the workers."""
    return (getattr(_local, "fn", None),
            getattr(_local, "count_fn", None),
            getattr(_local, "slot_fn", None))


def report(detail: str) -> None:
    """Report the current sub-step for this thread (best-effort).

    If this thread has an active slot and a slot reporter, the detail routes
    to the slot — the renderer updates that worker's sub-row. Otherwise the
    detail goes to the collector's single-string reporter (legacy path)."""
    sid = getattr(_local, "slot_id", None)
    slot_fn = getattr(_local, "slot_fn", None)
    if sid and slot_fn is not None:
        try:
            slot_fn(sid, getattr(_local, "slot_label", "") or "", detail)
        except Exception:
            pass
        return
    fn = getattr(_local, "fn", None)
    if fn is not None:
        try:
            fn(detail)
        except Exception:
            pass  # telemetry must never break collection


def add_count(n: int) -> None:
    """Add `n` to this collector's running driver total (best-effort).

    Lets a long-running catalog collector surface drivers as they are stored,
    instead of only at the end — the live renderer shows the cumulative total,
    which is the meaningful number when a run is never expected to "complete"."""
    if not n:
        return
    fn = getattr(_local, "count_fn", None)
    if fn is not None:
        try:
            fn(n)
        except Exception:
            pass
