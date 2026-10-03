"""Optional disassembly stage: Ghidra headless over triage-selected candidates.

Byte-parsing (`pipeline.index`) can only report *adjacency* — it cannot prove a
driver calls the mouse class service callback, nor that a symlink it declares is
actually created from DriverEntry and openable by a user. That needs following
code. This package drives Ghidra's `analyzeHeadless` + the `DriverTriage.py`
post-script to produce those verdicts (and the pseudo-C evidence behind them),
appending one ``kind: "disasm"`` line per driver to the same ``index.jsonl``.

It is heavy (JDK + Ghidra, ~GB) and slow (seconds-to-minutes per binary), so it
runs only over the subset worth the cost — by default the drivers that pass the
``pipeline.triage`` ``target`` gate (production-signed, x64, with a declared
device surface), typically hundreds, not the thousands in the raw corpus.
"""
from .runner import analyze_driver, main

__all__ = ["analyze_driver", "main"]
