"""HID input-driver collector (lean — no analyze, no AI).

Public layers:
- pipeline.collect    : CLI entry point (`python -m pipeline.collect ...`)
- pipeline.collectors : vendor-source → .sys extractors (driverguide, softpedia)
- pipeline.adapter.l1 : import-table fingerprint, written inline during collection
- pipeline.config     : env-driven paths (tools, output root)
"""
__version__ = "v0.1.0-collect"
