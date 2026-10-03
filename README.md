# hid-collect

Lean collector that pulls Windows kernel drivers (`.sys`) shipped alongside
HID peripherals — keyboard, mouse, graphics tablet, gamepad — from the
touslesdrivers.com aggregator. Deduplicates by SHA-256 and stores to a
content-addressed drive.

**Collection only.** No signature verification, no fingerprint, no scope
profiles, no analyze stage. If you need triage downstream, feed
`pipeline_out/drivers/` into the parent `hid-driver-triage` repo.

## Run

```bash
docker compose build
docker compose run --rm run
```

Outputs land in `pipeline_out/`:

```
pipeline_out/
  drivers/<sha256>.sys                                    # the corpus
  drivers/_provenance.jsonl                               # per-binary origin log
  drivers/index.json                                      # built report (see below)
  collectors/touslesdrivers-input/
    discovery_cache_<id>.json                             # cached brand walk
    processed.jsonl                                       # resume ledger
    <timestamp>/manifest.json                             # per-run index
```

## Index / report

The store is a flat tree of hash-named binaries. Build a single
`pipeline_out/drivers/index.json` describing every one of them — PE infos
(arch, subsystem, timestamp, imphash), imported APIs (grouped by DLL, with a
flagged driver-abuse subset), and extracted ASCII/UTF-16 strings — joined with
the origin metadata (`original_name`, package provenance) logged during
collection:

```bash
docker compose run --rm run pipeline.index
# or locally:  python -m pipeline.index [--min-str 5] [--max-str 3000]
```

Binaries are parsed **as bytes only** — nothing is executed. The report reads
`drivers/_provenance.jsonl` (written as each binary is stored, so origin
survives an interrupted run) and the run manifests; `original_name` is not
recoverable from the bytes, so it is blank for binaries collected before the
provenance log existed.

Re-running resumes from both the discovery cache (brand walk reused when
≤ `PDT_HID_DISCOVERY_TTL_DAYS` old, default 7) and the per-URL ledger
(`processed.jsonl`).

## Tuning

Set before `docker compose run`:

| Variable                     | Default        | Meaning                               |
|------------------------------|----------------|---------------------------------------|
| `PDT_HID_CATEGORIES`         | `10,11,17,19`  | Keyboard, mouse, tablet, gamepad      |
| `PDT_HID_TYPES`              | `1,4`          | Drivers, applications                 |
| `PDT_HID_MAX_BRANDS`         | `0` (unlim)    | Cap brands this run (sampling / dev)  |
| `PDT_HID_MAX_PACKS`          | `0` (unlim)    | Cap total packages this run           |
| `PDT_HID_JOBS`               | `6`            | Parallel download workers             |
| `PDT_HID_CRAWL_JOBS`         | `8`            | Parallel discovery crawlers           |
| `PDT_HID_MAX_MB`             | `60`           | Per-package size cap                  |
| `PDT_HID_REFRESH=1`          | off            | Ignore resume ledger                  |
| `PDT_HID_REFRESH_DISCOVERY=1`| off            | Ignore discovery cache, re-walk       |
| `PDT_HID_DISCOVERY_TTL_DAYS` | `7`            | Cache lifetime                        |

Category IDs on the aggregator:

| ID | Label                      |
|----|----------------------------|
| 10 | Clavier (keyboard)         |
| 11 | Souris (mouse)             |
| 17 | Tablette graphique         |
| 19 | Manette de jeu (gamepad)   |

## What's inside the image

Python 3.13-slim + `p7zip-full` + `curl`. The Python code uses stdlib only;
no `pefile`, `pyyaml`, `cryptography`, or anything else from the parent repo.
Image is ~130 MB.

## Safety model

Collection is static end-to-end: downloads, extractions, and PE header peeks
run containerized and never execute a driver. Binaries are parsed as bytes
only. Dynamic analysis belongs in isolated VMs — not here.
