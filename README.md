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
  collectors/touslesdrivers-input/
    discovery_cache_<id>.json                             # cached brand walk
    processed.jsonl                                       # resume ledger
    <timestamp>/manifest.json                             # per-run index
```

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
