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
  drivers/index.jsonl                                     # live index (see below)
  collectors/touslesdrivers-input/
    discovery_cache_<id>.json                             # cached brand walk
    processed.jsonl                                       # resume ledger
    <timestamp>/manifest.json                             # per-run index
```

## Index — `drivers/index.jsonl`

The store is a flat tree of hash-named binaries; `index.jsonl` is the single,
append-only index kept beside it that makes it readable, and it **updates on
every new `.sys`**. As a binary is stored, collection appends one *analysis*
line, and once origin is known it appends *provenance* line(s). Each line is a
JSON object keyed by `sha256`:

- **analysis** — everything derivable from the bytes:
  - **hashes** — `sha256`, `md5`, `sha1`, `pe.imphash`, file + per-section entropy
  - **pe** — arch, subsystem, `is_driver` flag, timestamp, linker, image base,
    entrypoint, checksum (+validity), characteristics, DLL characteristics
    (NX, ASLR, CFG), data directories
  - **sections** — name, VA, size, perms, entropy, `wx` flag
  - **apis** — `imports` grouped by DLL, `exports`, `api_count`,
    `dangerous_imports`, `capabilities` buckets (`input_injection`,
    `phys_mem`, `msr_control_reg`, `port_io`, `process_access`, `mem_copy`,
    `device_io`)
  - **debug** — CodeView PDB path, GUID, age (original build identity)
  - **resources** — manifest/RCDATA presence, `version_info` (CompanyName,
    OriginalFilename, FileVersion, …)
  - **signature** — embedded Authenticode presence + certificate common names
  - **overlay** — appended data (offset, size, entropy)
  - **strings** — deduped ASCII/UTF-16 + `interesting_strings`
    (device paths, registry, GUIDs, URLs, other `.sys`)
  - **hid_input** — score + bucket (`strong`/`candidate`/`weak`/`none`) for the
    project's question: does this driver look able to inject mouse/keyboard
    input from user mode, bypassing the legitimate HID stack?
  - **loldrivers** — cross-reference against a vendored LOLDrivers snapshot
    (`pipeline/refs/loldrivers_index.json`, matched by sha256 then imphash)
- **provenance** — `{"sha256", "provenance": {...}}` (brand, package URL, …)

A reader folds every line sharing a `sha256`; `pipeline.index.fold_index()` does
this. Binaries are parsed **as bytes only** — nothing is executed, nothing is
disassembled. `original_name` is not recoverable from the bytes alone, so it is
present only for binaries stored after the index existed (version-info's
`OriginalFilename` is a reliable fallback).

Appending happens automatically during collection. To (re)build analysis lines
for binaries already in the store — e.g. after a reset or an interrupted run:

```bash
docker compose run --rm run pipeline.index           # append missing lines
# or locally:  python -m pipeline.index [--rebuild] [--min-str 5] [--max-str 3000]
```

Re-running resumes from both the discovery cache (brand walk reused when
≤ `PDT_HID_DISCOVERY_TTL_DAYS` old, default 7) and the per-URL ledger
(`processed.jsonl`).

## Query — `pipeline.query`

`index.jsonl` is dense, single-line JSON per driver — meant for a machine, not
the eye. `pipeline.query` folds it (one record per sha256) and slices the corpus
with composable filters, then prints a table, CSV, JSON, a per-driver detail
view, or summary stats. Nothing opens a binary; it reads the index only.

```bash
docker compose run --rm run pipeline.query --stats       # corpus at a glance
# or locally:
python -m pipeline.query --hid-bucket strong --unsigned  # risky injection candidates
python -m pipeline.query --capability phys_mem --csv     # phys-mem importers, CSV
python -m pipeline.query --loldrivers                    # known-vulnerable hits
python -m pipeline.query --show 40061b30b124             # one driver, in detail
```

Filters combine with **AND**; a repeated flag **OR**s its own values.

| Filter | Matches |
|--------|---------|
| `--sha HEX`, `--name`, `--brand`, `--company` | substring (case-insensitive) |
| `--arch x64\|x86\|arm64…` | PE architecture |
| `--capability {input_injection,phys_mem,msr_control_reg,port_io,process_access,mem_copy,device_io,any}` | capability bucket present |
| `--hid-bucket {strong,candidate,weak,none}`, `--min-hid-score N`, `--creates-user-device` | HID-injection signal |
| `--signed` / `--unsigned` | embedded Authenticode |
| `--loldrivers` | known in the vendored LOLDrivers snapshot |
| `--wx`, `--driver`, `--overlay` | W^X section / looks-like-driver / appended overlay |
| `--min-entropy H` / `--max-entropy H` | file entropy |
| `--import SUBSTR`, `--export SUBSTR`, `--string SUBSTR` | name/string contains (repeat = AND) |
| `--url`, `--guid`, `--device-path` | interesting-strings subset contains |

Output: default aligned table (`--fields a,b,c` to pick columns — virtual names
like `sha,arch,sig,hid,lol,caps,name` or any dotted path such as
`pe.imphash`), `--csv`, `--json` / `--jsonl` (add `--strings` to include the raw
string dump, omitted by default), `--count`, `--stats`, `--show SHA` (sha256
prefix). Sort with `--sort FIELD [--desc]` (default: strongest `hid_input` first)
and cap with `--limit N`.

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
