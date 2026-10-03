# hid-collect

Lean collector that pulls Windows kernel drivers (`.sys`) shipped alongside
HID peripherals — keyboard, mouse, graphics tablet, gamepad — from the
touslesdrivers.com aggregator. Deduplicates by SHA-256 and stores to a
content-addressed drive.

**Goal.** The net is drivers that ship with HID peripherals; the *target* is the
subset that looks able to **inject synthetic mouse/keyboard input from user mode,
bypassing the legitimate HID stack** — the primitive behind input-spoofing /
aim-assist abuse, and the kind of vulnerable signed driver LOLDrivers tracks.
Every binary gets an `hid_input` score + bucket (`strong`/`candidate`/`weak`/
`none`) and a LOLDrivers cross-reference so that subset is scannable — see
[Index](#index--driversindexjsonl) and [Query](#query--pipelinequery).

**Collection, then triage.** Collection stays indiscriminate — it stores every
`.sys` it can pull. Two stages downstream turn that raw net into the target set:

- [`pipeline.triage`](#triage--pipelinetriage) — a reproducible policy gate
  (production-signed? x64? user-reachable device?) that prunes what can never
  match and writes a lean [`reports/index.jsonl`](#lean-index--reportsindexjsonl).
- [`pipeline.disasm`](#disassembly--pipelinedisasm) — an optional Ghidra-headless
  stage that follows `DriverEntry` to decide, with code not strings, whether a
  driver injects synthetic mouse movement (b) and exposes a user-openable symlink
  right after `sc start` (c).

## Run

```bash
docker compose build
docker compose run --rm run        # TousLesDrivers aggregator (default)
docker compose run --rm catalog    # Microsoft Update Catalog (WHQL-signed)
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
  - **signature** — embedded Authenticode presence, the **signer leaf** cert
    (`signer_cn`, `issuer_cn`, code-signing EKU) and a `cert_class` verdict
    (`production` / `test` / `private` / `unsigned`) — the signer is separated
    from the CA and timestamp chain, so a test cert timestamped by a commercial
    TSA is no longer mistaken for a production one (see `pipeline/sigcheck.py`)
  - **kmdf** — `is_kmdf` (binds `wdfldr.sys`); KMDF routes device/symlink
    creation through the WDF function table, invisible to import-based heuristics
  - **device** — user-mode surface read statically: `framework` (wdm/kmdf/both),
    `declares_symlink`, the `\DosDevices\`/`\??\` `symlink_paths`, and any
    embedded `sddl` + whether it `sddl_grants_user` (a non-admin can open it)
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

## Brand filtering

The aggregator classifies brands by *site category* (keyboard, mouse, tablet,
gamepad), but the classification is noisy — Panasonic, Samsung, HP, Creative,
M-Audio, Wacom, Fanatec, Elgato and friends sit under one of those categories
for incidental products and dominate the raw crawl (Samsung alone shipped 243
drivers to the corpus; none has a HID-input primitive). To steer the net toward
the actual target, two env vars apply **after discovery** (so changing them is
cheap — no re-walk):

- `PDT_HID_BRAND_DENY` — comma/semicolon list of substrings, case-insensitive;
  the default removes the chronic off-target vendors (audio, print, modem,
  monitor, sim-racing wheels, VR, stream capture). Overriding replaces the
  default entirely — pass an empty value to disable denylisting.
- `PDT_HID_BRAND_ALLOW` — if set, keep only brands whose name contains one of
  these substrings; otherwise keep everything the deny filter did not drop.

Default `DENY` turns 7796 discovered packages into ~5200 (93 mouse/kbd/gamepad
brands: Microsoft, Logitech, Razer, SteelSeries, CORSAIR, HyperX, ROCCAT,
Mad Catz, Saitek, Cooler Master, Wooting, CHERRY, Ducky, Pulsar, Mountain,
Mionix, Fnatic, Kensington, Endgame Gear, ZOWIE, Dygma, MonsGeek, Akko, …).
A tight mouse+keyboard-only run drops gamepad category too:

The same filter preset is baked into the `tight` compose service — same volume
as `run`, so discovery cache and `processed.jsonl` are shared and switching
between the two does not re-walk the site or re-download:

```bash
docker compose run --rm tight     # cats 10,11 + 81-brand mouse/kbd allowlist
                                   # (~5100 pkgs vs run's ~5200)
```

## Collectors

| Compose service | Collector name | Source | Trust |
|---|---|---|---|
| `run`   | `touslesdrivers-input` | touslesdrivers.com (aggregator) | third-party, as-shipped |
| `tight` | `touslesdrivers-input` with `PDT_HID_CATEGORIES=10,11` + mouse/kbd allowlist | same, narrower slice | — |
| `catalog` | `msupdate-catalog` | catalog.update.microsoft.com | WHQL-signed via Microsoft CDN |
| `catalog-deep` | `msupdate-catalog` with Playwright pagination | same, 20 pages/query | — |

The catalog collector fans ~60 narrow HID/mouse/keyboard queries, resolves
each UID's direct `.cab` URL via `DownloadDialog.aspx`, and downloads in
parallel. Every file is a WHQL-signed `.cab` from a Microsoft CDN.

**One-page mode (`catalog`, default).** `urllib` only, no browser. One GET
per query (25 hits max per page — the catalog's ASP.NET postback blocks
plain HTTP requests), so query diversity substitutes for pagination. Finishes
in a few minutes. Image stays slim (~130MB).

**Deep crawl (`catalog-deep`).** Drives a headless Chromium through up to
`PDT_MSC_MAX_PAGES` postback pages per query (default 20 in this service),
yielding ~500 UIDs per query instead of 25. Requires the Playwright-enabled
image:

```bash
docker compose build --build-arg WITH_PLAYWRIGHT=1 catalog-deep
docker compose run --rm catalog-deep           # ~60 queries × 20 pages
```

Image jumps to ~1 GB with Chromium + its apt deps; keep the regular `catalog`
image slim and only pay the size on this one service. Env knobs:
`PDT_MSC_QUERIES` (`;`-separated), `PDT_MSC_JOBS`, `PDT_MSC_CRAWL_JOBS`,
`PDT_MSC_MAX_PACKS`, `PDT_MSC_MAX_MB` (default 100), `PDT_MSC_MAX_PAGES`
(default 1 = urllib mode; `>1` activates Playwright),
`PDT_MSC_BROWSER_WORKERS` (default 3; each ~300MB RAM when active),
`PDT_MSC_REFRESH`, `PDT_MSC_REFRESH_DISCOVERY`, `PDT_MSC_DISCOVERY_TTL_DAYS`.

All three services share the same `pipeline_out/` volume, so dedup by sha256
happens naturally across sources — a driver that appears both in a vendor
installer and on the Microsoft catalog is stored once.

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
| `--prod-cert`, `--cert-class {production,test,private,unsigned}` | signer cert verdict |
| `--kmdf` | KMDF driver (binds `wdfldr`) |
| `--declares-symlink`, `--user-open` | user-reachable device surface / SDDL grants a non-admin |
| `--injects`, `--symlink-reachable` | disasm verdicts: mouse injection / symlink reachable from `DriverEntry` |
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

## Triage — `pipeline.triage`

The policy gate the collector never had. It folds the index, applies composable
**gates**, and reports — or, with `--apply`, prunes — the drivers that fail.
Default is a dry run. It also writes the lean [`reports/index.jsonl`](#lean-index--reportsindexjsonl).

```bash
docker compose run --rm triage                      # dry run, 'loadable' preset
docker compose run --rm triage --target             # the net's (a)+(c) goal
python -m pipeline.triage --require prod-cert --apply   # delete the rest + index lines
```

| Gate | Passes when |
|------|-------------|
| `signed` | embedded Authenticode present |
| `prod-cert` | signature `cert_class` is `production` (not test/private/unsigned) |
| `x64` | PE arch is x64 (loads on a 64-bit Windows kernel) |
| `driver` | looks like a kernel driver (native subsystem / ntoskrnl import) |
| `device` | declares a user-reachable device + symlink surface |
| `user-open` | an embedded SDDL grants a non-admin principal |
| `hid` | `hid_input` bucket is strong or candidate |
| `not-lol` / `lol` | absent from / present in the vendored LOLDrivers set |

Presets: `--loadable` (`signed,prod-cert,x64`) is the "stop wasting space"
baseline; `--target` (`+driver,device`) is the project's stated goal. `--apply`
deletes each failing `<sha>.sys`, drops its index lines, and writes a
`triage_removed_<ts>.txt` manifest first.

## Disassembly — `pipeline.disasm`

Byte-parsing only shows *adjacency*. Proving (b) a driver drives the mouse class
service callback, and (c) its symlink is created from `DriverEntry` (not behind
PnP/hardware) and is user-openable, needs following code. This optional stage
drives Ghidra's `analyzeHeadless` + `ghidra_scripts/DriverTriage.py` over the
triage-selected subset (so it runs on hundreds, not thousands):

```bash
docker compose build --build-arg WITH_GHIDRA=1 disasm
docker compose run --rm disasm --limit 50           # or: --sha 40061b30
```

For each driver it resolves the KMDF WDF function-table calls, decompiles
`DriverEntry` and its callees, finds the symlink-referencing function and its
callers, and writes per-driver artifacts under `reports/<sha256>/`:

```
reports/<sha256>/
  <driver_name>.sys                    # the binary, named for the driver
  <driver_name>-driver-entry.c         # pseudo-C of DriverEntry
  disassembly.txt                      # verdicts + evidence + full pseudo-C
```

It also appends a compact `kind:"disasm"` line to the store index (so
`query --injects` / `--symlink-reachable` work) and refreshes the lean index.
Static reachability is strong evidence, not proof — final (c) confirmation is a
dynamic load in an isolated VM. The WDF index→name map in `DriverTriage.py` is
version-sensitive; unknown indices are reported with their raw number.

## Lean index — `reports/index.jsonl`

`drivers/index.jsonl` is the complete, append-only store record — big, because
each line carries the raw string dump and full import map needed to *compute* the
signals. `reports/index.jsonl` is the consumer view: one short line per driver
(~1.7% the size), only the triage-relevant fields and the disasm verdicts,
best-candidate first, each pointing at its `reports/<sha256>/` folder. Written by
`pipeline.triage` (the passing set) and refreshed by `pipeline.disasm`.

```json
{"sha256":"…","name":"ETD.sys","arch":"x64","signer":"ELAN MICROELECTRONICS CORPORATION",
 "cert_class":"production","kmdf":true,"framework":"kmdf","declares_symlink":true,
 "symlink_paths":["\\DosDevices\\ETD"],"sddl_grants_user":true,"hid":"candidate:7","report":"…"}
```

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
| `PDT_HID_BRAND_ALLOW`        | *(unset)*      | If set, keep only matching brands     |
| `PDT_HID_BRAND_DENY`         | *(curated)*    | Drops off-target brands               |
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

Python 3.13-slim + `p7zip-full` + `curl` + `osslsigncode` (authoritative
signature verification when present). The Python code uses stdlib only — no
`pefile`, `pyyaml`, `cryptography`, or anything else from the parent repo; the PE
parser, the PKCS#7/ASN.1 signer walk (`sigcheck.py`) and the index are all
hand-rolled. Base image is ~130 MB. Two optional build args add weight only when
used: `WITH_PLAYWRIGHT=1` (Chromium, for the deep catalog crawl) and
`WITH_GHIDRA=1` (JDK + Ghidra, for `pipeline.disasm`).

## Safety model

Collection is static end-to-end: downloads, extractions, and PE header peeks
run containerized and never execute a driver. Binaries are parsed as bytes
only. Dynamic analysis belongs in isolated VMs — not here.
