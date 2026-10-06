# hid-collect

Lean collector that pulls Windows kernel drivers (`.sys`) shipped alongside HID
peripherals (mouse / keyboard / touchpad) from public, rate-limit-free archives,
scores every binary for input-injection potential **from the bytes only**, and
deduplicates into a content-addressed store.

**Goal.** The net is drivers that ship with HID peripherals; the *target* is the
subset able to **inject synthetic mouse/keyboard input by driving the input class
stack directly** (attaching to `\Device\KeyboardClass` / `\Device\PointerClass`,
calling `MouseClassServiceCallback`), while exposing a user-mode control interface
and **not** being a virtual HID device. That is the primitive behind
input-spoofing / aim-assist abuse and the kind of signed driver LOLDrivers tracks.

**Collection + static triage only.** Downloads, extraction and PE parsing run
containerized; nothing is executed or disassembled. Each `.sys` gets an
`hid_input` verdict for triage; feed the store into decompilation downstream.

## Sources

Three collectors survive, chosen because they have **no rate limit** and carry
**real, high-density HID `.sys`** (see *Source landscape* for what was rejected
and why):

| Collector          | What it pulls                                              | Mechanism |
|--------------------|------------------------------------------------------------|-----------|
| `msupdate-catalog` | Microsoft Update Catalog — WHQL-signed HID driver packages | Playwright-driven search pagination → `DownloadDialog` → CDN `.cab` |
| `vendor-catalog`   | Dell (`CatalogPC.cab`) + HP (`HpCatalogForSms`) OEM catalogs | parse catalog XML → per-component `.cab`/`.exe` |
| `snappy-driver`    | Snappy Driver Installer input driverpacks (`DP_Touchpad_*`, `DP_HID`) | aria2 BitTorrent, selective `--select-file` (Docker-only) |

## Run

```bash
docker compose build
docker compose run --rm collect           # just list collectors
docker compose run --rm msupdate-catalog  # sweep the MS Update Catalog (primary)
docker compose run --rm vendor-catalog    # sweep Dell/HP OEM catalogs
docker compose run --rm snappy-driver     # fetch SDI input driverpacks via torrent
```

Outputs land in `pipeline_out/` (bind-mounted, so the store, ledger and discovery
cache survive rebuilds):

```
pipeline_out/
  drivers/<sha256>.sys                 # the corpus (content-addressed)
  drivers/index.jsonl                  # append-only index (analysis + provenance)
  collectors/<collector>/
    discovery_cache.json               # cached search/catalog walk (TTL, default 7d)
    processed.jsonl                    # per-collector resume ledger
    <timestamp>/manifest.json          # per-run summary
```

Re-running resumes from both the discovery cache (reused when ≤
`PDT_*_DISCOVERY_TTL_DAYS` old) and the per-item ledger.

## How it works

### msupdate-catalog (primary)

The catalog serves a search term as up to 1000 results, 25 per page (max 40
pages), paginated by an ASP.NET `__doPostBack` that stdlib `urllib` cannot follow —
so discovery **always** drives headless Chromium via Playwright (there is no
single-page fallback). The collector runs an interleaved **discovery → download →
discovery** loop in batches: it searches a batch of queries across several browser
workers, resolves each result's `DownloadDialog.aspx` POST to its direct CDN
`.cab` URL, downloads and extracts that batch, then moves to the next. The default
query bank is a ~595-term curated HID set (generic classes, brands, model
families, touchpad OEMs, stylus, USB VIDs); override with `PDT_MSC_QUERIES`.

### vendor-catalog

Dell publishes `CatalogPC.cab` (UTF-16 XML, one `<SoftwareComponent>` per driver);
the collector keeps `Category="IN"` input components and resolves each to a
`downloads.dell.com` package. HP publishes `HpCatalogForSms.latest.cab` (SCCM SDP
XML); the collector keeps packages whose title matches the input keyword filter
and takes the first `ftp.hp.com` installer. Lenovo is excluded — its catalog is
model-pack-only, not component-level. `PDT_VC_SOURCES=dell,hp` selects which.

### snappy-driver (Docker-only)

Snappy Driver Installer ships its driverpacks over BitTorrent
(`SDIO_Update.torrent`, ~410 files). The collector bdecodes the torrent, selects
the input families by category regex, and fetches **only** those with aria2
`--select-file`. Mouse and keyboard ship in-box HID, so SDI has no `DP_Mouse` /
`DP_Keyboard`; the input content is the five `DP_Touchpad_*` packs plus the
generic `DP_HID` pack. aria2 is installed in the image and **never expected on the
host**. Default categories: `touchpad,hid`.

## Triage — the `hid_input` verdict

Every binary is scored on three independent axes derived from imports, strings,
device/symlink names and class GUIDs:

1. **`user_mode_interface`** — exposes a user-mode control surface (creates a
   device + symlink / handles IOCTLs).
2. **`virtual_hid`** — is a virtual HID device (VHF, HID minidriver). **This
   disqualifies** the driver as a target.
3. **`direct_injection`** — drives the input class stack directly (attaches to
   `\Device\KeyboardClass`/`PointerClass`, class-service callback).

These fold into a `verdict` + `rank` with supporting `evidence{}`:

| verdict       | rank | meaning |
|---------------|------|---------|
| `match`       | 3    | user-mode interface **and** direct injection, **not** virtual HID |
| `candidate`   | 2    | two axes satisfied |
| `virtual_hid` | 1    | is a virtual HID device (disqualified) |
| `none`        | 0    | no HID-input relevance |

### Corpus at a glance

As of the last sweep (`python -m pipeline.query --stats`): **6572** records,
5801 signed / 768 unsigned.

| verdict       | files |
|---------------|-------|
| `match`       | 180   |
| `candidate`   | 933   |
| `virtual_hid` | 1733  |
| `none`        | 3723  |

The 180 matches collapse to **54 distinct code variants** by `pe.imphash` — heavy
near-duplication (the same filter driver across many catalog versions). By source:

| source             | match files | distinct code |
|--------------------|-------------|---------------|
| `msupdate-catalog` | 139         | 44            |
| `vendor-catalog`   | 40          | 17            |
| `snappy-driver`    | 1           | 1             |

Matches are dominated by touchpad filters (Alps `Apfiltr`, Asus TP Filter, ELAN,
AlpsAlpine) with a thin true mouse/keyboard seam (Samsung `Mouse.sys`, `KbFiltr`,
MSR keyboard filter, Ideazon/Zippy gaming keyboards).

## Index — `drivers/index.jsonl`

A flat tree of hash-named binaries plus one append-only index beside it, updated
on every new `.sys`. Each line is a JSON object keyed by `sha256`:

- **analysis** — everything derivable from the bytes: hashes (incl. `pe.imphash`,
  entropy), PE header (`pe.arch`, `pe.is_driver`, `pe.native`, NX/`pe.wx`,
  sections), imports/exports + `pe.capabilities` buckets (`input_injection`,
  `phys_mem`, `port_io`, `device_io`, `mem_copy`, `process_access`, …), debug
  `pe.pdb` identity, `pe.info` version-info (lowercase keys: `companyname`,
  `productname`, `originalfilename`, …), Authenticode presence + `pe.signers`,
  the `hid_input` verdict/rank/evidence, and the `loldrivers` cross-reference.
- **provenance** — `{sha256, provenance: {source, source_kind, aggregator,
  update_title, package_url, matched_queries, …}}`

A reader folds every line sharing a `sha256`; `pipeline.index.fold_index()` does
this. Binaries are parsed **as bytes only**. To (re)build analysis lines for
binaries already in the store:

```bash
python -m pipeline.index [--rebuild]
```

## Query — `pipeline.query`

Folds `index.jsonl` (one record per sha256) and slices the corpus with composable
filters (AND across flags; a repeated flag ORs its values), then prints a table,
CSV, JSON, a per-driver detail view, or summary stats. Reads the index only.

```bash
python -m pipeline.query --stats                          # corpus at a glance
python -m pipeline.query --verdict match --unsigned       # strongest unsigned targets
python -m pipeline.query --direct-injection --no-virtual-hid --user-mode-interface
python -m pipeline.query --capability phys_mem --csv      # phys-mem importers
python -m pipeline.query --loldrivers                     # known-vulnerable hits
python -m pipeline.query --show aaf74cc5dd16              # one driver, in detail
```

Key filters: `--sha/--name/--company/--product` (substring), `--arch`,
`--capability`, `--verdict`/`--min-rank`, the three axes
(`--direct-injection`, `--user-mode-interface`, `--virtual-hid`/`--no-virtual-hid`),
`--signed`/`--unsigned`/`--signer`, `--loldrivers`, `--imphash`, `--pdb`,
`--symlink`, `--device`, `--class-guid`, `--native`, `--wx`, `--driver`.
Output: aligned table (`--fields A,B,C`), `--csv`, `--json`/`--jsonl`, `--count`,
`--stats`, `--show SHA`; sort with `--sort FIELD [--desc]`, cap with `--limit N`.

## Tuning

Set before `docker compose run`.

**msupdate-catalog:**

| Variable                      | Default | Meaning                                   |
|-------------------------------|---------|-------------------------------------------|
| `PDT_MSC_QUERIES`             | curated | `;`-separated search terms (default ~595) |
| `PDT_MSC_MAX_PAGES`           | `40`    | Pages per query (catalog caps at 40×25)   |
| `PDT_MSC_BROWSER_WORKERS`     | `6`     | Parallel headless-Chromium search workers |
| `PDT_MSC_JOBS`                | `8`     | Download workers                          |
| `PDT_MSC_MAX_PACKS`           | `0`     | Cap packages this run (0 = unlimited)     |
| `PDT_MSC_MAX_MB`              | `100`   | Per-`.cab` size cap (MB)                  |
| `PDT_MSC_REFRESH=1`           | off     | Ignore resume ledger                      |
| `PDT_MSC_REFRESH_DISCOVERY=1` | off     | Ignore discovery cache, re-search         |
| `PDT_MSC_DISCOVERY_TTL_DAYS`  | `7`     | Discovery cache lifetime                  |

**vendor-catalog:**

| Variable                     | Default    | Meaning                              |
|------------------------------|------------|--------------------------------------|
| `PDT_VC_SOURCES`             | `dell,hp`  | Which OEM catalogs to crawl          |
| `PDT_VC_JOBS`                | `8`        | Download workers                     |
| `PDT_VC_MAX_PACKS`           | `0`        | Cap packages this run (0 = unlimited)|
| `PDT_VC_MAX_MB`              | `300`      | Per-package size cap (MB)            |
| `PDT_VC_REFRESH` / `PDT_VC_REFRESH_DISCOVERY` | off | Ignore ledger / discovery cache |
| `PDT_VC_DISCOVERY_TTL_DAYS`  | `7`        | Discovery cache lifetime             |

**snappy-driver:**

| Variable                      | Default         | Meaning                            |
|-------------------------------|-----------------|------------------------------------|
| `PDT_SDI_CATEGORIES`          | `touchpad,hid`  | `DP_*` families to select          |
| `PDT_SDI_BT_TIMEOUT`          | `300`           | Abort a stalled swarm (seconds)    |
| `PDT_SDI_SEED_TIME`           | `0`             | Seed time after download           |
| `PDT_SDI_MAX_PACKS`           | `0`             | Cap selected packs (0 = all)       |
| `PDT_SDI_REFRESH` / `PDT_SDI_REFRESH_DISCOVERY` | off | Ignore ledger / re-fetch torrent |

## What's inside the image

Python 3.13-slim + `p7zip-full` + `curl` + `curl_cffi` (TLS fingerprint for
streaming downloads) + `aria2` (BitTorrent for snappy-driver) + Playwright/Chromium
(catalog search pagination). The analysis code is stdlib-only.

## Safety model

Collection is static end-to-end: downloads, extraction and PE header peeks run
containerized and never execute a driver. Binaries are parsed as bytes only.
Dynamic analysis belongs in isolated VMs — not here.

## Source landscape — what was rejected and why

The target is narrow, and most driver sources do not carry it. The structural
reason: **"dumb" mice and keyboards ship in-box HID and carry no vendor `.sys`**,
so general driver repos are thin on exactly the target. HID-input `.sys` density
lives in only two places, both already covered: **touchpad OEMs** (Synaptics /
Elan / Alps / Cypress-touch → snappy-driver) and **WHQL HID filters**
(→ msupdate-catalog).

Rejected after investigation:

- **Community web archives** (`driverguide`, `softpedia`, `driverscape`) —
  every one rate-limits or bot-blocks a sustained sweep (Cloudflare 429 /
  tarpitting). Not dependable for full-corpus volume. *(Removed.)*
- **archive.org** — no rate limit and huge, but driver items are opaque ISO/RAR
  blobs (download 0.3–15 GB to extract maybe one `.sys`); the dense items are
  DriverPack ISOs that overlap snappy-driver's upstream; HID-input density is low
  (audio / GPU / NIC / legacy dominate).
- **Station-Drivers** — no login/captcha and clean per-file downloads (redirects
  to the vendor's own CDN), but organized by *silicon* vendor; the mouse/keyboard
  branches are vestigial (Logitech = 1 package, keyboard = 0; Cypress = USB3.0
  host controllers, not touchpad).
- **Gaming-mouse peripheral vendors** (Rapoo, Fantech, Bloody/A4Tech, Redragon,
  Marvo, …) — their config software is **usermode-only**. Tested installers
  (Rapoo `Driver_Setup`, Fantech Crypto, Bloody7 suite) carry **zero `.sys`, no
  `.inf`, no `.cat`, and no `CreateService`/class-callback logic**. Even
  macro/anti-recoil engines run in user mode (SendInput / HID feature reports);
  the budget brands share one Chinese-ODM app. Kernel HID filters are a legacy
  pattern that msupdate-catalog + snappy-driver already capture.
