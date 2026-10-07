<h1 align="center">hid-collect</h1>

<p align="center">
  <strong>An LLM-operated research pipeline for finding Windows HID drivers that provide user-mode-reachable input injection.</strong>
</p>

<p align="center">
  <a href="#what-makes-it-different">What makes it different</a> &middot;
  <a href="#how-it-works">How it works</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#the-corpus">The corpus</a> &middot;
  <a href="AGENTS.md">AGENTS.md &rarr;</a>
</p>

---

## What makes it different

**This project is designed to be driven by an LLM agent, not a human reviewer.**

Most driver-research tooling expects a human to pick candidates, read decompiles,
run the dynamic tests, and write up findings. `hid-collect` instead ships a
machine-oriented operating spec — [`AGENTS.md`](AGENTS.md) — that an AI agent
loads on first turn and executes top-to-bottom: pick, confirm with the user,
build the report, read the Ghidra output, grow a per-report dynamic script step
by step, and emit a per-criterion verdict in `result.md`.

The pipeline, triage model, verdict schema, report folder contract, and
dynamic-script format are all designed around what makes an agent reliable:
explicit preconditions, enforceable rules, unambiguous verdict categories,
and `unknown` as a first-class answer.

If you're a human reading this, run the collectors below and poke around. If
you're an LLM reading this, open [`AGENTS.md`](AGENTS.md). That is your
bootstrap.

## What it does

Pulls Windows kernel drivers (`.sys`) shipped alongside HID peripherals from
rate-limit-free archives, scores every binary **from the bytes only**, and
deduplicates into a content-addressed store. From the shortlist, an agent
promotes one driver at a time through static read + controlled dynamic
validation under full Secure Boot + HVCI + driver-blocklist protections, and
emits a confirmed/rejected result against a six-criterion profile.

**Target.** A signed, Windows 10/11 x64 driver that creates its own HID mouse
device (virtual or software-enumerated), is hardware-independent at init, and
delivers caller-controlled mouse movement through that HID device via a
user-mode-reachable interface.

## How it works

```
                  +---------------------+
                  |  AI agent reads     |
                  |  AGENTS.md          |
                  +----------+----------+
                             |
                             v
+--------+     +-------------+-------------+     +----------------+
| Public |---->| Collectors (containerised |---->| Content-addr.  |
| sources|     | msupdate-catalog / vendor-|     | store + index  |
+--------+     | catalog / snappy-driver)  |     | (bytes only)   |
               +-------------+-------------+     +--------+-------+
                                                          |
                                                          v
                                                +---------+---------+
                                                | pipeline.query +  |
                                                | report --pick     |
                                                +---------+---------+
                                                          |
                                                          v
                                            +-------------+-------------+
                                            | reports/<sha256>/         |
                                            |   <driver>.sys            |
                                            |   <driver>.c (Ghidra)     |
                                            |   dynamic.ps1 (grown)     |
                                            |   result.md (per-criterion)|
                                            +-------------+-------------+
                                                          |
                                                          v
                                                +---------+---------+
                                                | Snapshotted VM:   |
                                                | STEP 1..15        |
                                                | observed effect   |
                                                +-------------------+
```

## Quickstart

```bash
docker compose build
docker compose run --rm msupdate-catalog   # primary: WHQL HID packages
docker compose run --rm vendor-catalog     # Dell / HP OEM catalogs
docker compose run --rm snappy-driver      # SDI input driverpacks (torrent)
```

Outputs:

```
pipeline_out/
  drivers/<sha256>.sys                 # the corpus
  drivers/index.jsonl                  # append-only index (analysis + provenance)
  collectors/<name>/
    discovery_cache.json               # resumeable search walk (TTL)
    processed.jsonl                    # per-item ledger
    <timestamp>/manifest.json          # per-run summary
```

Query the corpus:

```bash
python -m pipeline.query --stats
python -m pipeline.query --arch x64 --signed --self-hid --user-mode-interface
python -m pipeline.query --show <sha-prefix>
```

Build a per-driver report folder (static + seed dynamic script):

```bash
docker compose run --rm report --pick       # highest-ranked unresolved target
docker compose run --rm report <sha-prefix> # a specific hash
```

## Collectors

| Collector | What it pulls | Mechanism |
|-----------|---------------|-----------|
| `msupdate-catalog` | Microsoft Update Catalog — WHQL-signed HID driver packages | Playwright-driven search pagination &rarr; `DownloadDialog` &rarr; CDN `.cab` |
| `vendor-catalog` | Dell (`CatalogPC.cab`) + HP (`HpCatalogForSms`) OEM catalogs | parse catalog XML &rarr; per-component `.cab`/`.exe` |
| `snappy-driver` | Snappy Driver Installer input driverpacks (`DP_Touchpad_*`, `DP_HID`) | aria2 BitTorrent with selective `--select-file` (Docker-only) |

Each collector resumes from a discovery cache (default TTL 7 days) and a
per-item ledger. See [AGENTS.md &sect;2.1](AGENTS.md#21-pick-the-target) for
how an agent widens the shortlist when the default picker is exhausted.

## Triage model

`index.jsonl` carries, per sha256, every byte-reachable axis. The verdict is a
convenience label — a shortlist handle, not a confirmation.

| Axis | Meaning |
|------|---------|
| `mouse_injection` | direct mouse-stack injection signals |
| `keyboard_injection` | keyboard-side analog (disqualifying on its own) |
| `user_mode_interface` | user-openable control surface (device + symlink) |
| `self_hid_device` | VHF, HID minidriver, or hidclass/hidparse/vhf linkage |
| `hardware_independent_init` | unknown in byte triage; dynamic-only |
| `x64_driver` | PE is an x64 kernel driver |
| `signature_present` | embedded Authenticode blob (not validity) |

| Verdict | Rank | Meaning |
|---------|------|---------|
| `match` | 4 | self-HID + user-mode control + mouse evidence + x64 driver + embedded signature |
| `candidate` | 3 | self-HID + user-mode control, with mouse evidence or another gating fact unproven |
| `self_hid` | 2 | self-HID evidence, user-mode control unproven |
| `keyboard_only` | 1 | keyboard evidence without mouse or self-HID; outside the target |
| `none` | 0 | no self-HID lead and no keyboard-only classification |

Records are rescored on read, so query results reflect the current profile
without rebuilding the store. For the full criterion list and how
confirmation is actually established, see
[AGENTS.md &sect;1 — Required target profile](AGENTS.md#1-required-target-profile).

## The corpus

As of the last sweep: **6572** records, 5818 with an embedded-signature blob.

<details>
<summary>Verdict distribution (historical, previous profile)</summary>

| verdict | files |
|---------|-------|
| `match` | 0 |
| `candidate` | 939 |
| `keyboard_only` | 176 |
| `self_hid` | 1743 |
| `none` | 3714 |

Axis counts: `signature_present=5818`, `x64_driver=4808`,
`user_mode_interface=3809`, `self_hid_device=1743`,
`hardware_independent_init=931`, `keyboard_injection=184`, `mouse_injection=5`.
Arch: `x64=4808`, `x86=1700`, `arm64=58`, `ia64=4`.

The byte-level mouse-stack injection seam is thin (5 binaries total); none
combine signed x64 with mouse-stack injection. These stats reflect the
previous scoring profile and are kept as a historical reference.
</details>

## Project structure

```
hid-collect/
  AGENTS.md                     # <-- the LLM operating spec (start here)
  README.md                     # this file
  docker-compose.yml
  Dockerfile                    # collector image
  Dockerfile.ghidra             # analysis image (Ghidra headless + pipeline)
  pipeline/
    index.py                    # triage axes, verdict, apply_hid_profile
    query.py                    # composable filters over index.jsonl
    report.py                   # --pick + per-report folder materialisation
    collectors/
      msupdate_catalog/
      vendor_catalog/
      snappy_driver/
  pipeline_out/                 # bind-mounted outputs
  reports/<sha256>/             # per-driver report folders
```

## Tuning

Set before `docker compose run`.

<details>
<summary><code>msupdate-catalog</code></summary>

| Variable | Default | Meaning |
|----------|---------|---------|
| `PDT_MSC_QUERIES` | curated | `;`-separated search terms (~595 defaults) |
| `PDT_MSC_MAX_PAGES` | `40` | pages per query (catalog caps at 40&times;25) |
| `PDT_MSC_BROWSER_WORKERS` | `6` | parallel Chromium search workers |
| `PDT_MSC_JOBS` | `8` | download workers |
| `PDT_MSC_MAX_PACKS` | `0` | cap packages this run (0 = unlimited) |
| `PDT_MSC_MAX_MB` | `100` | per-`.cab` size cap |
| `PDT_MSC_REFRESH` / `PDT_MSC_REFRESH_DISCOVERY` | off | ignore ledger / discovery cache |
| `PDT_MSC_DISCOVERY_TTL_DAYS` | `7` | discovery cache lifetime |
</details>

<details>
<summary><code>vendor-catalog</code></summary>

| Variable | Default | Meaning |
|----------|---------|---------|
| `PDT_VC_SOURCES` | `dell,hp` | which OEM catalogs to crawl |
| `PDT_VC_JOBS` | `8` | download workers |
| `PDT_VC_MAX_PACKS` | `0` | cap packages this run |
| `PDT_VC_MAX_MB` | `300` | per-package size cap |
| `PDT_VC_REFRESH` / `PDT_VC_REFRESH_DISCOVERY` | off | ignore ledger / discovery cache |
| `PDT_VC_DISCOVERY_TTL_DAYS` | `7` | discovery cache lifetime |
</details>

<details>
<summary><code>snappy-driver</code></summary>

| Variable | Default | Meaning |
|----------|---------|---------|
| `PDT_SDI_CATEGORIES` | `touchpad,hid` | `DP_*` families to select |
| `PDT_SDI_BT_TIMEOUT` | `300` | abort stalled swarm (seconds) |
| `PDT_SDI_SEED_TIME` | `0` | seed time after download |
| `PDT_SDI_MAX_PACKS` | `0` | cap selected packs |
| `PDT_SDI_REFRESH` / `PDT_SDI_REFRESH_DISCOVERY` | off | ignore ledger / re-fetch torrent |
</details>

## Safety model

Collection is static end-to-end: downloads, extraction, and PE header peeks
run containerised and never execute a driver. Binaries are parsed as bytes
only. Dynamic analysis belongs in isolated VMs — not in the collector image.
The agent spec enforces this in rules R4-R6.

## Source landscape — what was rejected and why

<details>
<summary>Expand</summary>

The target is narrow, and most driver sources do not carry it. The structural
reason: **"dumb" mice and keyboards ship in-box HID and carry no vendor
`.sys`**, so general driver repos are thin on exactly the target.
HID-input `.sys` density lives in only two places, both already covered:
touchpad OEMs (Synaptics / Elan / Alps / Cypress-touch &rarr; `snappy-driver`)
and WHQL HID filters (&rarr; `msupdate-catalog`).

Rejected after investigation:

- **Community web archives** (`driverguide`, `softpedia`, `driverscape`) —
  every one rate-limits or bot-blocks a sustained sweep (Cloudflare 429 /
  tarpitting). Not dependable for full-corpus volume.
- **archive.org** — no rate limit and huge, but driver items are opaque
  ISO/RAR blobs (0.3-15 GB to extract maybe one `.sys`); the dense items
  are DriverPack ISOs that overlap `snappy-driver`'s upstream; HID-input
  density is low (audio / GPU / NIC / legacy dominate).
- **Station-Drivers** — no login/captcha and clean per-file downloads
  (redirects to the vendor's own CDN), but organized by *silicon* vendor;
  the mouse/keyboard branches are vestigial (Logitech = 1 package,
  keyboard = 0; Cypress = USB3.0 host controllers, not touchpad).
- **Gaming-mouse peripheral vendors** (Rapoo, Fantech, Bloody/A4Tech,
  Redragon, Marvo, &hellip;) — their config software is **usermode-only**.
  Tested installers (Rapoo `Driver_Setup`, Fantech Crypto, Bloody7 suite)
  carry **zero `.sys`, no `.inf`, no `.cat`, and no
  `CreateService`/class-callback logic**. Even macro / anti-recoil engines
  run in user mode (SendInput / HID feature reports); the budget brands
  share one Chinese-ODM app. Kernel HID filters are a legacy pattern that
  `msupdate-catalog` + `snappy-driver` already capture.
</details>

## Confirmed targets

Each confirmed-or-rejected target lands in `reports/<sha256>/result.md`.
Scope limits are recorded alongside the verdict (which Windows builds were
tested, which access modes measured, which capabilities exercised).

Current public result:

- **`c8819dbd...414de9f5c`** — `vhidev.sys` / `vhidflt.sys` (Virtual HID
  Provider, 18.13.46.429) &mdash; **CONFIRMED** on Windows 11 build 26300
  under Secure Boot + HVCI + VBS. All six criteria established; details
  under `reports/`.

## For AI agents

If you are an LLM operating in this repo: load [`AGENTS.md`](AGENTS.md)
before anything else. It is dense on purpose. Every clause there is a
precondition for valid output; this README is advertising.

## License

See `LICENSE`.
