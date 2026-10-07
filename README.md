<h1 align="center">hid-driver-triage</h1>

<p align="center">
  <strong>An LLM-operated research pipeline for finding Windows HID drivers that provide user-mode-reachable input injection.</strong>
</p>

<p align="center">
  <a href="#findings">Findings</a> &middot;
  <a href="#how-it-works">How it works</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="AGENTS.md">AGENTS.md &rarr;</a>
</p>

<p align="center">
  <strong>Already surfaced a real finding:</strong>
  <a href="https://github.com/dzn0/vhidev-hid-takeover"><code>dzn0/vhidev-hid-takeover</code></a>
  &mdash; a WHQL-signed Microsoft driver that puppets the full Windows HID input stack (keyboard, mouse, media, power). Found by this pipeline. PoC in its own repo.
</p>

---

## LLM-first by design

**This project is designed to be driven by an LLM agent, not a human reviewer.**

Most driver-research tooling expects a human to pick candidates, read decompiles, run dynamic tests, and write up findings. `hid-driver-triage` ships a machine-oriented operating spec — [`AGENTS.md`](AGENTS.md) — that an AI agent loads on first turn and executes top-to-bottom: pick, confirm with the user, build the report, read the Ghidra output, grow a per-report dynamic script step by step, and emit a per-criterion verdict in `result.md`.

The triage model, verdict schema, and dynamic-script format are all built around what makes an agent reliable: explicit preconditions, enforceable rules, unambiguous verdicts, and `unknown` as a first-class answer.

If you're a human reading this, run the collectors below. If you're an LLM, open [`AGENTS.md`](AGENTS.md) — that is your bootstrap.

## Findings

The pipeline is not a design exercise. It has produced a public, reproducible finding under its own six-criterion profile:

**[`vhidev.sys` / `vhidflt.sys`](https://github.com/dzn0/vhidev-hid-takeover) — CONFIRMED.** A WHQL-signed Microsoft driver (*Virtual HID Provider — HIDClass — 18.13.46.429*) that creates its own HID keyboard, mouse, consumer, and system-control collections and exposes a user-mode-reachable vendor interface. Any admin-installed process can then puppet the full Windows HID input stack through a single `WriteFile` — input flows through the normal HID path and is indistinguishable from a real USB device.

Validated end-to-end on Windows 11 build 26300 with **Secure Boot + HVCI + VBS all ON**, no protections disabled, no test-signing, no binary patching. All six criteria met.

- Standalone PoC + write-up: [`dzn0/vhidev-hid-takeover`](https://github.com/dzn0/vhidev-hid-takeover)
- Full report folder (static + dynamic + per-criterion verdict): `reports/c8819dbd...414de9f5c/`

More findings graduate to their own PoC repos the same way.

## How it works

```
Public sources ──▶ Containerised collectors ──▶ Content-addressed store
                   (msupdate / vendor / snappy)   + byte-triage index
                                                             │
                                                             ▼
                                                   pipeline.query + report --pick
                                                             │
                                                             ▼
                                                   reports/<sha256>/
                                                     <driver>.sys
                                                     <driver>.c    (Ghidra)
                                                     dynamic.ps1   (grown)
                                                     result.md     (verdict)
                                                             │
                                                             ▼
                                                   Snapshotted VM: STEP 1..15
```

The agent (per [`AGENTS.md`](AGENTS.md)) drives candidates from the byte-level shortlist through static read and controlled dynamic validation under full Secure Boot + HVCI, and emits a confirmed/rejected result against six criteria.

## Quickstart

```bash
docker compose build

# collect
docker compose run --rm msupdate-catalog   # WHQL HID packages (primary)
docker compose run --rm vendor-catalog     # Dell / HP OEM catalogs
docker compose run --rm snappy-driver      # SDI input driverpacks (torrent)

# query
python -m pipeline.query --stats
python -m pipeline.query --arch x64 --signed --self-hid --user-mode-interface

# promote a candidate -> reports/<sha256>/ (binary + Ghidra decomp + seed dynamic.ps1)
docker compose run --rm report --pick
```

Outputs land in `pipeline_out/`: content-addressed store (`drivers/<sha256>.sys`), append-only index (`drivers/index.jsonl`), per-collector discovery cache and ledger.

## Collectors

| Collector | Pulls | Mechanism |
|-----------|-------|-----------|
| `msupdate-catalog` | Microsoft Update Catalog — WHQL-signed HID packages | Playwright &rarr; `DownloadDialog` &rarr; CDN `.cab` |
| `vendor-catalog` | Dell + HP OEM catalogs | catalog XML &rarr; `.cab` / `.exe` |
| `snappy-driver` | SDI input driverpacks (`DP_Touchpad_*`, `DP_HID`) | aria2 BitTorrent, `--select-file` |

Each resumes from a discovery cache (TTL 7d) and per-item ledger. See [AGENTS.md §2.1](AGENTS.md#21-pick-the-target) for how the agent widens the shortlist when the picker is exhausted.

## Triage model

`index.jsonl` carries, per sha256, every byte-reachable axis. The verdict is a shortlist handle, not a confirmation.

| Axis | Meaning |
|------|---------|
| `mouse_injection` | direct mouse-stack injection signals |
| `keyboard_injection` | keyboard-side analog (disqualifying on its own) |
| `user_mode_interface` | user-openable control surface (device + symlink) |
| `self_hid_device` | VHF, HID minidriver, or hidclass linkage |
| `hardware_independent_init` | unknown in byte triage; dynamic-only |
| `x64_driver` + `signature_present` | PE arch + embedded Authenticode blob |

Verdicts rank from `match` (all axes present) down to `none`. Records are rescored on read, so queries always reflect the current profile. For the full criterion list and how confirmation is established, see [AGENTS.md §1](AGENTS.md#1-required-target-profile).

<details>
<summary>Corpus at a glance (6572 records; historical scoring)</summary>

| verdict | files |
|---------|-------|
| `match` | 0 |
| `candidate` | 939 |
| `keyboard_only` | 176 |
| `self_hid` | 1743 |
| `none` | 3714 |

Axis counts: `signature_present=5818`, `x64_driver=4808`, `user_mode_interface=3809`, `self_hid_device=1743`, `mouse_injection=5`. Arch: `x64=4808`, `x86=1700`, other=62.

The byte-level mouse-stack injection seam is thin (5 binaries total). These stats are the previous scoring profile, kept as historical reference.
</details>

## Tuning

Set env vars before `docker compose run`. Common ones:

- `PDT_MSC_MAX_PACKS=N` — cap packages this run (`msupdate-catalog`)
- `PDT_MSC_MAX_MB=100` — per-`.cab` size cap
- `PDT_*_REFRESH=1` / `PDT_*_REFRESH_DISCOVERY=1` — ignore ledger / discovery cache
- `PDT_*_DISCOVERY_TTL_DAYS=7` — discovery cache lifetime
- `PDT_VC_SOURCES=dell,hp` — which OEM catalogs
- `PDT_SDI_CATEGORIES=touchpad,hid` — SDI driverpack families

Full list in each collector's section of `docker-compose.yml`.

## Safety model

Collection is static end-to-end: downloads, extraction, and PE header peeks run containerised and never execute a driver. Binaries are parsed as bytes only. Dynamic analysis lives in isolated VMs — enforced by [`AGENTS.md`](AGENTS.md) rules R4–R6.

<details>
<summary>Source landscape — what was rejected and why</summary>

The target is narrow, and most driver sources do not carry it. The structural reason: **"dumb" mice and keyboards ship in-box HID and carry no vendor `.sys`**, so general driver repos are thin on exactly the target. HID-input `.sys` density lives in only two places, both already covered: touchpad OEMs (Synaptics / Elan / Alps / Cypress-touch &rarr; `snappy-driver`) and WHQL HID filters (&rarr; `msupdate-catalog`).

Rejected after investigation:

- **Community web archives** (`driverguide`, `softpedia`, `driverscape`) — every one rate-limits or bot-blocks a sustained sweep. Not dependable.
- **archive.org** — no rate limit and huge, but driver items are opaque ISO/RAR blobs (0.3-15 GB to extract maybe one `.sys`); dense items are DriverPack ISOs that overlap `snappy-driver`'s upstream.
- **Station-Drivers** — clean per-file downloads, but organized by *silicon* vendor; mouse/keyboard branches are vestigial.
- **Gaming-mouse peripheral vendors** (Rapoo, Fantech, Bloody/A4Tech, Redragon, Marvo, &hellip;) — their config software is **usermode-only**. Zero `.sys`, no `.inf`, no `CreateService`/class-callback logic. Even macro / anti-recoil engines run in user mode (SendInput / HID feature reports).
</details>

## For AI agents

Load [`AGENTS.md`](AGENTS.md) before anything else. It is dense on purpose. Every clause there is a precondition for valid output; this README is advertising.

## License & Disclaimer

[MIT](LICENSE). Provided for **authorized security research and educational purposes only**. The author is not responsible for any misuse. Collection is static and containerised; dynamic validation lives in isolated VMs. Always obtain proper authorization before testing on any system you do not own.
