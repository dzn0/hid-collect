# hid-collect

Lean collector that pulls Windows kernel drivers (`.sys`) shipped alongside
keyboard & mouse peripherals from public driver archives — primarily
[DriverGuide](https://www.driverguide.com) (plain, fast), with
[Softpedia](https://drivers.softpedia.com) (Cloudflare-fronted) as a second
source. Deduplicates by SHA-256 into a content-addressed store.

**Goal.** The net is drivers that ship with HID peripherals; the *target* is the
subset able to **inject synthetic mouse/keyboard input from user mode, bypassing
the legitimate HID stack** — the primitive behind input-spoofing / aim-assist
abuse, and the kind of vulnerable signed driver LOLDrivers tracks. Every binary
gets an `hid_input` score + bucket (`strong`/`candidate`/`weak`/`none`) and a
LOLDrivers cross-reference.

**Collection only.** No signature verification, no fingerprint, no analyze stage.
Feed `pipeline_out/drivers/` into the parent `hid-driver-triage` repo for triage.

> **Source status.** Every community web archive tried here —
> `softpedia`, `driverscape`, `driverguide` — rate-limits or bot-blocks a
> sustained sweep (Cloudflare 429 / tarpitted fetches), so none is dependable
> for full-corpus volume from a single IP. The **Microsoft Update Catalog**
> (`catalog`) showed no such limits and is the source to build on; work is
> moving back to it.

## Run

```bash
docker compose build
docker compose run --rm driverguide   # sweep DriverGuide (primary)
docker compose run --rm softpedia     # sweep Softpedia
docker compose run --rm driverscape   # DriverScape mice/touchpad versions
docker compose run --rm collect       # just list collectors
```

Outputs land in `pipeline_out/`:

```
pipeline_out/
  drivers/<sha256>.sys                 # the corpus
  drivers/index.jsonl                  # live append-only index (see below)
  collectors/<collector>/
    discovery_cache.json               # cached listing/detail-URL walk
    processed.jsonl                    # resume ledger
    <timestamp>/manifest.json          # per-run index
```

Re-running resumes from both the discovery cache (reused when ≤
`PDT_*_DISCOVERY_TTL_DAYS` old, default 7) and the per-item ledger
(`processed.jsonl`).

DriverGuide stops the run on HTTP 403/429 or its HTTP-200 access-denied page.
Wait until the source restores access before restarting. Failed items are
retried on the next run. Legacy `no_sys` ledger entries are also retried once:
older versions could mistake a blocked download or extraction failure for an
empty package. New `no_sys` entries require validated downloads and successful
extraction; existing successful entries remain resumable. The ledger is kept
intact, and new entries include a validation version and failure reason.

## How it works

### driverguide (primary)

Before resolving or downloading a package, the collector checks the detail page's
“Supported Operating Systems” section. Explicitly non-Windows-only entries are
recorded as `skipped_os`, including the OS text, and excluded on later runs.
Mixed Windows/non-Windows, missing, and unrecognized metadata remains eligible.
These skips count toward the batch limit and appear as `non-Windows` in progress,
separately from `no_sys` or failures. `PDT_DG_REFRESH=1` rechecks skipped entries.

Plain Apache site, no Cloudflare. The download button is gated by a reCAPTCHA
widget, but it is pure client-side theatre: the page ships a signed `auth` token
inline, and "solving" the captcha just runs `window.location =
detail.php?driverid=N&auth=<token>&frmist=1` — a URL already fully formed in the
page source. The collector reads that token and follows the same redirect; the
reCAPTCHA is never contacted or solved.

1. **Discovery** (cached): paginate the device listing (`device=9` =
   Mouse/Keyboard), harvesting driver ids from each row's `data-url`. Sponsored
   rows are outbound ad anchors with no `data-url`, so they drop out for free.
2. **Acquisition** (per driver): `detail.php?driverid=N` → read inline `auth`
   token + file name → GET `…&auth=…&frmist=1` → extract the members CDN
   `dispatch_cache_get.php` URL (not the ad mirror) → download → 7-Zip extract →
   harvest `.sys`.

### softpedia

Discovery is incremental: fetch listing pages only until there are enough
unprocessed candidates for the next batch, then start downloading. Every successful
listing page is checkpointed atomically, including its manufacturer/page cursor.
Later runs use queued candidates first, then continue discovery from that cursor.
Existing complete discovery caches remain supported. Discovery now uses one
sequential worker; `PDT_SP_CRAWL_JOBS` is retained for compatibility but does not
increase discovery concurrency. Request pacing, cooldowns and batch pauses still apply.

For Softpedia, `PDT_SP_BATCH_PAUSE=0` also bypasses an already-saved pause whose
reason is `pause between batches`. It does not bypass server `Retry-After` or
access-block restrictions. The 20-package batch limit remains active.

`drivers.softpedia.com` is fronted by Cloudflare, which fingerprints the TLS
handshake — plain `urllib` gets a 403 challenge page. The collector uses
[`curl_cffi`](https://github.com/lexiforest/curl_cffi) with `impersonate="chrome"`
to match a current Chrome's TLS stack, which passes with no browser or cookie.
Aggressive request volume still escalates the IP to a JS challenge (429 +
`cf-mitigated`), so requests are paced globally by `PDT_SP_DELAY`.

1. **Discovery** (cached): walk the 44 manufacturers' paginated listings →
   `.shtml` detail-page URLs.
2. **Acquisition** (per driver, at download time): `detail page` → extract
   `spjs_prog_id` + `zgz` → POST `/_xaja/dlinfo.php` → pick the Softpedia CDN
   (`/4/`) mirror → resolve the final file URL → download → 7-Zip extract →
   harvest `.sys`. Only the Softpedia CDN mirror is taken; external vendor
   mirrors can't be enumerated for the host allowlist.

## Index — `drivers/index.jsonl`

A flat tree of hash-named binaries plus one append-only index beside it,
updated on every new `.sys`. Each line is a JSON object keyed by `sha256`:

- **analysis** — everything derivable from the bytes: hashes (incl. `pe.imphash`,
  entropy), PE header (arch, driver flag, NX/ASLR/CFG, sections), imports/exports
  + `capabilities` buckets (`input_injection`, `phys_mem`, `port_io`, …), debug
  PDB identity, version-info, Authenticode presence, overlay, strings, the
  `hid_input` score + bucket, and the `loldrivers` cross-reference.
- **provenance** — `{sha256, provenance: {manufacturer, detail_url, package_url, …}}`

A reader folds every line sharing a `sha256`; `pipeline.index.fold_index()` does
this. Binaries are parsed **as bytes only** — nothing is executed or disassembled.
To (re)build analysis lines for binaries already in the store:

```bash
docker compose run --rm driverguide pipeline.index   # append missing lines
# or locally:  python -m pipeline.index [--rebuild]
```

## Query — `pipeline.query`

Folds `index.jsonl` (one record per sha256) and slices the corpus with
composable filters (AND across flags; a repeated flag ORs its values), then
prints a table, CSV, JSON, a per-driver detail view, or summary stats. Reads the
index only — nothing opens a binary.

```bash
python -m pipeline.query --stats                         # corpus at a glance
python -m pipeline.query --hid-bucket strong --unsigned  # risky injection candidates
python -m pipeline.query --capability phys_mem --csv     # phys-mem importers, CSV
python -m pipeline.query --loldrivers                    # known-vulnerable hits
python -m pipeline.query --show 40061b30b124             # one driver, in detail
```

Key filters: `--sha/--name/--brand/--company` (substring), `--arch`,
`--capability`, `--hid-bucket`/`--min-hid-score`, `--signed`/`--unsigned`,
`--loldrivers`, `--import/--export/--string`, `--url/--guid/--device-path`.
Output: aligned table (`--fields …`), `--csv`, `--json`/`--jsonl`, `--count`,
`--stats`, `--show SHA`; sort with `--sort FIELD [--desc]`, cap with `--limit N`.

## Tuning

Set before `docker compose run`.

**driverguide:**

| Variable                      | Default | Meaning                                 |
|-------------------------------|---------|-----------------------------------------|
| `PDT_DG_DEVICE`               | `9`     | Listing category (9 = Mouse/Keyboard)   |
| `PDT_DG_MAX_PAGES`            | `0`     | Cap listing pages this run (0 = unlim)  |
| `PDT_DG_MAX_PACKS`            | `0`     | Cap total driver pages this run         |
| `PDT_DG_JOBS`                 | `6`     | Parallel download workers               |
| `PDT_DG_DELAY`                | `0.3`   | Min seconds between requests            |
| `PDT_DG_MAX_MB`               | `100`   | Per-package size cap (MB)               |
| `PDT_DG_REFRESH=1`            | off     | Ignore resume ledger                    |
| `PDT_DG_REFRESH_DISCOVERY=1`  | off     | Ignore discovery cache, re-walk listing |
| `PDT_DG_DISCOVERY_TTL_DAYS`   | `7`     | Discovery cache lifetime                |

**softpedia:**

| Variable                      | Default | Meaning                                 |
|-------------------------------|---------|-----------------------------------------|
| `PDT_SP_MAX_MANUFS`           | `0`     | Cap manufacturers this run (0 = unlim)  |
| `PDT_SP_MAX_PACKS`            | `0`     | Cap total detail pages this run         |
| `PDT_SP_JOBS`                 | `6`     | Parallel download workers               |
| `PDT_SP_CRAWL_JOBS`           | `8`     | Parallel discovery crawlers             |
| `PDT_SP_DELAY`                | `0.5`   | Min seconds between requests (anti-throttle) |
| `PDT_SP_SKIP`                 | `mac,macos,linux,android` | Drop detail pages whose slug contains any of these tokens (no Windows `.sys`); empty = off |
| `PDT_SP_MAX_MB`               | `100`   | Per-package size cap (MB)               |
| `PDT_SP_REFRESH=1`            | off     | Ignore resume ledger                    |
| `PDT_SP_REFRESH_DISCOVERY=1`  | off     | Ignore discovery cache, re-walk         |
| `PDT_SP_DISCOVERY_TTL_DAYS`   | `7`     | Discovery cache lifetime                |

If you get throttled (429 / `cf-mitigated`), lower `PDT_SP_JOBS` and raise
`PDT_SP_DELAY`.

## What's inside the image

Python 3.13-slim + `p7zip-full` + `curl` + `curl_cffi`. The analysis code is
stdlib-only; `curl_cffi` is the one runtime dependency, needed to pass
Cloudflare's TLS fingerprint check. Image is ~140 MB.

## Safety model

Collection is static end-to-end: downloads, extractions, and PE header peeks run
containerized and never execute a driver. Binaries are parsed as bytes only.
Dynamic analysis belongs in isolated VMs — not here.

## Conservative collection defaults

Both sources use one acquisition worker, a global 5–7 second interval between
requests, and at most 20 unprocessed packages per execution. Softpedia discovery
also uses one worker. Discovery pages obey the same pacing; the package batch
limit does not cap the discovery walk. Cached discovery avoids repeating it.

`PDT_DG_BATCH_SIZE` / `PDT_SP_BATCH_SIZE` set the package batch size (default 20).
`PDT_DG_BATCH_PAUSE` / `PDT_SP_BATCH_PAUSE` set the minimum pause between executions
(default 900 seconds). The batch is selected **after** excluding completed items,
so a later execution advances through the corpus. `MAX_PACKS` remains a separate
discovery sampling cap; leave it at 0 for successive batches.

Pauses persist in each source's `cooldown.json`. A premature restart exits without
requests. HTTP 403/429 and detected access challenges stop that source for at
least one hour; longer `Retry-After` values take precedence. Both numeric seconds
and HTTP dates are supported, without truncating the server's requested delay.
Other responses with `Retry-After` also stop until that deadline. There is no
automatic restart: run the command again after the pause and restored access.
These rates do not guarantee that a source will permit collection.

## DriverScape

The `driverscape` source walks `/categories/mice-touchpad`, each manufacturer's
paginated device listing (`/page2`, etc.), and every version card on each
`/download/<device>` page. Utility/ad download buttons are excluded. Manufacturer,
device URL, version, release date, supported OS and package provenance are retained.

Download buttons call the site's normal `POST /files` endpoint to obtain an
authorized download URL. If a package requests verification (`valid: false`), it
is recorded as `verification_required` and the collector tries the next version.
These skips count toward the batch limit, remain retryable in later runs, and
appear separately in the progress counters and manifest. HTTP 403/429,
`Retry-After`, and site-wide challenge responses still stop the source.
The collector does not solve or bypass verification. The live
probe during implementation reached this verification gate, so a live package
download has not been confirmed. Temporary access keys are not cached.

Defaults: one worker, 5–7 seconds between requests (including redirects), 20
package versions per run, a 15-minute pause between runs, and a 100 MB package
cap. Block responses stop the source for at least an hour, respecting longer
`Retry-After` values. HTTPS downloads are restricted to DriverScape hosts.

`PDT_DS_MANUFACTURERS` optionally selects comma-separated manufacturer slugs;
empty means all manufacturers. For example:

```bash
docker compose run --rm -e PDT_DS_MANUFACTURERS=microsoft,egalax driverscape
```

Other settings: `PDT_DS_DELAY`, `PDT_DS_BATCH_SIZE`, `PDT_DS_BATCH_PAUSE`,
`PDT_DS_MAX_MB`, `PDT_DS_DISCOVERY_TTL_DAYS` (7), `PDT_DS_REFRESH` and
`PDT_DS_REFRESH_DISCOVERY`. Refresh does not bypass cooldowns.
Discovery and stable version links are cached. Resume is per device/package pair,
so a device with multiple versions can continue in a later batch. Failed versions
remain retryable. Extraction errors are not recorded as `no_sys`.
Discovery requests obey the interval but are not capped by the package batch size.
