# AGENTS.md

Bootstrap + CLI reference. Pipeline: collect -> index -> triage -> disasm -> query.
Entry points: `python -m pipeline.<stage>` (local) or `docker compose run --rm <service>`.

## Layout

```
pipeline/
  collect.py              python -m pipeline.collect
  index.py                python -m pipeline.index          (analyze/backfill)
  triage.py               python -m pipeline.triage         (policy gate)
  sigcheck.py             PKCS#7 signer classifier (lib)
  query.py                python -m pipeline.query
  config.py               tool + path resolution
  collectors/             touslesdrivers_input, msupdate_catalog
  disasm/                 python -m pipeline.disasm
    ghidra_scripts/DriverTriage.py   analyzeHeadless post-script
  refs/loldrivers_index.json
pipeline_out/             (gitignored) machine store
  drivers/<sha256>.sys
  drivers/index.jsonl     append-only: analysis + provenance + disasm lines
reports/                  (gitignored) consumer output
  index.jsonl             lean index (one line/driver)
  <sha256>/{<name>.sys,<name>-driver-entry.c,disassembly.txt}
```

## Build

```bash
docker compose build                                   # base -> hid-collect:latest
docker compose build --build-arg WITH_PLAYWRIGHT=1 catalog-deep   # + Chromium
docker compose build --build-arg WITH_GHIDRA=1 disasm             # + JDK21 + Ghidra
```

| image | arg | adds |
|---|---|---|
| hid-collect:latest | — | p7zip-full, curl, osslsigncode (~130MB) |
| hid-collect:playwright | WITH_PLAYWRIGHT=1 | Chromium (~1GB) |
| hid-collect:ghidra | WITH_GHIDRA=1 | Temurin 21 + Ghidra 11.3.1 (~2GB) |

## Collect

```bash
docker compose run --rm collect                        # list collectors
docker compose run --rm run                            # touslesdrivers-input
docker compose run --rm tight                          # cats 10,11 + mouse/kbd allowlist
docker compose run --rm catalog                        # msupdate-catalog (urllib, 1 page)
docker compose run --rm catalog-deep                   # msupdate-catalog (Playwright, 20 pages)
# local:
python -m pipeline.collect --list
python -m pipeline.collect touslesdrivers-input [-j N] [--no-progress]
python -m pipeline.collect --all
```

Output: `pipeline_out/drivers/<sha256>.sys` + one analysis line per new `.sys`.
Dedup by sha256 across all collectors. Resumable (discovery cache + processed.jsonl).

## Index (analyze / backfill)

```bash
docker compose run --rm run pipeline.index             # append missing analysis lines
python -m pipeline.index [--rebuild] [--min-str 5] [--max-str 3000]
```

`--rebuild` drops existing analysis lines, re-emits them (provenance preserved).
Analysis line keys: `pe` (arch, kmdf, sections, imports, capabilities, signature,
device), `hid_input`, `loldrivers`, `strings`, `interesting_strings`.
`pe.signature.cert_class` in {production,test,private,unsigned,unknown}.

## Triage (policy gate)

```bash
docker compose run --rm triage                         # dry run, preset 'loadable'
docker compose run --rm triage --target                # preset 'target'
docker compose run --rm triage --require prod-cert,x64,device
docker compose run --rm triage --require prod-cert --apply        # prune store + index
python -m pipeline.triage [--require G,G] [--target|--loadable] [--apply] [--list-failing] [--no-index]
```

Gates (AND): `signed prod-cert x64 driver device user-open hid not-lol lol`
Presets: `loadable`=signed,prod-cert,x64 ; `target`=loadable+driver,device
Writes `reports/index.jsonl` (passing set) unless `--no-index`.
`--apply` deletes failing `<sha>.sys`, drops their index lines, writes
`pipeline_out/drivers/triage_removed_<ts>.txt`. Default = dry run.

## Disasm (Ghidra verdicts, req b+c)

```bash
docker compose run --rm disasm                         # all 'target' candidates
docker compose run --rm disasm --limit 200             # batch (resumable)
docker compose run --rm disasm --sha 40061b30          # one driver by sha prefix
docker compose run --rm disasm --gate loadable         # wider selection
docker compose run --rm disasm --rebuild               # ignore done set
python -m pipeline.disasm [--gate target] [--sha HEX] [--limit N] [--timeout 600] [--rebuild]
```

Requires hid-collect:ghidra. Selects via triage gate, skips sha with an existing
disasm line (resumable). Per driver -> `reports/<sha256>/`:
`disassembly.txt`, `<name>-driver-entry.c`, `<name>.sys`. Appends a compact
`kind:"disasm"` line to the store index; refreshes `reports/index.jsonl`.
Verdicts: `mouse_injection.verdict` (b), `symlink_user_reachable` (c).

Run detached (long; ~12-14h for full target set):
```bash
# bash
docker compose run --rm -T disasm > reports/disasm_run.log 2>&1 &
```
```powershell
# PowerShell
Start-Job -Name disasm -ScriptBlock { Set-Location E:\hid-collect; docker compose run --rm -T disasm *>&1 | Out-File E:\hid-collect\reports\disasm_run.log -Encoding utf8 }
Get-Content E:\hid-collect\reports\disasm_run.log -Wait -Tail 20
```

## Query

```bash
docker compose run --rm run pipeline.query --stats
python -m pipeline.query --prod-cert --arch x64 --declares-symlink --user-open
python -m pipeline.query --injects --symlink-reachable
python -m pipeline.query --prod-cert --hid-bucket strong --fields sha,cert,kmdf,fw,symlink,useropen,hid,signer,name
python -m pipeline.query --show <sha-prefix>
```

Filters (AND; repeat flag = OR within): `--sha --name --brand --company --arch
--capability --hid-bucket --min-hid-score --creates-user-device --signed
--unsigned --prod-cert --cert-class --kmdf --declares-symlink --user-open
--injects --symlink-reachable --loldrivers --wx --driver --overlay
--min-entropy --max-entropy --import --export --string --url --guid --device-path`
Output: `--fields a,b,c --csv --json --jsonl [--strings] --count --stats --show
--sort F [--desc] --limit N --no-color`
Fields: `sha arch sig cert signer kmdf fw symlink useropen inject reach hid lol
caps driver nx aslr cf brand company product package url imphash` + any dotted path.

## Pipeline (full, from empty store)

```bash
docker compose build
docker compose run --rm tight                          # collect
docker compose run --rm triage --target                # gate -> reports/index.jsonl
docker compose build --build-arg WITH_GHIDRA=1 disasm
docker compose run --rm disasm --limit 200             # verdicts (repeat / detach for all)
python -m pipeline.query --prod-cert --injects --symlink-reachable --fields sha,name,signer,hid
```

## Env

| var | default | stage |
|---|---|---|
| PDT_OUTPUT_DIR | pipeline_out | all |
| PDT_REPORTS_DIR | reports | triage, disasm |
| PDT_7Z | PATH | collect |
| PDT_SIGNTOOL | PATH/legacy | sigcheck (optional verify) |
| PDT_GHIDRA_HOME | /opt/ghidra | disasm |
| PDT_GHIDRA_HEADLESS | — | disasm (override full path) |
| PDT_HID_CATEGORIES | 10,11,17,19 | touslesdrivers |
| PDT_HID_TYPES | 1,4 | touslesdrivers |
| PDT_HID_BRAND_ALLOW / PDT_HID_BRAND_DENY | / curated | touslesdrivers |
| PDT_HID_MAX_BRANDS / PDT_HID_MAX_PACKS | 0 | touslesdrivers |
| PDT_HID_JOBS / PDT_HID_CRAWL_JOBS | 6 / 8 | touslesdrivers |
| PDT_HID_MAX_MB | 60 | touslesdrivers |
| PDT_HID_REFRESH / PDT_HID_REFRESH_DISCOVERY | off | touslesdrivers |
| PDT_HID_DISCOVERY_TTL_DAYS | 7 | touslesdrivers |
| PDT_MSC_QUERIES / PDT_MSC_JOBS / PDT_MSC_CRAWL_JOBS | — | msupdate-catalog |
| PDT_MSC_MAX_PAGES | 1 (>1 = Playwright) | msupdate-catalog |
| PDT_MSC_MAX_PACKS / PDT_MSC_MAX_MB | / 100 | msupdate-catalog |
| PDT_MSC_BROWSER_WORKERS | 3 | catalog-deep |

## Invariants

- static only; no `.sys` is executed. disasm = Ghidra static analysis, not a load.
- `(c)` final confirmation = dynamic load in an isolated VM.
- `pipeline_out/` and `reports/` are gitignored; never commit them.
- store index is append-only; fold by sha256 (`pipeline.index.fold_index`).
- disasm is resumable; WDF index->name map in DriverTriage.py is version-sensitive.
