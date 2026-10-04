# AGENTS.md

Bootstrap + CLI reference. Pipeline: collect -> index -> triage -> disasm -> query.
Entry points: `python -m pipeline.<stage>` (local) or `docker compose run --rm <service>`.

## MISSION

Find signed, production-cert, x64 Windows kernel drivers shipped with HID
peripherals (keyboard/mouse/tablet/gamepad) that can **inject synthetic
mouse/keyboard input from user mode, bypassing the legitimate HID stack**, via a
**user-openable device reachable right after `sc start`** (no PnP/hardware gate).
This is the input-spoofing / aim-assist primitive and the vulnerable-signed-driver
(BYOVD / LOLDrivers) shape. Two verdicts decide a hit:
- **(b) injects** — drives the mouse/kbd class callback OR feeds a virtual-HID
  device synthetic reports over IOCTL (`mouse_injection.verdict` / lean `injects`).
- **(c) symlink_user_reachable** — symlink created from `DriverEntry`, not behind
  PnP, and SDDL lets a non-admin open it (`symlink_user_reachable`).
A TARGET = (b) AND (c). **Static is evidence to NARROW + PREP, never the verdict;
the VM is the judge of both (b) and (c)** (see DYNAMIC CONFIRM). Static (b) is a
high-recall hint that both over- and under-calls: `virtual_hid_ioctl` fired true
on a driver that only intercepts/remaps (vocabulary false-positive, vhidev
`c8819dbd` - a 5-min VM sweep settled what a day of static could not). Static (c)
likewise had a control-device-at-DriverEntry false-negative. So: use static to
rank and to fill the probe, then LOAD IN A VM to decide.

**class-hook = filter signature, NOT inject** (post-02f02ef3-ETD fix). A driver
that handles `IOCTL_INTERNAL_MOUSE_CONNECT (0xf0203)` / `KEYBOARD_CONNECT (0xb0203)`
and stores the class service callback is the SHAPE of a mouse/kbd class FILTER
(ETD, Apkbfiltr, Razer rz*endpt - all VM-rejected). Those IOCTLs reach the
driver only via `IRP_MJ_INTERNAL_DEVICE_CONTROL` from mouclass/kbdclass
(kernel->kernel); user `CreateFile+DeviceIoControl` emits `IRP_MJ_DEVICE_CONTROL`
and never hits them. The stored callback is fed by the hw-input path, not user.
Walker now tags that pattern as `mouse_injection.filter_hook` (informational);
`mouse_injection.verdict` fires only on `class_send_ioctl` or `virtual_hid_ioctl`.
Candidate IOCTLs with `internal_only=True` (device 0xB/0xF + METHOD_NEITHER +
FILE_ANY_ACCESS) are excluded from the probe sweep.

## FAST START (do this on session open, no prompt needed)

1. READ `reports/index.jsonl` (lean, one line/driver, **best-candidate-first**,
   already folded). This is the entry point — not the big store index.
2. CLASSIFY each row:
   - `status=="rejected"`                                      -> **SKIP** (already ruled out; never re-pick)
   - `status=="confirmed"`                                     -> **TARGET** (b+c proven in VM)
   - `injects==true && symlink_user_reachable==true`           -> **TARGET CANDIDATE** (static b+c) -> CONFIRM IN VM
   - `injects==true && !symlink_user_reachable`                -> static injects; still probe (c)-hint can be a false-negative
   - no `injects` key present                                  -> **not yet disasm'd**
   - CANDIDATE profile (pre-disasm, worth disasm):
     `cert_class=="production" && arch=="x64" && declares_symlink &&
      sddl_grants_user && hid startswith strong|candidate`
   Rejected rows carry a `status`/`status_reason` and are sunk to the bottom of
   `reports/index.jsonl`, so the best-first order already front-loads live work.
   When you finish ruling a driver out, record it so the next session skips it:
   `python -m pipeline.status reject <sha> --reason "fails (c): PnP-gated"` (see Status).
3. CONFIRM detail: take the candidate's `sha256`, fold its lines in
   `pipeline_out/drivers/index.jsonl` (grep the sha prefix; several lines share
   it -> merge). Pull the WHY: `hid_input.{bucket,score,string_hits,import_hits}`,
   `pe.device.{symlink_paths,sddl,sddl_grants_user,framework}`,
   `pe.apis.capabilities`, `pe.signature.{cert_class,signer_cn}`, `loldrivers`.
4. If a strong CANDIDATE has no verdict yet -> run disasm to get (b)/(c):
   `docker compose run --rm disasm --sha <prefix>` (needs hid-collect:ghidra).
5. REPORT directly and concisely (one block per driver), then continue the flow:

```
<sha12> <name>  [TARGET | CANDIDATE | injects-only | no-verdict]
  signer=<signer_cn> cert=<cert_class> arch=<arch> kmdf=<t/f> framework=<fw>
  hid=<bucket:score>  symlink=<paths>  user-open=<sddl_grants_user>
  (b) injects=<v/?>   (c) reachable=<v/?>   lol=<y/n>
  why: <string_hits/import_hits/capabilities that drove the score>
  next: <disasm --sha … | dynamic VM confirm | discard: fails gate X>
```

State plainly when a set is empty (e.g. "0 TARGETs; N candidates pending disasm").
Expect most work to be: pick candidates, disasm them, re-read, then CONFIRM the
single best in a VM (DYNAMIC CONFIRM). Never execute a `.sys` on the pipeline
host; the only load is `reports/<sha>/probe.ps1` in a disposable VM (see Invariants).

## DYNAMIC CONFIRM (dynamic-first; the bare-metal rig is the judge)

Flow: `collect -> analyze -> walker -> AI picks ONE -> fill probe -> rig -> verdict`.
The walker is the SCRIVENER (artifacts + hints), the rig is the JUDGE (bare-metal,
HVCI-on; see DYNAMIC RIG). VM is REJECTED: VM HID/mou/kbd class structures diverge
from bare metal and corrupt the (b) oracle (confirmed in prior work).

1. Walker emits per driver (hints, not verdicts): `<name>.c`, `disasm.txt`,
   `summary.md`, plus extracted `ioctls[]` (dispatch codes, decoded CTL_CODE) and
   `report_descriptor` (per-ReportID label + payload byte sizes). These are the
   inputs the probe needs - see summary.md sections "Candidate IOCTLs" and
   "HID report descriptor".
2. AI picks ONE best candidate per pass, reads its `summary.md` + `<name>.c`,
   confirms the dispatch/symlink in `disasm.txt`.
3. AI fills the template `pipeline/disasm/templates/dynamic_probe.ps1` -> drop the
   filled copy at `reports/<sha256>/probe.ps1`. CONFIG fields: `LoadMode`
   (service|pnp), `SysPath`, `ServiceName` (or `InfPath`+`HardwareId`),
   `DeviceUser` (`\DosDevices\X` -> `\\.\X`), `ExpectSid` (WD), `Ioctls` (from the
   walker), `Payloads` (shaped by `report_descriptor`).
4. Run on the bare-metal HVCI rig (DYNAMIC RIG), elevated (UAC). The rig IS this
   host; recovery is by OS reset (RECOVERY), not VM isolation. The probe GATES
   before any sweep: service must be RUNNING and the device object must exist,
   else it stops (no BSOD risk taken blind). Then it proves (c) (open + SDDL) and
   sweeps (b) (IOCTL x payload) while the LL-hook oracle watches for any synthetic
   mouse/kbd event.
5. Read the sweep: `dX/dY != 0` => (b) INJECTS (TARGET if (c) held); `Pend=True`
   => blocking read (intercept/keylogger path, driver->user); `OK, Bytes=0, no
   move` => config IOCTL. Record the verdict: `python -m pipeline.status set
   <sha> confirmed --reason "b+c in VM: ..."` or `reject <sha> --reason "...".

Dynamic does not scale (kernel load per driver, BSOD risk) - that is why step 2
picks ONE. Static narrows + prepares; the rig confirms the top candidate.

## DYNAMIC RIG + OS RECOVERY (bare-metal, HVCI-on)

Judge = the bare-metal host, NOT a VM (see DYNAMIC CONFIRM for why). Non-
virtualization hosts are out (no HVCI). This host IS the rig; this supersedes the
old "never execute on the pipeline host" rule - recovery is by OS reset, not VM
isolation (see RECOVERY).

Rig state (REQUIRED): HVCI + VBS running, `VulnerableDriverBlocklistEnable=1`.
Verify: `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard
Win32_DeviceGuard` -> `SecurityServicesRunning` contains `2` = HVCI.

HVCI load-test = FREE pre-filter, folded into the `rig` step:
- `sc start` FAILS under HVCI -> blocklisted or HVCI-incompatible -> DEAD surface,
  discard, do NOT fuzz.
- `sc start` LOADS -> LIVE surface (usable on a hardened modern box) -> sweep (c)/(b).

Oracle = global `WH_MOUSE_LL` + `WH_KEYBOARD_LL` in an interactive session
(session 1); ANY synthetic event during the sweep = (b) by effect. `dX/dY` alone
misses keyboard/click injectors. A session-0 service CANNOT host the hook ->
autologon of an admin account REQUIRED.

Harness home = `E:\hidfuzz` (queue + checkpoint + `results.jsonl` + oracle);
survives reboot AND a C: reset. Checkpoint before each `sc start` and each IOCTL;
BSOD -> auto-reboot -> boot scheduled-task resumes at N+1; a load/IOCTL that
bugchecks is itself signal (dangerous primitive, e.g. world-RW).

Phases: (0) config - baseline, autologon, auto-reboot, boot task; (1) HVCI
load-filter over distinct prod+x64 (live vs dead), LOW risk; (2) inject-fuzz the
LIVE set only (IOCTL x payload + oracle), HIGH risk.

## RECOVERY (OS corruption)

Disk layout: `C:` (OS/kernel) = disk 1; `E:` "Dados" (store + `E:\hidfuzz`) =
disk 0, SEPARATE; EFI/boot/recovery on disk 1. No disk image kept - workflow is
reset-oriented (winget reinstall script + all projects on GitHub).
- OS corruption -> Windows "Reset this PC" (Windows-drive only) + winget + `git
  clone`. `E:` (store, 202MB `index.jsonl`, `.sys`, `memory-backup`) survives it
  (separate disk).
- memory files (`C:\Users\<u>\.claude\...\memory`) are wiped by a C: reset ->
  backed up at `E:\hidfuzz\memory-backup`.
- Residual risk: a world-RW IOCTL corrupting `E:` directly (low prob). Optional
  insurance: gzip both `index.jsonl` OFF `E:` (USB / `gh release`).

## Layout

```
pipeline/
  collect.py              python -m pipeline.collect
  index.py                python -m pipeline.index          (analyze/backfill)
  triage.py               python -m pipeline.triage         (policy gate)
  sigcheck.py             PKCS#7 signer classifier (lib)
  query.py                python -m pipeline.query
  status.py               python -m pipeline.status         (AI review status)
  config.py               tool + path resolution
  collectors/             touslesdrivers_input, msupdate_catalog
  disasm/                 python -m pipeline.disasm
    ghidra_scripts/DriverTriage.py   analyzeHeadless post-script
    templates/dynamic_probe.ps1      VM probe template (AI fills per driver)
  refs/loldrivers_index.json
pipeline_out/             (gitignored) machine store
  drivers/<sha256>.sys
  drivers/index.jsonl     append-only: analysis + provenance + disasm lines
reports/                  (gitignored) consumer output
  index.jsonl             lean index (one line/driver; carries status when set)
  <sha256>/<name>.sys     binary (copied from store)
  <sha256>/<name>.c       full pseudo-C; every fn tagged [REACHED]/[UNREACHED] by walker
  <sha256>/summary.md     (b)/(c) evidence + WDF calls + symlink callers + Candidate
                          IOCTLs + HID report descriptor  (static = hints, not verdicts)
  <sha256>/disasm.txt     raw objdump assembly (-d -M intel); confirmation cross-check
  <sha256>/probe.ps1      filled dynamic_probe.ps1 (the VM step; see DYNAMIC CONFIRM)
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

## Status (AI review verdict, persistent)

```bash
python -m pipeline.status reject <sha> --reason "fails (c): symlink not from DriverEntry"
python -m pipeline.status clear  <sha>                 # un-reject
python -m pipeline.status set    <sha> confirmed --reason "b+c verified in VM"
python -m pipeline.status list                         # every driver carrying a status
```

Records an AI-authored `status` (`rejected`|`confirmed`|`candidate`|`active`) per
driver so a ruled-out driver is not re-picked next session. Persisted as an
append-only `kind:"status"` line in `pipeline_out/drivers/index.jsonl` (survives
every triage/disasm rewrite; `fold_index` merges it, last-non-null wins). Surfaced
as `status`/`status_reason` in `reports/index.jsonl`; `rejected` rows sort last.
Each command refreshes the lean index. sha256 prefix is enough (must be unambiguous).

## Disasm (Ghidra verdicts, req b+c)

```bash
docker compose run --rm disasm                         # all 'target' candidates
docker compose run --rm disasm --limit 200             # batch (resumable)
docker compose run --rm disasm --sha 40061b30          # one driver by sha prefix
docker compose run --rm disasm --gate loadable         # wider selection
docker compose run --rm disasm --rebuild               # ignore done set
docker compose run --rm disasm --jobs 6                # 6 parallel Ghidra workers
docker compose run --rm disasm --shas-file reports/distinct_shas.txt --jobs 6
python -m pipeline.disasm [--gate target] [--sha HEX] [--shas-file PATH] [--jobs N] [--limit N] [--timeout 600] [--rebuild]
```

Requires hid-collect:ghidra (bundles binutils for objdump). Selects via triage
gate (or exact list with `--shas-file`, one sha256/line, bypasses the gate),
skips sha with an existing disasm line unless `--rebuild` (resumable). `--jobs N`
runs N analyzeHeadless in parallel (each gets an isolated HOME; 4-6 sane on a
12-core/16GB host). Per driver -> `reports/<sha256>/`: `<name>.c` (full pseudo-C,
reached/unreached), `summary.md` (verdicts + evidence), `disasm.txt` (raw asm),
`<name>.sys`. Appends a compact `kind:"disasm"` line to the store index;
refreshes `reports/index.jsonl`.
Static fields: `mouse_injection.verdict` (b-hint), `symlink_user_reachable`
(c-hint), `ioctls[]` + `report_descriptor` (probe pre-fill). These RANK and PREP;
the VM decides (b)/(c) - see DYNAMIC CONFIRM. Never reject a candidate on the
static (b)/(c) alone (both have known false calls).

`--shas-file` list: one representative per imphash group dedups the ~2187 target
candidates to ~434 distinct binaries (duplicates are version-hashes, same code,
same verdict). Walker blind spots = `[UNREACHED]` fns in `<name>.c` that still
reference a symlink / connect-IOCTL / class primitive.

Run detached (long; full distinct set ~434 drivers, ~1h at --jobs 6):
```bash
# bash
docker compose run --rm -T disasm --shas-file reports/distinct_shas.txt --jobs 6 > reports/disasm_run.log 2>&1 &
```
```powershell
# PowerShell
Start-Job -Name disasm -ScriptBlock { Set-Location E:\hid-collect; docker compose run --rm -T disasm --shas-file reports/distinct_shas.txt --jobs 6 *>&1 | Out-File E:\hid-collect\reports\disasm_run.log -Encoding utf8 }
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

- the pipeline stages (collect/index/triage/disasm/query) are static; no `.sys`
  is executed ON THE PIPELINE HOST. disasm = Ghidra static analysis, not a load.
- `(b)` and `(c)` final confirmation = load the emitted `reports/<sha>/probe.ps1`
  on the bare-metal HVCI rig (DYNAMIC RIG). The rig IS this host; recovery is by
  OS reset (RECOVERY), not VM isolation - VM is rejected (HID structs diverge).
  The probe still gates before sweeping (service RUNNING + device object exists)
  and never sweeps blind.
- `pipeline_out/` and `reports/` are gitignored; never commit them.
- store index is append-only; fold by sha256 (`pipeline.index.fold_index`).
- disasm is resumable; WDF index->name map in DriverTriage.py is version-sensitive.
- this file's register: documentation / CLI reference — declarative, terse,
  imperative. No conversational prose. On any rewrite, keep that register.
