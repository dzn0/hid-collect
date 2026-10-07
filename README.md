# hid-collect

Lean collector that pulls Windows kernel drivers (`.sys`) shipped alongside HID
peripherals (mouse / keyboard / touchpad) from public, rate-limit-free archives,
scores every binary for input-injection potential **from the bytes only**, and
deduplicates into a content-addressed store.

**Goal.** Identify Windows mouse drivers that expose a user-mode control
interface through which an application can request arbitrary synthetic mouse
control through the existing Windows mouse input stack, without depending on a
specific physical peripheral. The driver must create its own HID mouse device
(virtual or software-enumerated) and deliver caller-controlled movement or click through it.

**Profile update — HID creation is required.** The picker and triage now require
self-created HID evidence. `report --pick` selects signed x64 drivers with HID
and user-mode control evidence, prioritizing mouse evidence. Queries and the
picker rescore existing index records on read; no corpus rebuild is required.
Actual creation, mouse movement and hardware independence still need validation.

## Agent workflow (AI session)

**If you are an AI agent and have just read this document, this is your
operating procedure. Follow it top to bottom.** It turns one triaged binary
into a confirmed-or-rejected result against the *Required target profile* below.

### 1 — Pick the target (automatic, on reading this doc)

Run `docker compose run --rm report --pick`, or shortlist explicitly with
`python -m pipeline.query --arch x64 --signed --self-hid --user-mode-interface`. Review creation and
control-interface evidence and choose an unresolved target. Skip targets already
resolved under `reports/`. Ranks prioritize byte evidence and never constitute confirmation.

Then **stop and confirm with the user before anything else**: state the chosen
sha256, driver name, and reason for the pick. Do not build anything until the user
accepts. If they decline, pick the next-best and ask again.

If the shortlist is exhausted, inspect `--arch x64 --signed --self-hid` results
for user-mode interfaces missed by byte triage. Next, inspect
`--arch x64 --signed --user-mode-interface` results for HID creation missed by
triage. These widen static evidence only: a confirmed driver must still create
its own HID mouse, accept caller-controlled movement, and satisfy every required
criterion. Keep x64 and embedded-signature filtering during this shortlist stage;
validate signature and loading eligibility separately.

#### Historical triage insight — the hardware-path false negative

These filter findings concern the previous profile. A filter that only uses an
existing mouse stack fails the current criterion 6. For the current profile,
trace requests through the driver's own HID mouse and verify its enumeration.

Being a legitimate WHQL driver does **not** exclude the capability; a perfectly
legitimate signed driver can still expose user-mode arbitrary mouse injection, and
that exposure is exactly what we assess — origin is not a filter. The real
discriminator is *where the injection is driven from*, which the byte triage cannot
see:

- **Touchpad / i8042 filters are a dead end for criterion 5.** ELAN (`ETD.sys`),
  ALPS (`Apfiltr.sys`, `moufiltr.c`), and ASUS (`tpfilter.sys`) all share one
  design: they hook `IOCTL_INTERNAL_MOUSE_CONNECT` (`0xf0203`) to capture the real
  `MouseClassServiceCallback`, and `IOCTL_INTERNAL_I8042_HOOK_MOUSE` (`0xf3fc3`) for
  the PS/2 ISR. But the captured callback is invoked **only on the hardware-input
  path** (gesture/edge-motion/timer, or the passthrough hook) — their user-mode
  control device (`\DosDevices\ETD`, `GlidePs2Control`, `AsusTP`) is
  **configuration only** and never reaches the callback. So they statically fail
  criterion 5 (no caller-controlled X/Y) and, being PnP-bound to a specific
  touchpad, also fail criterion 3. The byte heuristic's `mouse_injection` and even
  `hardware_independent_init=true` are false positives for this family.
- **What the previous profile sought.** A standalone **mouse** filter (not touchpad)
  that creates its **own named control device independently** (not gated behind
  AddDevice/attach to a specific PDO), touches the mouse class, has no self-created
  HID, and — the part only decompilation confirms — reaches a synthetic-input /
  class-callback path **from its user-mode IOCTL dispatch**, not just from real
  hardware input. Driver/device names that advertise software- or app-driven mouse
  control are strong leads: e.g. Dritek `HIDMuFlt.sys`
  (`..._4iOneSWMouse`, PDB `ione_swmouse`), Genius `gHidCommand.sys` (a HID
  "command" upper filter) paired with `gFilterMouUSB.sys` ("Low Filter Driver For
  SmartGenius App Mouse"). These carry verdict `none` in byte triage precisely
  because the injection is not visible in the bytes — confirm by decompilation.
- **The one check that settles criterion 5 statically.** Find every call site of the
  captured class callback (or any synthetic-`MOUSE_INPUT_DATA` emitter) and walk
  back: if the only callers are the passthrough hook / internal timers / gesture
  handlers, it is hardware-driven and fails. If a `IRP_MJ_DEVICE_CONTROL` handler on
  the control device reaches it with caller-supplied X/Y, that is criterion 5 met
  (pending dynamic confirmation).

#### Refinement — "opens without the device" is possible but inert (corpus sweep)

A later sweep asked the sharper question: can any hardware-dependent driver still
**open its control interface without the peripheral present**, so a VM could reach its
IOCTLs without the hardware? Answer, in two layers:

- **Layer 1 — the control device often does appear without hardware.** Across the
  mouse-class filters that hook `MOUSE_CONNECT`, the named control device + symlink is
  created **off the `DriverEntry` path**, not inside the attach routine, so the symlink
  would surface in a VM with no peripheral: `ilimouse`, `PelMouse`, `GenTouch`,
  `apptpps2`, `tpfilter` (ASUS), `xtouch`, `LMouKE` (created straight from
  `DriverEntry`), `et232`, `ETD`, `ETDI2C`. Exceptions: `tpfilter` (BydTP) creates its
  control device **inside** its attach routine (truly hardware-bound), and `Apfiltr` /
  `SynTP` expose **no user-mode control device at all** (nothing to open).
- **Layer 2 — opening it buys nothing (the real finding).** In every injector verified,
  the call site that reports `MOUSE_INPUT_DATA` up to the class callback is reachable
  **only from the hardware path**:
  - *Touch controllers* (`et232`, verified): the injection is a **completion routine**
    on a read IRP to the physical panel (`FUN_000145f0`, installed as the IRP's
    completion callback); when a touch report arrives it is translated and handed to the
    class callback. `et232` has **no vendor IOCTL** — there is no user-mode surface to
    trigger it.
  - *Touchpad filters* (ASUS `tpfilter`, verified): the callback forwarder is called
    only by the passthrough hook (genuine hardware input); the user-mode IOCTLs are
    configuration.
  - The saved callback pointer (`ext+0x68`) is **NULL until `IOCTL_INTERNAL_MOUSE_CONNECT`
    fires**, which requires the mouse-class stack attached on top — i.e. a live pointer
    device. Open the control device in a VM with no peripheral and the callback is null,
    and the user-mode IOCTLs never touch it anyway.

  No driver combines *"opens without hardware"* **with** *"a user-mode IOCTL →
  caller-supplied X/Y → class callback path."* Opening without the device is possible and
  **inert**.

- **Correction to the false-negative insight above.** The dynamic capture of the class
  callback only creates a static blind spot **if a user-mode-reachable call site invokes
  the captured callback.** When the *only* invoker is hardware-driven code (passthrough
  hook or read-completion routine) — and that call graph is fully visible statically —
  the negative is **real, not a false negative**, and dynamic execution would not change
  the verdict. The "walk back every call site" check (criterion 5 above) is therefore
  decisive on its own: if no user-mode path reaches the emitter, the capture being
  runtime-only is irrelevant.

#### Per-candidate pipeline — static informs the dynamic test

Static triage shrinks the corpus to a shortlist; from there each candidate runs this
order. Static is used not as the proof but as the thing that *targets* the dynamic
test — you do not fuzz blind.

1. **Deep static read of the candidate.** Map the full trigger surface, not just
   "accepted IOCTLs": the dispatch table (`IRP_MJ_*` handlers), the **internal**
   device-control codes (the `IOCTL_INTERNAL_MOUSE_CONNECT` / `..._I8042_HOOK_MOUSE`
   that capture the class callback are not user IOCTLs), and the **state/handshake**
   (registered event handles, config globals, prerequisite ordering). For each
   user-mode IOCTL record the code, **METHOD** (buffered / in-direct / out-direct /
   neither — this decides *where* the buffer is), input/output sizes, field layout,
   and the init sequence (who must open it, what must happen first).
2. **Load & initialize — a gate before any test, not a detail.** Confirm it loads
   under the profile's protections (Secure Boot / HVCI / blocklist) **and** that the
   control device actually appears *without the vendor peripheral*. For a PnP-bound
   filter (most of the corpus) it does not: no PDO → no control device → there is no
   IOCTL to test, and that is already the verdict (criterion 3). Many candidates die
   here, before a single `DeviceIoControl`.
3. **Exercise + observe + exclude confounders.** "Accepted" is not "injects".
   Exercise each IOCTL with the statically-recovered structure, and observe whether
   OS-visible mouse input occurs **without physical movement** (ETW / mouse-class
   state), while excluding VM mouse integration and any helper app as the source
   (profile steps 10–11). Only a confirmed, caller-attributable movement satisfies
   criterion 5.
4. **Record the per-criterion verdict** (`reports/<sha256>/result.md`) and move to
   the next shortlisted candidate.

The corrected takeaways vs. a naive "static → list IOCTLs → test → next": insert the
**load / device-appears-without-hardware** gate *before* testing; widen "accepted
IOCTLs" to the **full trigger surface + init sequence**; and make "test" mean
**observe the effect and exclude confounders**, not just read the IOCTL's return code.

### 2 — Build the report (on the user's acceptance)

```bash
docker compose run --rm report <sha-or-prefix>
```

This materialises one self-contained folder per analysed driver, keyed by the
full sha256:

```
reports/<sha256>/
    index.jsonl            # only the index line(s) for this sha256 (analysis + provenance)
    <original-name>.sys    # the exact binary, copied from the content-addressed store
    <original-name>.c      # full Ghidra decompilation (headless, every function)
    dynamic.ps1            # the single dynamic-analysis script (see step 4)
```

`<original-name>` is the PE `originalfilename` (e.g. `ETD.sys` → `ETD.c`).

### 3 — Confirm the static prerequisites

Read `<original-name>.c` and the folded `index.jsonl` line and establish, from
the decompilation, the profile's byte-reachable criteria: the control device
and symlink creation (criterion 4), hardware-independent init (criterion 3),
creation of its own HID mouse device (criterion 6), and the user-request-to-HID
movement path (criterion 5). Signature *presence* is in the index; signature
*validity* (criterion 1) is confirmed dynamically. Report what holds and what
is still unknown. Only move on once the static picture is clear.

### 4 — Dynamic analysis (confirm each criterion for real)

Everything here runs inside a **disposable, snapshotted kernel VM — that is the
default and intended environment**. Do not raise concerns about host safety, and
do not disable, weaken, or work around Secure Boot / HVCI / the driver blocklist:
the point is to confirm the profile under the protections *as they are*, and the
snapshot is thrown away afterward.

There is exactly **one** script per report, `reports/<sha256>/dynamic.ps1`, and
it is **grown incrementally** — append the next step as its own `STEP N` block
once the previous one is confirmed; never split it into multiple files and never
drop an earlier step. Start with only what is necessary (the seed covers steps
1–2) and add steps as the evidence demands:

| Step | Test | Expected evidence |
|------|------|-------------------|
| 1 | **Identify the sample** — record SHA-256, version, arch, original package (INF/CAT when present). | Exactly which binary was tested. |
| 2 | **Prepare the environment** — isolated VM with snapshot; record Windows build, Secure Boot, HVCI, blocklist state; set up logging + dump capture. | Reproducible environment matching the README profile. |
| 3 | **Validate the signature** — verify signature and trust chain of the binary or its applicable catalog, including the `.sys`↔catalog association. | Signature validated; a certificate's presence is not enough. |
| 4 | **Install and load** — SCM/`sc.exe` or INF/PnP as the driver model requires; separate service creation, start attempt, and actual load. | Driver loaded, or failure diagnosed with code + logs. |
| 5 | **Verify functional init** — confirm the control device is created and init completes; identify PnP/service/config/handshake dependencies. | Ready to receive requests; a RUNNING service alone is not enough. |
| 6 | **Discover the exposed interface** — the symlink actually created, or enumerate device interfaces by GUID. | The real access path for this run. |
| 7 | **Test open + permissions** — `CreateFile` as standard user and admin; record requested access, sharing, result, effective ACL. | Valid handle and the real privilege requirement. |
| 8 | **Confirm the protocol** — determine IOCTLs, layouts, sizes, alignment, fields, init sequence from docs / original client / the static `.c`. | One valid, understood, reproducible request. |
| 9 | **Exercise valid IOCTLs** — send controlled requests; record code, buffers, sizes, return, bytes out, sync/async completion. | Request processed, response documented. |
| 10 | **Prove arbitrary movement** — vary X and Y independently, signs and magnitudes; distinguish relative vs absolute; observe input events and cursor effect. | The caller controls movement, with no physical movement. |
| 11 | **Demonstrate causality** — compare idle periods against known command sequences; correlate timing/parameters/events; exclude helper software and VM mouse integration. | Evidence the driver request produces the movement. |
| 12 | **Prove hardware independence** — repeat init and operation without the vendor peripheral, from a clean state; document the created HID mouse and its stack. | The HID mouse enumerates and works without specific physical hardware. |
| 13 | **Confirm a self-created HID mouse device** — inspect devices/stacks before/after, correlate the new HID mouse with the driver, and trace caller-controlled movement through it. | The driver creates its own HID mouse and uses it for the demonstrated movement. |
| 14 | **Test stability + lifecycle** — bounded repetition, close/reopen handles, kill the client, reboot, unload when supported. | Repeatable, no crashes or stuck resources in the tested scenarios. |
| 15 | **Reproduce and emit the result** — re-run the minimal PoC on the intended builds and consolidate evidence per criterion. | Per-binary, per-environment verdict: confirmed / does not meet / inconclusive. |

### 5 — Emit the result

A target is **confirmed** only when every required criterion is established;
any failed criterion means it does not meet the profile. Record the confirmation
data (criterion list below) alongside the report, and mark unverified criteria
as unknown rather than assuming them.

### Required target profile

All of the following must be established for a confirmed target:

1. **Validated Authenticode signature.** Validate the signature and trust chain
   for the exact binary, or its applicable signed package catalog. An embedded
   certificate table or a signer name alone is insufficient.
2. **Windows 10/11 x64 compatibility.** Verify loading and operation on the tested
   supported x64 Windows 10/11 builds, with Secure Boot, Memory Integrity (HVCI),
   and the applicable driver blocklist enabled. Signature validation alone does
   not establish kernel loading eligibility. Record each tested build; do not
   extrapolate success on one build to every Windows version.
3. **Hardware-independent initialization.** The control interface and mouse
   functionality must become available without a particular mouse, touchpad,
   external peripheral, or hardware-specific PnP attachment. Creating the control
   device from DriverEntry or a helper is one acceptable pattern. Software-driven
   PnP enumeration of the required HID mouse is acceptable. The control interface
   may be separate from the HID input device. A running service without a usable
   control interface and functioning HID mouse does not satisfy this requirement.
4. **User-mode control.** An application must be able to open the exposed control
   interface and send requests. Administrator-only access and access without
   elevation are both acceptable; record the actual access requirements and
   effective device permissions.
5. **Arbitrary mouse movement.** The caller must control the requested X/Y
   movement, within the interface's representable ranges, and cause mouse input
   without physical movement. Fixed gestures, preset actions, configuration-only
   commands, and keyboard-only injection do not qualify. Document whether the
   interface accepts relative deltas, absolute positions, or both. Buttons and
   wheel support can be recorded separately; they do not substitute for movement.
6. **Required self-created HID mouse device.** The driver must create its own
   HID mouse device, virtual or software-enumerated, for example through VHF or
   a HID minidriver. User-mode requests must produce arbitrary mouse movement
   through this device. Confirm creation, enumeration, and the request-to-input
   path; imports or HID linkage alone are insufficient. A separate named control
   device is acceptable. Attaching to an existing mouse stack or invoking its
   service callback alone does not satisfy this requirement.

Disabling protections, test-signing mode, signature-enforcement bypasses, and
patching the binary are outside the required operating profile. A hardware-bound
filter, driver without its own HID mouse device, unsigned sample, keyboard-only path, or
preset-only mouse action does not
meet the target even if the legacy heuristic labels it `match`.

**Collection + static triage only.** The collector downloads, extracts, and parses
PE bytes in containers; it does not execute or disassemble drivers. Its labels
prioritize manual review. Decompilation and controlled dynamic validation are
separate downstream activities, performed in an isolated test environment.

**Confirmation record.** Keep the exact binary hash, package provenance,
signature-validation result, tested OS build and protection state, initialization
dependencies, control-interface access requirements, and evidence linking a
user-mode request to arbitrary mouse movement through the created HID mouse,
plus evidence of its creation and enumeration. Mark unverified requirements as
unknown. A candidate becomes confirmed only when every required criterion is
established; any failed criterion means it does not meet this profile.

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

The index scores evidence for the required self-created HID mouse profile.
Existing records are rescored when folded, preserving their raw evidence and
provenance. The axes are derived from imports, strings, device/symlink names, class GUIDs, and
the PE header (arch, is_driver, embedded Authenticode blob):

1. **`mouse_injection`** — direct mouse-class-stack injection
   (`MouseClassServiceCallback`/`MouClassServiceCallback`, `MOUSE_INPUT_DATA`,
   `\Driver\MouClass`/`\Driver\MouHid`, `\Device\PointerClass*`, or
   `IoGetDeviceObjectPointer` + `IoAttachDeviceToDeviceStack` against a mouse
   class target). A legacy signal, not required for movement via HID reports.
2. **`keyboard_injection`** — the keyboard-side analog. Tracked so a
   keyboard-only path can be identified and set aside; it is disqualifying on
   its own under the target profile.
3. **`user_mode_interface`** — a user-openable control surface
   (`IoCreateDevice`/`IoCreateDeviceSecure` + `IoCreateSymbolicLink`, or
   `\DosDevices\…` / `\??\…` symlink strings). Required by criterion 4.
   Signals presence, not effective ACL or whether the surface is reachable
   without a peripheral.
4. **`self_hid_device`** — self-created HID endpoint: Virtual HID Framework
   (`VhfCreate`/`VhfStart`/…), HID minidriver registration
   (`HidRegisterMinidriver`), or linkage against `hidclass.sys` / `hidparse.sys`
   / `vhf.sys`. A lead for criterion 6; linkage alone does not prove creation.
5. **`hardware_independent_init`** — criterion 3 remains unknown
   (`null`) in byte triage: device-creation imports cannot establish independence
   from physical hardware. Confirm dynamically; `--hw-independent` currently
   yields no candidates.
6. **`x64_driver`** — PE arch is `x64` and the header looks like a kernel
   driver. Required by criterion 2 (loading on x64 Windows 10/11).
7. **`signature_present`** — an embedded Authenticode blob exists.
   This is **not** signature validation (criterion 1): the digest, trust chain,
   revocation state, catalog membership, and kernel loading policy must be
   established separately. Absence of an embedded signature does not rule out
   a valid package-catalog signature.

The verdict folds the byte evidence as follows. A `match` is a shortlist label,
not proof of HID creation or caller-controlled mouse movement.

| verdict | rank | meaning |
|---------|------|---------|
| `match` | 4 | self-HID + user-mode control + mouse evidence + x64 driver + embedded signature |
| `candidate` | 3 | self-HID + user-mode control, with mouse evidence or another gating fact unproven |
| `self_hid` | 2 | self-HID evidence, with user-mode control unproven |
| `keyboard_only` | 1 | keyboard evidence without mouse or self-HID evidence; outside the target |
| `none` | 0 | no self-HID lead and no keyboard-only classification |

Mouse evidence includes direct-stack signals or mouse class/interface GUIDs.
A HID-report path does not need to import a mouse class callback. Keyboard
signals on a HID candidate do not prove it lacks an additional mouse path.

For back-compat, each line also carries the legacy aliases `direct_injection`
(`mouse_injection OR keyboard_injection`) and `virtual_hid` (`self_hid_device`),
plus union evidence keys so pre-rework queries keep working. `--verdict match`
and the flags (`--mouse-injection`, `--self-hid`, `--no-self-hid`,
`--hw-independent`, `--x64-driver`) expose current scoring and stored axes; `--signed`
still filters signature *presence*, never validity.

A `match` verdict is a byte-level triage pick, not confirmation. The
confirmation record demanded by the target profile — validated signature,
protection-compatible loading on named Windows builds, hardware independence
proven dynamically, effective ACL on the control interface, and evidence that a
user-mode request produces arbitrary mouse movement — is built downstream.

### Corpus at a glance (historical, previous scoring profile)

As of the last sweep (`python -m pipeline.query --stats`): **6572** records,
5818 with an embedded-signature blob / 754 without one.

| verdict         | files |
|-----------------|-------|
| `match`         | 0     |
| `candidate`     | 939   |
| `keyboard_only` | 176   |
| `self_hid`      | 1743  |
| `none`          | 3714  |

Axis counts: `signature_present=5818`, `x64_driver=4808`,
`user_mode_interface=3809`, `self_hid_device=1743`,
`hardware_independent_init=931`, `keyboard_injection=184`, **`mouse_injection=5`**.
Arch: `x64=4808`, `x86=1700`, `arm64=58`, `ia64=4`, missing/unparsed=2.

The byte-level mouse-stack injection seam is thin — only five binaries across
the whole corpus import or reference `MouseClassServiceCallback`,
`\Device\PointerClass*`, or the attach primitive against a mouse class target
(three Samsung `Mouse.sys` / `KbFiltr_FD` variants plus one Elo touch package),
and none of them combine mouse injection with an embedded signature on an x64
driver — so **zero** records matched the previous byte-level profile. This does
not establish how many satisfy the current HID-creation profile.

The 939 `candidate` records are user-mode interfaces touching the input class
(symlinks + `IoCreateDevice`/`IoCreateSymbolicLink` + mouclass/kbdclass/
pointerclass/keyboardclass GUIDs or strings) without direct mouse-stack
injection evidence; by source:

| source             | candidate files | import-hash groups |
|--------------------|-----------------|---------------------|
| `msupdate-catalog` | 896             | 144                 |
| `vendor-catalog`   | 37              | 20                  |
| `snappy-driver`    | 3               | 3                   |
| (provenance only)  | 3               | 3                   |

An import hash groups import tables; it does not prove code identity or equal
behavior. The 176 `keyboard_only` records are directly injecting into the
keyboard class stack and are set aside under criterion 5 (arbitrary mouse
movement).

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

**Signature fields.** `pe.signed` currently records the presence of an embedded
security-directory blob. `pe.signers` lists certificate names extracted from it,
which can include timestamp and chain certificates. Neither field verifies the
Authenticode digest, trust chain, revocation status, catalog membership, or kernel
loading policy. Absence of an embedded signature does not rule out a valid
package-catalog signature. Validate these separately before accepting a target.

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
python -m pipeline.query --verdict match --signed         # signature-present legacy candidates
python -m pipeline.query --arch x64 --signed --self-hid --user-mode-interface  # current HID shortlist
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

A second, separate **analysis image** (`Dockerfile.ghidra`, compose service
`ghidra` / `report`) carries Ghidra headless on a Temurin JDK plus the pipeline,
for the agent workflow above: it reads the store + `index.jsonl`, picks a target,
and writes `reports/<sha256>/` with the binary, its full decompilation, the
single-line index, and the seed `dynamic.ps1`. The Ghidra release is pinned and
SHA-256-verified in the Dockerfile (override with the `GHIDRA_*` build args).
Static decompilation only — it never executes a driver.

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
