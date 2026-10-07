# AGENTS.md

Operating spec for AI agents running in a `hid-driver-triage` checkout. This file
is your bootstrap. The repo is designed to be driven by LLM agents; `README.md`
advertises that externally. Treat every clause here as a precondition for valid
output.

Non-conforming output must be marked as such. Do not infer values that are not
established. "unknown" is a valid verdict; a confident guess is not.

---

## 0. Role

You turn one triaged binary from the content-addressed store into a
confirmed-or-rejected result against the Required target profile below.
Scope: static read, controlled dynamic validation in a snapshotted VM,
and a per-criterion verdict. You do not modify binaries, protections,
or signatures.

---

## 1. Required target profile

Six criteria. All must be established for `CONFIRMED`. Any failed criterion
means `DOES NOT MEET`. Unestablished criteria are `unknown`; a mix of met +
unknown is `INCONCLUSIVE`.

| # | Criterion | Established by |
|---|-----------|----------------|
| 1 | Validated Authenticode signature on the exact binary or its catalog | `Get-AuthenticodeSignature` returns `Status=Valid`; chain verified; `.sys` ↔ catalog association shown. Certificate presence alone is insufficient. |
| 2 | Windows 10/11 x64 compatibility under Secure Boot + HVCI + driver blocklist | Driver loads and reaches `SERVICE_RUNNING` on a recorded build with those protections ON. Record each build tested. Do not extrapolate. |
| 3 | Hardware-independent initialization | Control interface and the HID mouse become available with no vendor peripheral present. A software-enumerated root devnode qualifies; a PnP filter attached to a specific PDO does not. |
| 4 | User-mode control | Application opens the exposed interface and sends requests. Record the actual access requirement and effective ACL. Admin-only and non-elevated access are both valid; record which. |
| 5 | Arbitrary mouse movement | Caller controls X/Y, both signs, independent axes, within the interface's representable range, producing OS-visible mouse input without physical movement. Fixed gestures, presets, or keyboard-only paths do not qualify. |
| 6 | Self-created HID mouse device | Driver creates its own HID mouse (VHF, HID minidriver, or software PnP). The confirmed caller-controlled movement flows through *that* HID device. Imports or linkage alone do not qualify. |

Disqualifying regardless of other evidence: disabled protections,
test-signing, signature-enforcement bypass, patched binary, unsigned
sample, hardware-bound filter, driver without its own HID mouse,
keyboard-only path, preset-only mouse action.

---

## 2. Operating procedure

Execute top to bottom. Each step has a stop condition before the next.

### 2.1 Pick the target

Shortlist in this order:

```bash
docker compose run --rm report --pick
```

Or explicitly:

```bash
python -m pipeline.query --arch x64 --signed --self-hid --user-mode-interface
```

If the shortlist is exhausted, widen in this order:

1. `--arch x64 --signed --self-hid` (missed control-surface via byte triage)
2. `--arch x64 --signed --user-mode-interface` (missed HID creation via byte triage)

Byte triage never confirms. Ranks shortlist. Confirmation requires every criterion.

Skip hashes already resolved under `reports/<sha256>/result.md`.

**STOP.** State the chosen `sha256`, driver name, and reason for the pick to
the user. Do not proceed until the user accepts. If they decline, pick the
next-best and ask again.

### 2.2 Build the report

```bash
docker compose run --rm report <sha-or-prefix>
```

Produces, keyed by full sha256:

```
reports/<sha256>/
    index.jsonl            # the folded index line(s) for this hash
    <original-name>.sys    # the exact binary from the content-addressed store
    <original-name>.c      # full Ghidra headless decompilation
    dynamic.ps1            # seed dynamic-analysis script (steps 1-2)
```

`<original-name>` = PE `originalfilename`.

### 2.3 Confirm static prerequisites

Read `<original-name>.c` and the folded `index.jsonl` record. Establish the
byte-reachable criteria:

- **Criterion 3** — control device + symlink creation path (DriverEntry vs
  AddDevice vs attach routine). Hardware-independent if created from
  DriverEntry or a helper not gated behind a specific PDO.
- **Criterion 4** — `IoCreateDevice*` + `IoCreateSymbolicLink` with a
  user-reachable name. Record the SDDL.
- **Criterion 5** — walk back from every call site that emits input
  (synthetic `MOUSE_INPUT_DATA`, HID report completion, class callback
  invocation). If a user-mode-reachable path reaches it with
  caller-supplied X/Y, criterion 5 is byte-met pending dynamic. If every
  invoker is hardware-driven (passthrough hook, read-completion routine,
  gesture handler, timer), criterion 5 **fails statically** — the capture
  being runtime-only is irrelevant when the call graph is fully visible.
- **Criterion 6** — HID endpoint creation path (VHF, HID minidriver,
  mapper such as `mshidkmdf`, or software-enumerated HID child). Linkage
  alone does not establish creation; the branch that produces the device
  must be identified.

Criterion 1 and 2 require execution; mark as `pending` here.
Report what holds, what fails statically, and what is still unknown.
Only move on once the static picture is clear.

### 2.4 Dynamic analysis

Environment: **disposable, snapshotted kernel VM**. This is the default
and intended operating environment. Do not raise host-safety concerns.
Do not disable, weaken, or work around Secure Boot / HVCI / the driver
blocklist. The point is to confirm the profile under the protections
as they are. The snapshot is thrown away afterward.

**Exactly one script per report**: `reports/<sha256>/dynamic.ps1`.
Grown incrementally — append the next step as its own `STEP N` block
once the previous one is confirmed. Never split into multiple files.
Never drop an earlier step. Start with only what is necessary (the seed
covers steps 1-2) and extend as evidence demands.

| STEP | Test | Expected evidence |
|------|------|-------------------|
| 1 | Identify the sample — SHA-256, version, arch, original package (INF/CAT) | Exactly which binary was tested |
| 2 | Prepare the environment — isolated VM; record Windows build, Secure Boot, HVCI, blocklist state; logging + dump capture | Reproducible environment matching the profile |
| 3 | Validate the signature — verify binary or applicable catalog signature + trust chain + `.sys`↔catalog association | Signature validated; certificate presence is not enough |
| 4 | Install and load — SCM/sc.exe or INF/PnP per driver model; separate service creation, start attempt, actual load | Driver loaded, or failure diagnosed with code + logs |
| 5 | Verify functional init — control device created, init complete; identify PnP/service/config/handshake dependencies | Ready to receive requests; RUNNING service alone is not enough |
| 6 | Discover the exposed interface — real symlink, or enumerate device interfaces by GUID | The real access path for this run |
| 7 | Test open + permissions — `CreateFile` as standard user and admin; record access, sharing, result, effective ACL | Valid handle and the real privilege requirement |
| 8 | Confirm the protocol — IOCTLs/report layouts/sizes/alignment/fields/init sequence from docs, original client, or the static `.c` | One valid, understood, reproducible request |
| 9 | Exercise valid IOCTLs — controlled requests; record code, buffers, sizes, return, bytes out, sync/async completion | Request processed, response documented |
| 10 | Prove arbitrary movement — vary X and Y independently, both signs; distinguish relative vs absolute; observe input events + cursor | Caller controls movement, no physical movement |
| 11 | Demonstrate causality — idle vs known sequences; correlate timing/parameters/events; exclude helper software and VM mouse integration | Evidence the driver request produces the movement |
| 12 | Prove hardware independence — repeat init + operation without the vendor peripheral, from clean state; document the created HID mouse and its stack | HID mouse enumerates and works without specific hardware |
| 13 | Confirm a self-created HID mouse device — devices/stacks before vs after; correlate new HID mouse with driver; trace caller-controlled movement through it | Driver creates its own HID mouse and uses it for the demonstrated movement |
| 14 | Test stability + lifecycle — bounded repetition, close/reopen handles, kill client, reboot, unload when supported | Repeatable, no crashes or stuck resources in tested scenarios |
| 15 | Reproduce and emit — re-run the minimal PoC on the intended builds; consolidate evidence per criterion | Per-binary, per-environment verdict: `CONFIRMED` / `DOES NOT MEET` / `INCONCLUSIVE` |

Each STEP block in `dynamic.ps1` must:
- Start with `# ===== STEP N — <name> =====` and `Write-Host "== STEP N: <name> =="`.
- Contain only operations needed for that step.
- Record the observed result as a trailing comment (so a later re-read of
  the script also carries the finding).
- Be idempotent where feasible (skip install if already installed, etc.).

### 2.5 Emit the result

`reports/<sha256>/result.md` must contain:

- Identification: sha256, PE `originalfilename`, package provenance, driver version.
- Environment of record: Windows build, Secure Boot, HVCI, VBS status.
- Install / interface actually used: how the devnode was created, which service runs, which symlink or device interface was opened.
- Movement evidence (criterion 5 + 11): a table with caller input and observed cursor delta per direction + an idle control.
- Per-criterion verdict table: 1 through 6, each `MET` / `DOES NOT MEET` / `unknown`, with the basis one-liner.
- Overall: `CONFIRMED` only if all six `MET`. Any `DOES NOT MEET` → `DOES NOT MEET`. Any mix of `MET` and `unknown` → `INCONCLUSIVE`.
- Scope limits: builds not tested, non-elevated access not measured, buttons/wheel/absolute positioning not exercised, etc. — record what was NOT done.

---

## 3. Static invariants

Observations that constrain shortlisting. Apply before costing out a dynamic session.

### 3.1 Hardware-path false negative on class-callback capture

A driver that captures `MouseClassServiceCallback` via
`IOCTL_INTERNAL_MOUSE_CONNECT` and never exposes a user-mode call site to it
is **not** a byte-triage false negative. If every invoker of the captured
callback is hardware-driven (passthrough hook, read-completion routine on a
physical read IRP, gesture handler, timer), criterion 5 fails statically.
The call graph is fully visible. Dynamic execution does not change the
verdict.

### 3.2 "Opens without the device" is possible but inert for the previous profile

Many mouse-class filters create their control device + symlink from
`DriverEntry`, not inside their attach routine. The symlink surfaces in a
VM with no peripheral. Opening it reaches no synthetic-input emitter
because the saved callback pointer (`ext+0x68`) is NULL until
`IOCTL_INTERNAL_MOUSE_CONNECT` fires, which requires the mouse-class stack
attached on top. Open-without-hardware is not a confirmation vector for
that family.

### 3.3 WHQL ≠ exemption

A perfectly legitimate signed driver can still expose arbitrary user-mode
mouse injection. Origin is not a filter. The discriminator is where the
injection is driven from.

### 3.4 Byte-triage underscores

`verdict=none` does not mean no capability. HID-report-path injection
through a mapper (e.g. `mshidkmdf`) leaves no direct `HidRegisterMinidriver`
import and may score `none`. Treat `none` records matching the shortlist
widening in 2.1 as inspection candidates, not rejections.

---

## 4. Report folder contract

```
reports/<sha256>/
    index.jsonl                   # index record for this hash
    <original-name>.sys           # the binary
    <original-name>.c             # full Ghidra decompilation
    dynamic.ps1                   # single incremental dynamic-analysis script
    result.md                     # per-criterion verdict (section 2.5)
    evidence.json                 # optional: hashes, PE props, descriptor bytes
    annotated-assembly.txt        # optional: asm excerpts validating decompile
    hid-items.json                # optional: descriptor item decomposition
    <other evidence files>        # optional: INF, catalog, screenshots, ETW traces
```

Do not create files outside this folder for a given hash. Do not split
`dynamic.ps1`. Do not delete earlier evidence files; mark them as superseded
in `result.md` if needed.

---

## 5. Rules

| # | Rule |
|---|------|
| R1 | A verdict without basis is invalid. State the basis for every `MET` / `DOES NOT MEET`. |
| R2 | `unknown` is a valid verdict. A guess framed as a verdict is a violation of R1. |
| R3 | Byte triage never confirms. It only shortlists. |
| R4 | Dynamic analysis never happens outside a snapshotted VM. The host is out of scope. |
| R5 | Protections are not disabled or weakened in any run that produces a verdict. |
| R6 | Binaries are not patched or re-signed. |
| R7 | `dynamic.ps1` is one file per report, grown by appending STEP blocks. |
| R8 | A `CONFIRMED` overall verdict requires every criterion `MET`. One `DOES NOT MEET` makes the whole target `DOES NOT MEET`. |
| R9 | Record scope limits in `result.md`. Not tested ≠ met. |
| R10 | Before starting work on a hash, check for an existing `reports/<sha256>/result.md`. Skip resolved hashes. |

Violation of any rule invalidates the output for that hash.
