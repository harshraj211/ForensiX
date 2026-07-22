# Forensic validation

ForensiX now produces a versioned, integrity-sealed validation record for every controlled ADB
validation run. A record is supporting test evidence; it is not a statement that every Android
device, parser, or acquisition is forensically validated and it cannot guarantee admissibility.

## Run the deterministic known-answer scenario

```powershell
.\.venv\Scripts\python.exe .\scripts\run-forensic-validation.py `
  --mode mock `
  --scenario authorized `
  --output .\validation-results\mock-authorized.json
```

The report records the host platform, Python and ADB versions, classified transport counts,
property coverage, package count, root capability, shared-storage readiness, and two-pass inventory
repeatability. Raw device serials, build fingerprints, package names, and inventory paths are not
stored. Stable identifiers and paths are represented only by SHA-256 values.

## Run the Evidence Twin known-answer workflow

The Evidence Twin validation creates an isolated temporary case and a synthetic Android provider
SQLite database. It exercises the actual source import, fixed-size chunk ledger, whole-source and
manifest hashing, independent working copy, signature-based inspection, contacts/SMS/MMS/call-log
parsers, normalized timeline, custody/audit chains, and preliminary report outputs.

```powershell
.\.venv\Scripts\python.exe .\scripts\run-evidence-twin-validation.py `
  --output .\validation-results\evidence-twin-known-answer.json
```

The output is a versioned JSON report with its own canonical SHA-256. It records only hashes,
counts, pass/fail decisions, environment metadata, and limitations. Synthetic names, phone numbers,
and message bodies are deliberately excluded from the validation report.

A passing result proves that this build reproduced the controlled software expectations on the
recorded host. It does not validate real-device acquisition, encrypted databases, alternate Android
schemas, every OEM/application version, certificate trust, or evidentiary admissibility.

## Run against a controlled physical device

Use only a test device for which you have authority—never place the fixture on evidentiary media.
First create the deterministic fixture locally:

```powershell
.\.venv\Scripts\python.exe .\scripts\create-validation-fixture.py `
  --output "$env:TEMP\ForensiX-validation-v1.bin"
```

Manually copy that unchanged file to the controlled phone as
`Download/ForensiX-validation-v1.bin`. Unlock and authorize the test phone, stop applications that
may modify shared storage, then run:

```powershell
.\.venv\Scripts\python.exe .\scripts\run-forensic-validation.py `
  --mode system `
  --adb-path "C:\Android\platform-tools\adb.exe" `
  --serial "SERIAL_FROM_ADB_DEVICES" `
  --validate-known-file `
  --validate-transport-cycle `
  --output .\validation-results\windows-android-device.json
```

The validator can pull only that compiled-in relative path; neither the CLI nor the report accepts
an arbitrary remote path. It acquires the fixture twice into isolated temporary workstation files,
checks the inventory size, local sizes, fixed SHA-256, and repeatability, and removes the temporary
copies when the check ends. A missing fixture makes the validation incomplete and a size/hash
mismatch fails it. A different inventory digest remains a warning because device activity can
legitimately change paths between observations. The ADB executable itself is hashed in system mode.

With `--validate-transport-cycle`, the runner pauses after the initial two known-file acquisitions.
It asks the examiner to disconnect the selected controlled-device transport, observes that the
exact hashed transport identity becomes missing or offline, then asks for reconnection. It requires
the same serial to return authorized within 60 seconds, inventories the same approved root again,
and reacquires and hashes the fixed fixture. The sealed report records only the state transition,
known size/hash result, and redacted identity. Do not run this interactive protocol on evidence
devices or unattended automation.

Omit both validation flags when collecting metadata-only diagnostics. Such a run does not prove
file acquisition or interruption behavior and cannot satisfy the physical acquisition release gate.

## Validation matrix and release gate

For each supported release, retain sealed results for:

| Dimension | Minimum controlled coverage |
| --- | --- |
| Host | Current supported Windows, Linux, and macOS releases |
| Android | Each declared Android/API range and at least two OEM families |
| Access | authorized non-rooted; rooted only for explicitly rooted modules |
| State | no device, unauthorized, offline, disconnect, storage blocked, authorized |
| Workflow | detect, assess, inventory, acquire known files, hash verify, report reproduce |
| Dataset | known names, sizes, timestamps, SHA-256 values, and expected parser outputs |

A production release is blocked until its declared matrix is executed on physical devices, failures
are dispositioned, and the validation records are independently reviewed. CI mock results prevent
software regressions but never satisfy that physical-device gate.

After collecting one sealed system-mode JSON record per controlled matrix run, build the release
gate. Declare every supported Android release explicitly:

```powershell
.\.venv\Scripts\python.exe .\scripts\verify-physical-validation-matrix.py `
  --input .\validation-results\windows-infinix-android12-nonrooted.json `
  --input .\validation-results\windows-test-rooted.json `
  --input .\validation-results\linux-oem2-android14.json `
  --input .\validation-results\macos-oem2-android14.json `
  --require-android-release 12 `
  --require-android-release 14 `
  --minimum-manufacturers 2 `
  --output .\validation-results\physical-matrix.json
```

By default the verifier requires Windows, Linux, and Darwin records, every declared Android
release, two manufacturer families, both rooted and non-rooted coverage, and successful known-file
and disconnect/reconnect checks in every accepted record. It verifies every source seal, rejects
mock records, deduplicates identical reports, lists coverage gaps, and seals the matrix result. A
passing aggregate is still supporting evidence that requires independent review; it is not proof of
hardware write blocking or admissibility.

## Examiner validation report template

Record the release commit and artifact SHA-256, operator, authority, host and device matrix, Android
build/security patch, ADB version and hash, cable/driver, test-dataset manifest hash, observed versus
expected results, repeat count, false positives/negatives, interruptions, limitations, deviations,
reviewer, and disposition. Attach the sealed JSON results without editing them.
