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

Use only a test device for which you have authority. Unlock it, authorize this workstation, stop
applications that may modify shared storage, and run:

```powershell
.\.venv\Scripts\python.exe .\scripts\run-forensic-validation.py `
  --mode system `
  --adb-path "C:\Android\platform-tools\adb.exe" `
  --serial "SERIAL_FROM_ADB_DEVICES" `
  --output .\validation-results\windows-android-device.json
```

This command runs registered metadata operations only. It does not pull file contents. A different
inventory digest is a warning because device activity can legitimately change paths between the two
observations. The ADB executable itself is hashed in system mode.

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

## Examiner validation report template

Record the release commit and artifact SHA-256, operator, authority, host and device matrix, Android
build/security patch, ADB version and hash, cable/driver, test-dataset manifest hash, observed versus
expected results, repeat count, false positives/negatives, interruptions, limitations, deviations,
reviewer, and disposition. Attach the sealed JSON results without editing them.
