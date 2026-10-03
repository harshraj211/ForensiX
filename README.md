# ForensiX

ForensiX is a local Android evidence-triage workstation for authorized examinations. It records collection capability, source hashes, parser versions, custody events, and explicit limitations so an examiner can distinguish available evidence from unsupported or unavailable acquisition paths.

## What it supports

- Logical Android collection through ADB or the companion Agent bundle, subject to the connected device's state and granted permissions.
- Offline examination of Android artifacts, Google Takeout, WhatsApp exports and supported plaintext databases, Microsoft, Telegram and iCloud exports, Samsung Smart Switch archives, legacy Android backups, and FAT32 card images.
- Evidence sealing, verified working copies, normalized artifacts, timeline and correlation review, media metadata/OCR/face-region analysis, and PDF, JSON, CSV, or portable HTML reports.
- Capability-gated workflows for rooted-device paths and externally produced physical-image or recovery results.

See [the technical repository guide](TECHNICAL_REPOSITORY.md) for the architecture and source map. Format-specific scope and boundaries are documented in [cloud export imports](docs/cloud-export-imports.md), [Smart Switch imports](docs/smart-switch-imports.md), and [memory-card imports](docs/memory-card-imports.md).

## Important boundaries

ForensiX does not claim to bypass locks, decrypt protected backups, obtain cloud data, or perform physical acquisition by itself. Those paths require an authorized source, supported device state, appropriate tools, and per-profile validation. The product records unavailable or blocked capabilities rather than representing them as collected evidence.

## Development setup

Requirements: Node.js 22+, pnpm 11+, and Python 3.12+.

```powershell
pnpm install
uv venv
uv pip install -r requirements-dev.txt
```

Start the API in mock ADB mode:

```powershell
$env:FORENSIX_ADB_MODE = "mock"
$env:FORENSIX_MOCK_ADB_SCENARIO = "authorized"
uv run uvicorn forensix_api.main:app --host 127.0.0.1 --port 8765
```

In another terminal, start the web application:

```powershell
pnpm dev
```

For a Windows ADB device test, use the bundled launcher:

```powershell
.\scripts\start-forensix.ps1 -AdbPath "C:\platform-tools\adb.exe"
```

## Integrity and safety model

- Browser clients cannot submit arbitrary ADB shell commands.
- Sources are sealed before examination; parsers operate on verified working copies.
- Transfers are bounded and hash-verified. Archives are validated against traversal, link, size, and compression-ratio hazards.
- Evidence and custody events retain provenance, parser identity, and source limitations for review and reporting.

## Validation

Run the available frontend checks from the repository root:

```powershell
pnpm typecheck
pnpm test
```

Python package-specific tests live beside the API, forensic, and server modules. Use the relevant package environment and test configuration when validating a focused change.

## Local-only files

Release bundles, databases, runtime data, Android/Gradle build products, and locally supplied model weights are intentionally excluded from version control. Configure local model paths through `.env` (see `.env.example`); never add evidence, credentials, or production model artifacts to the repository.
