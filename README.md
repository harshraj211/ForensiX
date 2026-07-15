# ForensiX

ForensiX is a planned cross-platform Android rapid evidence triage and forensic preview platform. It runs on an investigator workstation and uses Android Debug Bridge (ADB) to perform capability-gated logical collection from connected Android devices.

This repository is currently in the architecture and implementation-planning phase. No production forensic capability is claimed yet.

## Project status

- Product name: **ForensiX**
- Default operating mode: **Controlled Logical Triage Mode**
- Target stack: React, TypeScript, FastAPI, Python, SQLite, and ADB
- Current deliverable: [Implementation Plan](docs/IMPLEMENTATION_PLAN.md)

## Important limitation

ForensiX will not claim hardware write blocking, physical acquisition, locked-device bypass, unrestricted access to app-private data, or universal deleted-data recovery. Supported operations will depend on the device, Android version, authorization state, encryption, OEM restrictions, and available privileges. Every acquisition action and known side effect must be recorded.
