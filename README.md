# ForensiX

ForensiX is a planned cross-platform Android rapid evidence triage and forensic preview platform. It runs on an investigator workstation and uses Android Debug Bridge (ADB) to perform capability-gated logical collection from connected Android devices.

The implementation has started with the Phase 0 transport-validation and product-security foundation. The current build provides offline local authentication and RBAC, case lifecycle and object-level authorization, case-linked device identity and readiness history, immutable capability-gated acquisition plans, case-owned durable acquisition jobs, and the first bounded content-free shared-storage path inventory. No production forensic capability is claimed yet.

## Project status

- Product name: **ForensiX**
- Default operating mode: **Controlled Logical Triage Mode**
- Target stack: React, TypeScript, FastAPI, Python, SQLite, and ADB
- Architecture: [Implementation Plan](docs/IMPLEMENTATION_PLAN.md)
- Current implementation: [Phase 0 Status](docs/PHASE0_STATUS.md)

## Important limitation

ForensiX will not claim hardware write blocking, physical acquisition, locked-device bypass, unrestricted access to app-private data, or universal deleted-data recovery. Supported operations will depend on the device, Android version, authorization state, encryption, OEM restrictions, and available privileges. Every acquisition action and known side effect must be recorded.

## Implemented now

- React 19, TypeScript 6, Vite, Tailwind CSS, TanStack Query, and accessible route shell
- FastAPI application factory with loopback-safe CORS configuration and request IDs
- SQLite WAL/foreign-key configuration and an initial reversible Alembic migration
- Migration-aware workstation startup that safely adopts recognized legacy development schemas before upgrading
- One-time local administrator bootstrap, Argon2id credentials, opaque hashed sessions, lockout, session rotation/revocation, CSRF validation, and explicit RBAC permissions
- Unique case numbers, creator ownership, memberships, lifecycle transitions, optimistic versions, append-only case events, protected case APIs, and Cases UI
- Case-scoped device detection, hashed device identity, immutable readiness snapshots, closed-case blocking, device history APIs, and case registry UI
- Explicit ADB binary discovery and version validation primitives
- Typed ADB operation catalog with fixed arguments, serial validation, operation timeouts, and no browser-supplied command or path fields
- Shell-free asynchronous ADB execution with timeouts, cancellation cleanup, and output limits
- Device-state parsing for absent, authorized, unauthorized, offline, multiple, recovery, sideload, bootloader, and unknown states
- Immutable capability snapshots from fixed property/package operations and content-free shared-storage root checks with explicit supported, blocked, unknown, and unsupported decisions
- Immutable acquisition plans bound to an exact case, device, operator, and readiness snapshot, with a 30-minute freshness gate
- Metadata-only, quick-triage, shared-storage-inventory, and custom scopes with server-enforced module capability checks
- Canonical SHA-256 plan and readiness-snapshot hashes, recorded limitation acknowledgement, protected planning APIs, and plan-history UI
- Strict portable evidence-storage keys with traversal, link, and reparse-point boundary checks
- Partial-file streaming, atomic sealing, non-overwrite behavior, and streaming SHA-256 verification
- Durable versioned job states with restrictive case/plan ownership, validated transitions, monotonic progress, bounded JSON checkpoints, append-only sequenced events, cooperative cancellation, and restart interruption recovery
- Idempotent acquisition-job preparation, status/event/cancellation APIs, and case UI that clearly labels prepared jobs as not running
- Fixed-policy shared-storage path inventory with live device/fingerprint/root revalidation, a 30-second command timeout, depth 6 and 250-path limits, durable checkpoints, cancellation preservation, and a canonical SHA-256 manifest
- Path-only inventory persistence and UI: relative path, extension, per-path SHA-256, counts, limits, and manifest hash; no Android file bytes, timestamps, sizes, or arbitrary remote paths
- Selected inventory-item acquisition through shell-free `adb pull`, with a 100 MiB ceiling, 120-second timeout, contained random partial file, streaming SHA-256, canonical JSON manifest, restart/failure state, and no caller-supplied remote path
- Durable transfer-attempt ledger with startup reconciliation, retained-partial hashes, integrity-checked cleanup, explicit retain/discard decisions, and byte-zero restart without claiming unsupported ADB byte-range resume
- Immutable metadata-only artifact normalization for sealed files, deterministic extension classification, canonical provenance/limitations, SQLite FTS5 indexing, case-scoped search filters, and a non-rendering evidence explorer
- Append-only evidence re-verification that independently re-hashes both sealed file and manifest, records verified/mismatch/missing/error outcomes, preserves original expected hashes, and exposes verification history in the UI
- Append-only chain-of-custody history with automatic evidence registration/integrity events, manual transfers, correction-by-amendment, per-case SHA-256 chaining, and chain verification
- Global tamper-evident audit chain for custody actions with canonical serialization, genesis hash, sequence/link verification, protected audit APIs, and no claim that local SQLite is tamper-proof
- Deterministic mock ADB scenarios and safe API error envelopes
- Device-readiness UI with forensic limitations and operator guidance
- CI for frontend lint/type/test/build and backend Ruff/mypy/Pytest

## Local setup

Requirements:

- Node.js 24+
- pnpm 11+
- Python 3.12+
- Android Platform Tools only when testing a real device

Install the frontend:

```powershell
pnpm install
```

Create the Python environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Run the local API with the safe mock device:

```powershell
$env:FORENSIX_ADB_MODE = "mock"
$env:FORENSIX_MOCK_ADB_SCENARIO = "authorized"
.\.venv\Scripts\python.exe -m uvicorn forensix_api.main:app --host 127.0.0.1 --port 8765
```

In a second terminal, run the web application:

```powershell
pnpm dev
```

Open `http://127.0.0.1:5173/devices`.

Mock scenarios are `no_devices`, `authorized`, `unauthorized`, `offline`, `multiple`, `storage_blocked`, and `timeout`. To use a real ADB executable, set `FORENSIX_ADB_MODE=system` and optionally set `FORENSIX_ADB_PATH` to the full executable path.

## Validation commands

```powershell
pnpm lint
pnpm typecheck
pnpm test
pnpm build
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\mypy.exe forensic/src server/src apps/api/src tests
.\.venv\Scripts\pytest.exe
```

## Current security boundary

The Phase 0 API implements local authentication, case-level authorization, and session/CSRF/permission checks, but the service must remain bound to `127.0.0.1`. It exposes no arbitrary ADB shell operation and accepts no command text or remote path from the browser. A confirmed Quick Triage job can enumerate relative paths under one approved shared-storage root. An operator can then acquire one of those persisted inventory items; the browser submits only the opaque item ID. The backend revalidates device identity and root access, reconstructs the policy-approved path, uses shell-free `adb pull`, limits the transfer to 100 MiB, seals it into contained append-oriented storage, and writes file and manifest SHA-256 values. Interrupted bytes are reconciled and hashed but remain quarantined from evidence indexing until an operator records a retain or verified-discard decision; restart begins again at byte zero. Completed files are normalized into immutable metadata records and a case-scoped FTS5 index without opening evidence content. MIME labels are extension-derived and the current explorer renders metadata only. Later integrity checks independently re-hash both sealed objects and append a result without replacing expected hashes. Evidence registration, integrity outcomes, transfers, amendments, and recovery decisions are hash-chained in custody/audit history. These chains are tamper-evident, not immutable or tamper-proof, because the database and application remain on one workstation. The acquisition path has deterministic mock/known-answer coverage but has not been validated on a physical device in this environment because ADB is unavailable. It does not access app-private storage or prove completeness. Use only controlled test devices until formal forensic validation is complete.
