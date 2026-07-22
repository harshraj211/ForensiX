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
- Process-isolated JPEG/PNG/GIF/WebP signature validation and bounded thumbnail generation that re-verifies the sealed source, re-encodes a metadata-stripped PNG derivative, records extension mismatch/limits/version/hash, and never serves original evidence content
- Bounded Android stat metadata that preserves original modification epochs, normalized UTC values, source/confidence/precision, and inventory-versus-acquired size consistency without claiming creation/access times
- Deterministic timeline materialization for explicit acquisition collection timestamps, with source-artifact links, UTC basis, confidence, stable hashes, idempotent backfill, and no invented device-side times
- Analyst bookmarks, normalized case tags, and append-only notes with correction-by-supersession, separate from immutable evidence and recorded in the tamper-evident audit chain
- Append-only evidence re-verification that independently re-hashes both sealed file and manifest, records verified/mismatch/missing/error outcomes, preserves original expected hashes, and exposes verification history in the UI
- Append-only chain-of-custody history with automatic evidence registration/integrity events, manual transfers, correction-by-amendment, per-case SHA-256 chaining, and chain verification
- Global tamper-evident audit chain for custody actions with canonical serialization, genesis hash, sequence/link verification, protected audit APIs, and no claim that local SQLite is tamper-proof
- Sealed custody/audit checkpoint JSON exports that verify the current custody chain and audit chain, hash the package before download, and label the result as not externally anchored
- Append-only external-anchor receipts for checkpoint hashes, with provider/reference metadata, optional receipt SHA-256, canonical anchor hashing, protected APIs, and case UI; ForensiX records the receipt but does not perform the external anchoring
- Detached RSA/ECDSA checkpoint-signature verification against supplied X.509 certificates, including certificate validity/key-usage checks, sealed-checkpoint re-hashing, immutable verification fingerprints, audit events, and case UI; certificate-chain trust and revocation validation remain external responsibilities
- Deterministic mock ADB scenarios and safe API error envelopes
- Sealed end-to-end Evidence Twin known-answer validation covering import/chunk/manifest hashes, verified working copies, SQLite detection, contacts/SMS/MMS/calls, normalized timeline, custody/audit chains, and report-output integrity without retaining fixture PII
- Device-readiness UI with forensic limitations and operator guidance
- Experimental, metadata-only SQLite/WAL/rollback-journal recovery-readiness assessment on verified Evidence Twin copies, with sealed results and no claim that candidate pages are deleted or recovered records
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

On Windows, after installing dependencies, the launcher can start both services in real-device
mode, validate the configured ADB executable, and open the device-readiness screen:

```powershell
.\scripts\start-forensix.ps1 -AdbPath "C:\platform-tools\adb.exe"
```

Use `-NoBrowser` for a terminal-only readiness check. Existing listeners on the configured API or
web ports are reused instead of starting duplicate services.

Run `.\scripts\Test-ForensiX.ps1 -AdbPath "C:\path\to\adb.exe"` for a non-acquisition
workstation check. Linux/macOS users can start with `FORENSIX_ADB_PATH=/path/to/adb
./scripts/start-forensix.sh`. See [workstation setup](docs/WORKSTATION_SETUP.md) for driver, udev,
Gatekeeper, status, and log guidance.

Encrypted workstation backups can be created, independently verified, and safely restored with
`scripts/forensix-backup.py`; see [backup and recovery](docs/BACKUP_RECOVERY.md). Live evidence
storage still relies on BitLocker, FileVault, or LUKS until an OS-keychain and agency-escrow design
is formally validated.

Create a privacy-preserving, integrity-sealed mock or controlled-device validation record with
`scripts/run-forensic-validation.py`; see [forensic validation](docs/FORENSIC_VALIDATION.md). The
physical runner supports a fixed-path, two-pass known-file acquisition and SHA-256 check without
allowing caller-supplied device paths, plus an examiner-driven disconnect/reconnect check. The
matrix verifier rejects mock or tampered records and requires declared host, Android, OEM, rooted,
and non-rooted coverage. A passing mock run is regression evidence and does not replace the
physical-device release matrix.

The requirement-by-requirement implementation evidence and remaining external proof are recorded in
[the Evidence Twin completion audit](docs/EVIDENCE_TWIN_COMPLETION_AUDIT.md).

Verified SQLite databases and safe ZIP/TAR working copies can be checked for recovery candidates
from the Evidence Twin screen. This experimental probe reads bounded metadata only; it does not
carve deleted rows or prove deletion. See [deleted-data research](docs/DELETED_DATA_RESEARCH.md).

Supervisors and administrators can export sealed custody/audit checkpoint packages from a case
after chain verification succeeds. The package hash must be preserved, signed, or published through
an agency-controlled process before it becomes externally anchored. After that external action,
the case screen can record its provider, reference, time, and optional receipt SHA-256 as an
append-only anchor receipt. It can also verify a detached RSA/ECDSA signature against a supplied
public X.509 certificate without accepting private keys. See
[custody checkpoints](docs/CUSTODY_CHECKPOINTS.md).

Unsigned portable workstation bundles, CycloneDX SBOMs, SHA-256 manifests, and GitHub build
attestations are defined in [release packaging](docs/RELEASE_PACKAGING.md). Native code signing,
notarization, and a production installer remain explicit release gates.

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

The Phase 0 API implements local authentication, case-level authorization, and session/CSRF/permission checks, but the service must remain bound to `127.0.0.1`. It exposes no arbitrary ADB shell operation and accepts no command text or remote path from the browser. A confirmed Quick Triage job can enumerate relative paths under one approved shared-storage root. An operator can then acquire one of those persisted inventory items; the browser submits only the opaque item ID. The backend revalidates device identity and root access, reconstructs the policy-approved path, uses shell-free `adb pull`, limits the transfer to 100 MiB, seals it into contained append-oriented storage, and writes file and manifest SHA-256 values. Interrupted bytes are reconciled and hashed but remain quarantined from evidence indexing until an operator records a retain or verified-discard decision; restart begins again at byte zero. Completed files are normalized into immutable metadata records and a case-scoped FTS5 index without opening evidence content. Artifact MIME labels remain extension-derived. On explicit request, a separate worker checks bounded magic bytes and may decode only JPEG, PNG, GIF, or WebP under time, byte, and pixel limits; the browser receives only an independently hashed, metadata-stripped PNG derivative. SVG, PDF, archive, Office, executable, audio, video, rejected, and failed inputs are never rendered. This is process isolation and resource bounding, not a claim of an absolute Windows OS sandbox. Later integrity checks independently re-hash both sealed objects and append a result without replacing expected hashes. Evidence registration, integrity outcomes, transfers, amendments, preview outcomes, recovery decisions, and custody checkpoint downloads are hash-chained in custody/audit history. Checkpoint packages can be exported only after chain verification and are hash-sealed before download, but they remain not externally anchored unless preserved, signed, or published outside the workstation. These chains are tamper-evident, not immutable or tamper-proof, because the database and application remain on one workstation. The acquisition path has deterministic mock/known-answer coverage but has not been validated on a physical device in this environment because ADB is unavailable. It does not access app-private storage or prove completeness. Use only controlled test devices until formal forensic validation is complete.
