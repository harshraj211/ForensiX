# ForensiX Repository Guide

## 1. Project summary

ForensiX is a local, cross-platform Android evidence-triage workstation. It combines a React user interface, a FastAPI application, domain-oriented Python services, controlled Android Debug Bridge operations, SQLite metadata persistence, and contained file storage.

The primary workflow is:

1. Authenticate a local investigator.
2. Create or open a case.
3. Detect an authorized Android device through ADB.
4. Assess device, provider, storage, root, and encryption capabilities.
5. Create an immutable, capability-bound acquisition plan.
6. Inventory and selectively collect approved evidence.
7. Hash, seal, index, preview, parse, analyze, and verify evidence.
8. Curate key findings and construct an investigation storyboard.
9. Generate reports and append custody and audit records.

ForensiX is designed as a single-investigator workstation. Its ordinary deployment runs the UI and API locally over loopback HTTP. It is not designed to be exposed directly as an internet-facing service.

## 2. Repository layout

| Path | Responsibility |
| --- | --- |
| `apps/web` | React and TypeScript investigator interface |
| `apps/api` | FastAPI transport layer and desktop launcher |
| `server` | Domain services, persistence, reporting, custody, and acquisition workflows |
| `forensic` | ADB policy/client, forensic parsers, storage primitives, workers, and external integrations |
| `server/alembic` | SQLite schema migrations |
| `packaging` | PyInstaller desktop bundle definition |
| `scripts` | Startup, diagnostics, validation, backup, installation, and release utilities |
| `tests` | Cross-package smoke tests |
| `.github/workflows` | Continuous integration and release automation |
| `README.md` | Product-facing usage and capability documentation |
| `TECHNICAL_REPOSITORY.md` | Existing technical handover documentation |
| `info.md` | Current consolidated repository guide |

Generated directories such as `node_modules`, `dist`, `build`, `.venv`, runtime `data`, and release archives are not source modules.

## 3. System architecture

```text
Investigator
    |
    v
React / TypeScript SPA
apps/web/src
    |
    | same-origin or proxied /api requests
    v
FastAPI transport and composition layer
apps/api/src/forensix_api
    |
    +--> Authentication, cases, jobs, evidence, reports
    |    server/src/forensix_server
    |
    +--> ADB, parsers, storage, external tools
    |    forensic/src/forensix_forensic
    |
    +--> SQLite metadata database
    |    <data_dir>/forensix.db
    |
    +--> Contained evidence and generated outputs
         <data_dir>/evidence
```

The intended dependency direction is:

```text
web -> HTTP API -> server services -> forensic primitives/adapters
```

Most backend components run in one local Python process. The packaged desktop application also serves the compiled SPA from that process and opens it through pywebview.

## 4. Technology stack

### Frontend

- React 19
- React DOM
- TypeScript 6
- Vite 8
- React Router 7
- TanStack Query 5
- Tailwind CSS 4
- Lucide React
- Vitest
- Testing Library
- jsdom
- ESLint 9 with type-aware TypeScript rules

### API and backend

- Python 3.12
- FastAPI
- Uvicorn
- Pydantic and Pydantic Settings
- SQLAlchemy 2
- Alembic
- SQLite
- Argon2 password hashing
- Cryptography
- ReportLab
- Groq SDK for the optional AI narrative feature

### Forensic processing

- Android Debug Bridge
- Pillow
- defusedxml
- Androguard
- Optional scrcpy integration
- Optional ALEAPP integration
- Optional TestDisk/PhotoRec integration
- Native Android SQLite and document parsers
- Isolated image-preview and media-analysis workers

### Build, quality, and release tooling

- pnpm 11
- Node.js 24 in `.nvmrc` and CI
- Pytest and pytest-asyncio
- Ruff
- strict mypy
- PyInstaller
- CycloneDX SBOM tooling
- GitHub Actions
- Optional Windows Authenticode signing

## 5. Workspace and package structure

The root `package.json` delegates frontend commands to `@forensix/web`:

```text
pnpm dev
pnpm build
pnpm lint
pnpm typecheck
pnpm test
```

`pnpm-workspace.yaml` includes `apps/web` and reserves `packages/*`. No active shared JavaScript package tree currently exists under `packages`.

The Python implementation is split into three independently installable setuptools packages:

- `forensic/pyproject.toml`
- `server/pyproject.toml`
- `apps/api/pyproject.toml`

Development installs all three packages in editable mode through `requirements-dev.txt`. Release tooling uses `requirements-release.txt`.

The root `pyproject.toml` defines shared Pytest, Ruff, and mypy behavior. Python test discovery spans `tests`, `forensic/tests`, `server/tests`, and `apps/api/tests`.

## 6. Frontend application

### Entry and state management

`apps/web/src/main.tsx` creates the React root and installs:

- `StrictMode`
- `QueryClientProvider`
- `BrowserRouter`
- the root `App` component

The frontend divides state into:

- React Router for page and case context;
- TanStack Query for remote state and cache invalidation;
- local React state for forms, filters, selections, and dialogs;
- URL search parameters for evidence filters;
- a small context for the persistent live-screen dock;
- cookies and an in-memory CSRF token for authentication state.

There is no Redux-style global state store.

### Main routes

`apps/web/src/App.tsx` defines the primary routes:

| Route | Function |
| --- | --- |
| `/` | Public landing page |
| `/devices` | Device detection and readiness |
| `/cases` | Case list and creation |
| `/cases/:caseId` | Case details and custody |
| `/cases/:caseId/command-center` | Investigation summary and next actions |
| `/cases/:caseId/devices` | Case-linked device workflow |
| `/cases/:caseId/acquisitions` | Planning, inventory, jobs, and transfer |
| `/cases/:caseId/evidence` | Acquired evidence explorer |
| `/cases/:caseId/artifacts` | Parsed artifact browser |
| `/cases/:caseId/artifact-search` | Cross-source artifact search |
| `/cases/:caseId/media-map` | Geolocated media visualization |
| `/cases/:caseId/key-evidence` | Curated findings |
| `/cases/:caseId/storyboard` | Investigation narrative structure |
| `/cases/:caseId/evidence-twin` | Imported and offline evidence examination |
| `/cases/:caseId/timeline` | Deterministic timeline |
| `/cases/:caseId/correlations` | Entity and evidence graph |
| `/cases/:caseId/reports` | Report generation and review |
| `/audit` | Global audit history |
| `/validation` | Known-answer validation dashboard |

`AuthBoundary` protects workstation routes, while `AppShell` supplies navigation, account controls, and the live-screen provider.

### API client

`apps/web/src/lib/api.ts` is the central frontend transport contract. It:

- defines TypeScript models for API resources;
- uses relative `/api/v1` URLs;
- sends same-origin cookies;
- adds `X-CSRF-Token` to mutating requests;
- normalizes structured API errors;
- supports multipart uploads;
- exhausts paginated inventory and artifact endpoints where necessary.

`apps/web/src/lib/downloads.ts` supports two download modes:

- ordinary browser downloads;
- streamed pywebview downloads through a native save dialog.

### Important feature modules

- Authentication: `apps/web/src/features/auth`
- Cases and command center: `apps/web/src/features/cases`
- Devices, root probes, screenshots, and live screen: `apps/web/src/features/devices`
- Acquisition planning and inventory: `apps/web/src/features/acquisitions`
- Acquired evidence and investigation analysis: `apps/web/src/features/evidence`
- Parsed artifact browser: `apps/web/src/features/artifacts`
- Evidence Twin: `apps/web/src/features/evidence-twin`
- Reports: `apps/web/src/features/reports`
- Audit: `apps/web/src/features/audit`
- Validation: `apps/web/src/features/validation`

AI narrative, APK analysis, and Takeout-import panels exist under the evidence feature tree, but they are not currently mounted as main application routes.

## 7. FastAPI application

### Composition root

`apps/api/src/forensix_api/main.py` creates the FastAPI application. It configures:

- settings and database services;
- authentication services;
- request-ID middleware;
- controlled CORS;
- security and domain error handlers;
- all API routers;
- the ADB client dependency.

Application startup performs:

1. database initialization or Alembic migration;
2. default RBAC role creation;
3. durable job restart recovery;
4. acquisition partial reconciliation;
5. artifact normalization backfill;
6. timeline backfill.

### Authentication boundary

`apps/api/src/forensix_api/dependencies.py`:

- reads the opaque `forensix_session` cookie;
- validates the readable CSRF cookie against `X-CSRF-Token`;
- resolves permissions and the current principal;
- creates the system ADB client through a validated resolver and subprocess runner.

### Router families

| Router | Responsibility |
| --- | --- |
| `health.py` | Liveness and readiness |
| `auth.py` | Bootstrap, login, current user, session rotation, logout |
| `cases.py` | Cases, membership, lifecycle, events, devices, plans, command center |
| `devices.py` | Detection, assessment, providers, screenshots, live screen, scrcpy |
| `acquisitions.py` | Jobs, inventory, transfer, partial recovery, verification |
| `artifacts.py` | Search, content, previews, bookmarks, tags, notes |
| `evidence_sources.py` | Evidence Twin lifecycle, parsers, inspection, and recovery |
| `rooted.py` | Root probes, rooted bundles, temporary-root and physical workflows |
| `reports.py` | Report generation, review, and downloads |
| `custody.py` | Custody, checkpoints, anchors, signatures, audit exports |
| `timeline.py` | Case timeline |
| `correlation.py` | Evidence and entity graph |
| `key_evidence.py` | Curated findings |
| `storyboard.py` | Investigation storyboard |
| `media_analysis.py` | Metadata, OCR/classification, and similarity |
| `validation.py` | Known-answer validation |
| `integrations.py` | External integration diagnostics |
| `exports.py` | CASE/UCO-style export |
| `ai.py` | Optional Groq-backed narrative |
| `apk.py` | Uploaded APK analysis |
| `takeout.py` | Google Takeout import |
| `extraction.py` | Experimental downgrade/rooted extraction and carving endpoints |

FastAPI exposes generated API documentation at `/docs`, `/redoc`, and `/openapi.json` while the local API is running.

## 8. Desktop runtime

`apps/api/src/forensix_api/desktop.py` is the packaged desktop entry point. It:

1. selects an available loopback port;
2. chooses an operating-system-specific data directory;
3. creates production settings;
4. serves the compiled SPA from `apps/web/dist`;
5. falls back to `index.html` for client routes;
6. starts Uvicorn;
7. opens pywebview by default;
8. supports `--browser` and `--no-browser`;
9. exposes an atomic native download bridge;
10. stops the API when the native window closes.

Default data locations are:

- Windows: `%LOCALAPPDATA%\ForensiX`
- macOS: `~/Library/Application Support/ForensiX`
- Linux: `$XDG_DATA_HOME/forensix` or `~/.local/share/forensix`

## 9. Server domain services

`server/src/forensix_server` contains the application and domain layer.

| Area | Responsibility |
| --- | --- |
| `auth` | Bootstrap, Argon2 credentials, sessions, lockout, CSRF, RBAC |
| `cases` | Case lifecycle, ownership, membership, events, optimistic versions |
| `case_devices` | Device identity and immutable readiness assessments |
| `jobs` | Durable state machine, progress, events, cancellation, recovery |
| `acquisitions` | Plans, inventory, selected transfers, partial handling, verification |
| `evidence` | Artifact indexing, content, previews, timeline, correlation, annotations |
| `evidence_twin` | Sealed sources, chunks, working copies, parsers, inspection, recovery |
| `rooted` | Root proof, rooted bundles, temporary-root and physical acquisition |
| `screen_recordings` | scrcpy session tracking and MP4 evidence sealing |
| `media` | Bounded media analysis and perceptual similarity |
| `investigation` | Command center, storyboard, optional AI narrative |
| `reporting` | Frozen snapshots and PDF/JSON/CSV renderers |
| `custody.py` | Per-case custody and global audit chains |
| `custody_exports` | Checkpoints, anchors, signatures, CASE/UCO export |
| `validation` | Known-answer Evidence Twin validation |
| `backup.py` | Encrypted offline backup, verification, and restore |
| `release.py` | Portable bundle sealing and verification |
| `vault` | Supplementary Fernet-based file manager |

The Fernet vault is not the active evidence-storage implementation. The primary pipeline uses `EvidenceStore` under the configured evidence directory.

## 10. Forensic layer

### ADB subsystem

`forensic/src/forensix_forensic/adb` contains:

- executable discovery and validation;
- a typed operation catalog;
- shell-free asynchronous subprocess execution;
- bounded text and binary output handling;
- Android transport and provider parsing;
- high-level device operations;
- diagnostics and controlled validation fixtures.

The central policy is `adb/policy.py`. It limits operations, arguments, roots, paths, records, output sizes, and deadlines. Shared-storage acquisition is restricted to approved Android roots, and selected transfers are resolved from persisted inventory items rather than browser-supplied remote paths.

### Capability assessment

`forensic/src/forensix_forensic/capabilities` determines:

- authorization and transport state;
- Android properties and packages;
- battery state;
- accessible shared-storage roots;
- contacts, SMS, and call-log provider status;
- encryption and credential-storage state;
- chipset and root requirements;
- ordinary, temporary-root, and locked-device readiness.

Capabilities are classified as supported, blocked, unknown, unsupported, or research-only. Empty executable profile registries prevent temporary-root and locked-device research descriptions from becoming active product claims.

### Evidence I/O and parsers

`forensic/src/forensix_forensic/evidence_io` supplies:

- bounded ZIP and TAR extraction;
- read-only SQLite access with an authorizer and operation budget;
- parser contracts and closed registries;
- SQLite/WAL/journal recovery assessment.

`forensic/src/forensix_forensic/android_artifacts` contains parsers for:

- contacts;
- SMS, MMS, and call logs;
- WhatsApp and Telegram plaintext stores;
- Meta application interchange data;
- Snapchat, Discord, TikTok, and Gmail summaries;
- calendars and downloads;
- browser history;
- notifications and notes;
- location and Maps activity;
- usage statistics;
- bounded Wi-Fi and Bluetooth configuration documents.

Parsers declare identifiers, versions, required tables, path hints, acquisition level, categories, and maturity.

### Isolated processing

`preview_worker.py` and `media_analysis_worker.py` process bounded media in subprocesses. They perform signature checks, image-size controls, metadata extraction, derivative generation, perceptual hashing, optional OCR, and deterministic classification.

### External tools

- `integrations/scrcpy.py`: mirror, control, and recording
- `integrations/aleapp.py`: hash-pinned ALEAPP execution
- `integrations/photorec.py`: hash-pinned, bounded PhotoRec recovery
- `apk_analysis/analyzer.py`: Androguard-based APK inspection

Optional tools do not prevent core startup when absent.

## 11. Persistence model

### SQLite

`server/src/forensix_server/db/database.py` configures SQLite with:

- foreign keys enabled;
- WAL journaling;
- `synchronous=FULL`;
- a busy timeout;
- transaction-scoped SQLAlchemy sessions.

Production startup applies Alembic migrations from `server/alembic/versions`. The current migration history spans `0001` through `0041`.

### Main schema groups

| Group | Representative records |
| --- | --- |
| Platform/jobs | system events, jobs, sequenced job events |
| Authentication | users, roles, assignments, sessions, auth events |
| Cases | cases, members, case events |
| Devices | detections, capability runs, linked devices, assessments |
| Root/physical | root probes, block probes, recording sessions |
| Acquisition | plans, inventories, items, acquired files, partials |
| Evidence | artifacts, previews, verifications, timelines, annotations |
| Evidence Twin | sources, chunks, copies, inspections, parser and recovery runs |
| Reports | report snapshots, reviews, outputs |
| Custody/audit | custody events, checkpoints, anchors, signatures, audit logs |
| Media | media analyses and screen recordings |

Evidence bytes are stored as contained files and referenced by opaque storage keys. They are not stored as database BLOBs.

## 12. Core workflows

### Authentication

```text
Bootstrap or login
  -> Argon2 credential verification
  -> opaque server-side session
  -> HTTP-only session cookie
  -> CSRF cookie and request header
  -> RBAC and case-membership checks
```

### Device readiness

```text
Detect ADB transports
  -> select authorized device
  -> read fixed properties/packages/provider probes
  -> classify capabilities
  -> persist immutable case-device assessment
  -> expose only supported operations
```

### Logical shared-storage acquisition

```text
Fresh readiness assessment
  -> immutable acquisition plan
  -> durable job
  -> live device identity/root revalidation
  -> bounded metadata-only inventory
  -> persisted inventory item IDs
  -> explicit file selection
  -> shell-free adb pull into tracked partial
  -> SHA-256 and manifest
  -> atomic seal
  -> artifact indexing, timeline, custody, and audit
```

Interrupted transfers are reconciled and retained as partials. They require an explicit disposition, and retries start from byte zero rather than claiming unsupported ADB range resumption.

### Provider and rooted collection

Provider operations first perform content-free probes, then use fixed projections and bounded records. Selected provider material can be sealed as logical evidence.

Rooted operations require a fresh UID 0 proof, a matching case/device relationship, fixed collection profiles, and explicit side-effect acknowledgements. Rooted TAR streams are sealed through Evidence Twin.

### Evidence Twin

```text
Import or acquisition stream
  -> fixed-size chunks
  -> sealed master
  -> chunk ledger and manifest
  -> SHA-256 verification
  -> separate verified working copy
  -> signature inspection
  -> safe parser or bounded recovery tool
  -> normalized derived artifacts
  -> timeline, correlation, custody, and reporting
```

Sealed masters are preserved separately from examination copies. Imported sources remain origin-unverified even when their stored bytes and hashes verify correctly.

### Preview and media analysis

```text
Sealed evidence
  -> source hash verification
  -> isolated bounded worker
  -> signature/decode checks
  -> metadata-stripped preview or analysis result
  -> derivative/result hash and provenance
```

### Investigation analysis

The analysis layer provides:

- FTS5-backed metadata and artifact search;
- deterministic timeline events with explicit timestamp source and confidence;
- an evidence/entity correlation graph based on explicit extracted values;
- bookmarks, tags, and append-only notes;
- investigator-selected key evidence;
- deterministic storyboard chapters, gaps, and source hashes.

The system does not automatically infer identity or claim speculative investigative conclusions.

### Reporting and custody

```text
Case state and evidence
  -> frozen report snapshot
  -> selected redaction profile
  -> deterministic PDF/JSON/CSV output
  -> sealed hashes
  -> review record
  -> custody and audit events
```

Custody records form a per-case SHA-256 chain. Audit records form a workstation-global SHA-256 chain. Checkpoints can be exported, externally anchored, and verified against detached RSA/ECDSA signatures. These controls are tamper-evident, not tamper-proof.

### Backup

`server/backup.py` and `scripts/forensix-backup.py`:

- create a consistent SQLite backup;
- archive database and evidence files;
- record per-file hashes;
- encrypt with AES-256-GCM;
- derive keys with scrypt;
- verify backups independently;
- restore through a validated staging directory.

## 13. Development workflow

### Requirements

- Python 3.12
- Node.js 24 recommended and used by CI
- pnpm 11
- Android Platform-Tools for physical-device work

### Install

```bash
pnpm install
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

Windows uses `.venv\Scripts\python.exe` instead of `.venv/bin/python`.

### Start in source mode

Terminal 1:

```bash
.venv/bin/python -m uvicorn forensix_api.main:app --host 127.0.0.1 --port 8765
```

Terminal 2:

```bash
pnpm dev
```

Vite runs at `127.0.0.1:5173` and proxies `/api` to the local API at port `8765`.

Platform launchers:

- Windows: `scripts/start-forensix.ps1`
- Linux/macOS: `scripts/start-forensix.sh`
- Windows diagnostics: `scripts/Test-ForensiX.ps1`

The current implementation accepts system ADB mode; documentation referring to a complete runtime mock-ADB mode must be reconciled with the current source before relying on it.

## 14. Testing and quality checks

### Frontend

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Frontend tests include utility tests and a broad mocked application workflow suite in `apps/web/src/App.test.tsx`.

### Python

```bash
ruff check .
ruff format --check .
mypy forensic/src server/src apps/api/src
pytest
```

Backend tests cover:

- authentication and cases;
- migrations and database durability;
- job and acquisition state machines;
- ADB policy, parsing, execution, and limits;
- storage containment;
- safe archive and SQLite processing;
- parsers and external integrations;
- Evidence Twin and recovery;
- reports, custody, backup, and release sealing;
- media and screen recordings;
- investigation products.

### Validation utilities

- `scripts/run-evidence-twin-validation.py`
- `scripts/run-forensic-validation.py`
- `scripts/create-validation-fixture.py`
- `scripts/verify-physical-validation-matrix.py`

Mock or synthetic known-answer validation is regression evidence. It does not replace a controlled physical-device validation matrix.

## 15. CI and release workflow

### Continuous integration

`.github/workflows/ci.yml` runs frontend and backend jobs.

Frontend checks:

1. frozen pnpm install;
2. ESLint;
3. TypeScript checking;
4. Vitest;
5. production build.

Backend checks:

1. install development dependencies;
2. Ruff lint;
3. Ruff format check;
4. strict mypy;
5. Pytest.

### Portable release

`packaging/forensix.spec` bundles:

- the desktop/API entry point;
- all Python packages;
- the compiled React application;
- Alembic migrations and configuration;
- ReportLab data;
- pywebview support;
- optional Windows scrcpy files.

`scripts/build-release.py`:

1. validates version and repository state;
2. builds the frontend;
3. runs PyInstaller;
4. materializes bundle symlinks where required;
5. optionally signs Windows binaries;
6. generates a CycloneDX SBOM;
7. produces a release manifest and checksums;
8. creates a deterministic portable ZIP.

`.github/workflows/release.yml` builds Windows, Linux, and macOS archives, creates attestations, uploads artifacts, and publishes normalized assets for version tags.

## 16. Security and forensic design strengths

- Local loopback deployment by default.
- Clear UI, API, domain, and forensic module boundaries.
- Argon2 credentials, opaque hashed sessions, CSRF, RBAC, and case membership.
- Mostly closed, typed, bounded ADB operations.
- Shell-free host subprocess invocation.
- Browser selection through opaque inventory IDs instead of remote paths.
- Strict evidence storage-key validation and root containment.
- Link, reparse-point, traversal, and overwrite defenses.
- Streaming SHA-256 and atomic evidence sealing.
- Separate sealed masters and verified working copies.
- Bounded archive extraction and read-only SQLite access.
- Versioned parser registries and explicit provenance.
- Isolated and bounded preview/media workers.
- Hash-pinned optional external executables.
- Immutable verification history and amendment-based corrections.
- Per-case custody and global audit hash chains.
- Frozen, hashed report snapshots and outputs.
- Conservative capability and recovery claims.
- Broad domain and forensic-boundary tests.
- SBOM, manifest, checksum, attestation, and optional signing support.

## 17. Priority issues and recommended fixes

### Release blockers

1. **Isolate or disable `apps/api/src/forensix_api/routers/extraction.py` until it follows the main evidence pipeline.**
   - It accepts request-supplied case/operator values and local paths.
   - It does not consistently validate case-linked device identity.
   - Results are returned from temporary directories rather than sealed storage.
   - Custody, audit, durable jobs, and cleanup are incomplete.
   - Signal and Telegram database transfer uses a text-oriented root command path that can corrupt binary data.

2. **Replace free-form `root_exec()` command strings with structured operations.**
   Prefix validation is weaker than the rest of the closed ADB policy and should not be relied on to reject shell metacharacters.

3. **Replace unsafe downgrade archive handling.**
   The WhatsApp workflow uses unbounded decompression and direct TAR extraction. It should use `SafeArchiveExtractor`, strict limits, staging cleanup, and the standard evidence-sealing path.

4. **Make release packaging depend on all quality gates.**
   Tagged releases should require lint, type checking, tests, physical-validation requirements where applicable, archive verification, and a packaged-executable health smoke test.

5. **Treat the Groq narrative as an explicit external-disclosure boundary.**
   It should be disabled by default or require clear authorization, redaction controls, disclosure text, and audit records before sending case data off the workstation.

### High-priority engineering work

- Add route-level tests for authentication, CSRF, RBAC, case isolation, downloads, acquisition, and custody.
- Add browser E2E tests against a real loopback API and a controlled ADB fixture.
- Add measurable Python and frontend coverage thresholds.
- Add Windows and macOS runtime tests for filesystem, WebView, and packaging behavior.
- Produce hash-locked Python dependency manifests.
- Verify downloaded external-tool archives against maintainer-provided signatures or predeclared hashes before execution.
- Publish SBOMs directly with GitHub Release assets.
- Add CodeQL, dependency, secret, and license scanning.
- Either remove the unused Fernet vault or formally integrate and validate it.
- Ensure all temporary extraction directories are cleaned and all successful outputs enter durable evidence storage.

### Documentation and governance

- Reconcile package version `1.0.0` with documentation references to `1.0.1`.
- Align the root Node engine with Node 24 used by `.nvmrc`, documentation, and CI.
- Correct outdated inventory limits in the README.
- Reconcile mock-ADB documentation with the current system-only implementation.
- Reconcile statements that downgrade extraction is not implemented with the registered experimental endpoints.
- Fix links to missing workstation setup and release packaging documents.
- Add `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, a release checklist, and recovery runbooks.
- Clarify whether remote HTTPS deployment is supported or merely planned.

## 18. Architectural assessment

The strongest parts of ForensiX are its primary logical-acquisition and Evidence Twin pipelines. They are bounded, provenance-heavy, conservative about claims, and designed around immutable metadata, streaming hashes, controlled device operations, separate examination copies, and explicit custody records.

The main architectural inconsistency is the standalone extraction subsystem. It bypasses several controls already implemented elsewhere and should be brought under the same case authorization, device binding, binary-safe transport, durable job, storage, cleanup, verification, custody, and audit architecture before being treated as a production feature.

The next engineering priorities should be:

1. secure or disable experimental extraction and free-form root execution;
2. enforce complete release gates and packaged-artifact verification;
3. add API integration and browser E2E coverage;
4. strengthen dependency and external-tool supply-chain controls;
5. remove documentation drift and add governance/runbook material.

## 19. Authoritative files

When this guide and descriptive documentation disagree with implementation, use these sources in order:

1. current source code and tests;
2. generated FastAPI OpenAPI schema;
3. package manifests and lockfiles;
4. Alembic migrations and SQLAlchemy models;
5. CI and release workflows;
6. `info.md`, `TECHNICAL_REPOSITORY.md`, and `README.md`.

This order prevents stale documentation from overriding executable behavior or security boundaries.
