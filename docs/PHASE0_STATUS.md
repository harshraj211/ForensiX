# Phase 0 Implementation Status

**Updated:** 16 July 2026
**Branch:** `agent/phase0-foundation`

## Completed slices

| Slice | Output | Verification |
|---|---|---|
| Monorepo foundation | pnpm web workspace, three Python packages, strict TypeScript/Ruff/mypy/Pytest, CI | clean install; frontend and backend checks pass |
| Controlled ADB foundation | resolver, immutable models, parsers, shell-free bounded runner, system/mock clients | 18 focused ADB tests |
| Local detection API | FastAPI factory, request IDs, strict CORS origins, health/readiness, SQLite metadata, Alembic migration, safe error mapping | 13 API/database/migration tests |
| Device-readiness UI | responsive shell, detection states, limitation warning, central API client, actionable errors | 4 component/integration tests plus browser interaction and overflow QA |
| Capability assessment | serial/state revalidation, fixed property/package operations, immutable decisions, hashed-serial persistence, readiness UI | capability/API/migration tests plus end-to-end browser QA |
| Evidence storage and hashing | strict portable keys, contained paths, link/reparse rejection, partial writes, atomic sealing, no overwrite, streaming SHA-256 | 15 passed; 1 Windows symlink test skipped without developer-mode permission |
| Durable local jobs | explicit state graph, monotonic progress, cancellation, restart recovery, version-based stale-update detection, migration | 9 job tests plus migration coverage |
| Authentication and RBAC | one-time administrator bootstrap, Argon2id, lockout, hashed opaque sessions, CSRF, rotation/revocation, five roles, protected device operations, React setup/login | service/API/component tests plus reversible migration |
| Case management | unique case numbers, ownership/memberships, object authorization, lifecycle graph, optimistic versions, append-only events, REST API, Cases UI | service/API/component tests plus reversible migration |
| Case-linked devices | case-authorized detection, hashed stable identity, immutable readiness history, closed-case blocking, history APIs, case device registry UI | 96 backend tests passed, 1 Windows symlink-permission skip, 10 frontend tests passed |
| Shared-storage root probe | formal typed ADB catalog, fixed `/sdcard` and `/storage/emulated/0` directory/readability predicates, explicit supported/blocked decisions, persisted/UI root results | 105 backend tests passed, 1 Windows symlink-permission skip, 10 frontend tests passed |
| Immutable acquisition planning | exact readiness-snapshot binding, freshness/capability gates, preset and custom scopes, canonical plan/snapshot hashes, limitation acknowledgement, REST API and planning history UI | service/API/migration coverage plus 11 frontend tests |
| Durable acquisition-job preparation | restrictive case/plan/operator links, idempotent preparation, bounded checkpoints, sequenced append-only events, cancellation, restart interruption records, status UI | service/API/migration/UI coverage |
| Bounded shared-storage path inventory | fixed approved root, live identity/readiness revalidation, path/depth/time/output limits, durable result and canonical manifest hash, API and result UI | ADB parser/policy, service failure-state, migration, API, and UI coverage |
| Selected evidence-file acquisition | opaque inventory-item selection, shell-free bounded pull, contained partial/seal, SHA-256, canonical JSON manifest, durable provenance/failure state, result UI | known-answer storage/ADB/service/API/UI tests; physical-device validation pending |
| Interrupted-transfer recovery | durable attempt IDs, startup filesystem reconciliation, retained partial SHA-256, review-before-restart, verified discard, byte-zero retry | disconnect/process-termination/tamper/service/API/UI tests; physical-device validation pending |
| Artifact normalization and search | one immutable artifact per sealed file, canonical provenance/limitations, extension-only classification, SQLite FTS5, case/category/status/extension filters, metadata-only explorer | known-answer/no-content-index/reindex/case-isolation/API/UI tests |
| Timeline and analyst annotations | deterministic acquisition-time events, stable hashes/backfill, UTC/confidence/source links, bookmarks, normalized tags, append-only notes and supersession | determinism/idempotency/case-scope/source-immutability/API/UI tests |
| Evidence integrity re-verification | independent file/manifest re-hashing, append-only result history, mismatch/missing detection, preserved expected hashes, API and UI controls | known-answer, tampering, missing-object, API, and UI tests |
| Custody and audit chains | automatic evidence/integrity custody events, manual transfers, amendments, per-case custody hashes, global audit hashes, verification APIs, case UI | service tampering tests, migration/API authorization, append-only route tests, UI checks |
| Workstation schema upgrades | Alembic startup upgrade plus guarded adoption of recognized pre-Alembic create-all databases | base/head, legacy-adoption, and unknown-schema refusal tests |

## Supported development behavior

- Deterministic mock detection for no device, authorized, unauthorized, offline, multiple transports, and timeout.
- Real ADB discovery from an explicit configured path or host `PATH`.
- `adb version` and `adb devices -l` only through fixed internal operations.
- Serial-scoped `getprop` and package listing for authorized transports only.
- Serial-scoped, content-free `test -d` and `test -r` checks for two internal-policy storage roots; no caller-provided path and no file listing.
- Explicit decisions for device metadata, package inventory, shared storage, private app data, and deleted-data recovery.
- Persisted successful detection-run metadata without storing evidence content.
- Evidence-root primitives that never accept investigator strings as direct paths.
- Streaming file writes and SHA-256 calculations without loading whole evidence files in memory.
- Durable job records that preserve interruption/error state across backend restarts.
- Local administrator bootstrap and session-protected device operations without browser-stored access tokens.
- Case-scoped access rules and lifecycle history that cannot be bypassed by frontend navigation.
- Case-linked device observations that retain a masked serial suffix and SHA-256 identity but never persist the raw ADB serial.
- Immutable readiness snapshots and append-only case events for detection and assessment operations.
- Immutable acquisition plans that bind the selected modules to an exact readiness snapshot and operator acknowledgement.
- Server-side rejection of stale, unsupported, cross-case, closed-case, and underprivileged planning requests.
- Prepared acquisition jobs that run only the explicitly selected bounded path-inventory executor.
- Content-free path inventory under one approved shared-storage root, capped at depth 6, 250 persisted paths, 30 seconds, and the ADB runner output limit.
- Live serial-hash, authorization, build-fingerprint, readable-root, and workstation free-space checks immediately before inventory.
- Durable relative paths, extensions, per-path hashes, counts, and a canonical inventory-manifest hash without Android file bytes.
- Selected acquisition of an inventory-issued path only; no browser-supplied remote path or arbitrary ADB command.
- Per-file 100 MiB and 120-second limits, contained partial handling, final file SHA-256, and separately hashed canonical manifest.
- Explicit `not_physically_validated` state on acquired files until the controlled device matrix is executed.
- Append-only verification history with expected/observed file and manifest hashes, size comparison, canonical verification-record hash, actor, and timestamp.
- Explicit mismatch and missing-object outcomes that never silently replace acquisition hashes.
- Automatic evidence registration and integrity custody events plus manual transfers and correction-by-amendment; no custody update/delete API exists.
- Per-case custody and global audit SHA-256 chains with canonical serialization, genesis linkage, sequence verification, and protected audit access.
- Reconstructable progress history with monotonic sequence numbers and persisted restart interruption events.

## Not implemented yet

- External audit anchoring, digital signatures, and write-once custody exports
- Bulk acquisition and physical-device validation of byte-zero restart behavior
- Sandboxed thumbnails/content preview and device-side timestamp extraction from validated sources
- Report generation and exports
- Production packaging, signing, and forensic validation

These omissions are visible project status, not silent product claims. Real-device testing remains a controlled Phase 0 activity.

## Next critical-path slice

1. Install Android Platform Tools and validate inventory plus selected pulls against controlled physical devices and hostile filename fixtures.
2. Validate disconnect/restart recovery against physical devices on Windows, Linux, and macOS.
3. Add external audit anchoring and signed/write-once custody exports before evidentiary claims.
4. Add isolated, resource-bounded MIME sniffing and thumbnail generation for validated formats.
5. Add validated source timestamp claims to the existing deterministic timeline without inventing missing values.
