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
- Reconstructable progress history with monotonic sequence numbers and persisted restart interruption events.

## Not implemented yet

- Custody and tamper-evident audit chain
- Android file-content pulling, evidence-file manifests, and verification records
- Artifact normalization, search, preview, and timeline
- Report generation and exports
- Production packaging, signing, and forensic validation

These omissions are visible project status, not silent product claims. Real-device testing remains a controlled Phase 0 activity.

## Next critical-path slice

1. Validate the bounded inventory against controlled physical devices and hostile filename fixtures.
2. Define a safe item-metadata strategy that never interpolates device filenames into a shell command.
3. Add evidence-file manifests and item-level SHA-256 verification records.
4. Enable the first controlled shared-storage pull only after physical-device validation.
5. Add custody and chained audit records before presenting outputs as forensic evidence.
