# Phase 0 Implementation Status

**Updated:** 15 July 2026  
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

## Supported development behavior

- Deterministic mock detection for no device, authorized, unauthorized, offline, multiple transports, and timeout.
- Real ADB discovery from an explicit configured path or host `PATH`.
- `adb version` and `adb devices -l` only through fixed internal operations.
- Serial-scoped `getprop` and package listing for authorized transports only.
- Explicit decisions for device metadata, package inventory, shared storage, private app data, and deleted-data recovery.
- Persisted successful detection-run metadata without storing evidence content.
- Evidence-root primitives that never accept investigator strings as direct paths.
- Streaming file writes and SHA-256 calculations without loading whole evidence files in memory.
- Durable job records that preserve interruption/error state across backend restarts.
- Local administrator bootstrap and session-protected device operations without browser-stored access tokens.
- Case-scoped access rules and lifecycle history that cannot be bypassed by frontend navigation.

## Not implemented yet

- Custody and tamper-evident audit chain
- Acquisition planning/orchestration, ADB pulling, evidence manifests, and verification records
- Artifact normalization, search, preview, and timeline
- Report generation and exports
- Production packaging, signing, and forensic validation

These omissions are visible project status, not silent product claims. Real-device testing remains a controlled Phase 0 activity.

## Next critical-path slice

1. Probe accessible shared-storage roots through fixed, bounded operations.
2. Persist devices and link readiness snapshots to authorized cases.
3. Connect durable jobs to an acquisition-plan model and progress event stream.
4. Add acquisition manifests and item-level interruption checkpoints.
5. Enable the first controlled shared-storage pull only after physical-device validation.
