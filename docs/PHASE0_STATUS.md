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

## Supported development behavior

- Deterministic mock detection for no device, authorized, unauthorized, offline, multiple transports, and timeout.
- Real ADB discovery from an explicit configured path or host `PATH`.
- `adb version` and `adb devices -l` only through fixed internal operations.
- Serial-scoped `getprop` and package listing for authorized transports only.
- Explicit decisions for device metadata, package inventory, shared storage, private app data, and deleted-data recovery.
- Persisted successful detection-run metadata without storing evidence content.

## Not implemented yet

- Authentication, roles, cases, custody, and audit chain
- Acquisition planning, pulling, evidence storage, hashing, and manifests
- Artifact normalization, search, preview, and timeline
- Report generation and exports
- Production packaging, signing, and forensic validation

These omissions are visible project status, not silent product claims. Real-device testing remains a controlled Phase 0 activity.

## Next critical-path slice

1. Add safe evidence-root containment and streaming SHA-256 primitives.
2. Add a durable acquisition/job state machine before any file pull operation.
3. Start authentication and case scoping before exposing acquisition controls.
4. Probe accessible shared-storage roots through fixed, bounded operations.
5. Add acquisition manifests and interruption checkpoints before enabling file collection.
