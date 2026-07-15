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

## Supported development behavior

- Deterministic mock detection for no device, authorized, unauthorized, offline, multiple transports, and timeout.
- Real ADB discovery from an explicit configured path or host `PATH`.
- `adb version` and `adb devices -l` only through fixed internal operations.
- Persisted successful detection-run metadata without storing evidence content.

## Not implemented yet

- Authentication, roles, cases, custody, and audit chain
- Device property/capability assessment
- Acquisition planning, pulling, evidence storage, hashing, and manifests
- Artifact normalization, search, preview, and timeline
- Report generation and exports
- Production packaging, signing, and forensic validation

These omissions are visible project status, not silent product claims. Real-device testing remains a controlled Phase 0 activity.

## Next critical-path slice

1. Add immutable device property and capability snapshots.
2. Add serial-scoped, fixed operations for approved property and package metadata.
3. Add safe evidence-root containment and streaming SHA-256 primitives.
4. Add a durable acquisition/job state machine before any file pull operation.
5. Start authentication and case scoping before exposing acquisition controls.
