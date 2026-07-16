# ADR-017: Timeline claims and analyst annotations remain separate from source artifacts

## Status

Accepted for the ForensiX MVP foundation.

## Context

A forensic timeline must distinguish observed timestamps from inferred or unavailable timestamps. The current logical acquisition records a trustworthy workstation collection time but does not yet collect remote filesystem stat values, EXIF timestamps, or application event times. Analyst bookmarks, tags, and observations are useful during triage but must not rewrite normalized evidence or its provenance.

## Decision

ForensiX materializes one `acquisition_collected_at` timeline event from every normalized artifact. The event stores the UTC value, original serialized value, timestamp type, timezone basis, precision, confidence, category, source artifact/job, builder version, and a deterministic SHA-256 over the canonical claim. The unique artifact/type constraint and stable hash make rebuilding idempotent. Startup backfill creates missing events for artifacts produced by earlier builds.

The interface labels these as workstation acquisition timestamps. It does not display them as file creation, modification, access, EXIF, message, or application timestamps. Future timestamp sources must add separate typed claims with their own original values, parser versions, timezone basis, confidence, and conflict handling; they cannot replace this collection event.

Bookmarks are user-scoped state with recorded add/remove audit events. Tags are normalized and unique within a case, then associated with artifacts without changing artifact fields. Analyst notes are append-only. A correction creates a new note whose `supersedes_id` points to the prior note; there is no note update or delete endpoint. All annotation writes require case access plus `evidence:analyze` and enter the global tamper-evident audit chain.

## Alternatives considered

- Use collection time as file modification time: rejected because it would create a false device-side claim.
- Store tags or notes inside artifact JSON: rejected because analyst work would mutate normalized evidence.
- Allow editing notes in place: rejected because it erases review history.
- Generate timeline events on every request: rejected because durable, versioned events are easier to validate and reproduce.

## Consequences and limitations

- The first timeline is intentionally sparse and contains acquisition events only.
- Device-side and application timestamps remain unavailable until validated acquisition/parser modules supply them.
- Bookmark removal changes bookmark state but leaves the corresponding audit history intact.
- The audit chain is locally tamper-evident, not immutable, signed, or externally notarized.
- Timeline scale and p95 targets still require the planned million-artifact benchmark.
