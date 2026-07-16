# ADR-016: Normalize sealed files as metadata-only artifacts indexed with SQLite FTS5

## Status

Accepted for the ForensiX MVP foundation.

## Context

Evidence search needs a stable, case-authorized schema rather than direct filesystem traversal. Evidence files are hostile input: opening a malformed image, document, archive, or media file inside the API process can expose parsers and renderers before isolation and resource limits exist. Operating-system MIME registries also vary and are not deterministic enough for forensic normalization.

## Decision

ForensiX creates one immutable normalized artifact after a file is atomically sealed and hashed. The artifact binds the evidence-file, case, device, job, source-path hash, storage provenance, SHA-256, size, collection time, tool/parser version, validation state, schema version, and explicit limitations. It uses an internal extension-to-MIME mapping and records `filename_extension_only` as the classification basis. Unknown extensions become `application/octet-stream` and category `other`.

No evidence bytes are opened, sniffed, decoded, executed, or rendered by this normalizer. The evidence explorer displays metadata and provenance only. A future isolated worker may add content-derived metadata as a separate versioned derivation; it must never overwrite the raw file artifact.

Search uses a separately maintained SQLite FTS5 table containing artifact ID, case ID, title, fixed summary, and source name. User input is converted to at most eight quoted Unicode word terms; raw FTS syntax and SQL are never accepted. Case authorization is checked before every query and detail lookup. Category, status, and extension filters use allowlisted structured columns. Sort order is collected time then artifact UUID for stable pages.

Acquisition completion indexes transactionally. Startup backfill creates missing artifacts and repairs missing FTS entries idempotently for earlier completed evidence. The API exposes GET only for artifacts in this slice; there is no source metadata update or delete route.

## Alternatives considered

- Search the evidence filesystem: rejected because it bypasses case authorization and provenance.
- Use `LIKE` over JSON metadata: rejected because it scales poorly and has unclear indexing behavior.
- Run full MIME/EXIF/document parsing in FastAPI: rejected until process isolation, time/memory/pixel/archive limits, and hostile fixtures exist.
- Elasticsearch or a cloud search service: rejected because the MVP is local-first, offline, and single-workstation.

## Consequences and limitations

- MIME values are preliminary extension classifications, not content-verified media types.
- Content text, EXIF, remote filesystem timestamps, and thumbnails are not available yet.
- Duplicate SHA-256 values remain separate case/acquisition provenance records; relationship materialization is future work.
- FTS5 availability is a workstation database requirement and is verified by migrations/tests.
- The million-artifact p95 performance target still requires the planned reference dataset benchmark.
