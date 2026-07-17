# ADR-019: Versioned preliminary report snapshots

## Status

Accepted - 17 July 2026

## Context

ForensiX needs PDF, JSON, and CSV outputs without allowing renderer differences or later case edits to change the meaning of an existing report. Report files may contain hostile evidence metadata, and spreadsheet exports can execute formulas when opened. A local report must also remain explicit about logical-triage limitations.

## Decision

- Assemble one strict Pydantic snapshot with independently versioned schema and template identifiers.
- Canonically serialize and SHA-256 hash that snapshot before rendering.
- Render Preliminary PDF, validated JSON, and selected-bookmark CSV from the same snapshot.
- Use ReportLab for the workstation PDF renderer because it is offline, deterministic, and does not require an HTML/browser engine.
- Prefix CSV cells beginning with `=`, `+`, `-`, `@`, tab, or carriage return with an apostrophe.
- Seal snapshots and outputs into contained, append-only evidence storage; persist their sizes and SHA-256 values.
- Verify an output hash before every download and record report generation in both custody and audit history.
- Mark every PDF and API record as Preliminary. Never claim hardware write blocking, physical acquisition, lock bypass, complete private-app coverage, or tamper-proof local logs.

## Consequences

Existing reports are reproducible historical snapshots and are never silently regenerated. Generating a new report creates a new ID and output set. ReportLab adds one local dependency and templates must be tested for pagination. Output files written before a database transaction failure can become unreferenced; a future storage reconciler should quarantine such objects.

## Alternatives

- WeasyPrint was rejected for the MVP because its native runtime is harder to package consistently on all three workstation operating systems.
- Browser-side PDF generation was rejected because it would expose report data to a larger rendering surface and make deterministic output harder.
- Live reports without a snapshot were rejected because later case changes would make the original output impossible to explain or reproduce.

## Validation

Known-answer tests cover deterministic PDF bytes, strict JSON, CSV neutralization, migration reversibility, API authorization, sealed downloads, SHA-256 headers, and report-linked custody events. Sample PDFs are rendered to images with Poppler and visually inspected for clipping, overflow, and footer placement.
