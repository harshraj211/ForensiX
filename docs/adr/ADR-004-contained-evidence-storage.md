# ADR-004: Contained evidence storage and atomic sealing

- **Status:** Accepted
- **Date:** 15 July 2026

## Context

Evidence paths and acquired filenames are hostile input. Directly joining device or investigator strings to a workstation path can permit traversal, platform-specific path confusion, symlink or reparse-point escape, accidental overwrite, and ambiguous partial files after interruption.

## Decision

ForensiX uses a configured evidence root and application-generated portable storage keys. Keys reject absolute paths, parent/dot segments, backslashes, drive separators, empty segments, non-portable characters, and Windows device names. Existing path components are rejected when they are links or reparse points.

Bytes are streamed to a uniquely named partial file with restrictive best-effort permissions. Sealing flushes and synchronizes the file, acquires a key-specific lock, refuses an existing destination, atomically replaces the final path, and synchronizes the parent directory where supported. Interrupted writes preserve their partial bytes; clean unsealed exits remove temporary bytes. SHA-256 is computed incrementally during the write and can be independently recalculated afterward.

## Consequences

- Evidence code refers to portable storage keys instead of arbitrary absolute paths.
- Final evidence objects are append-oriented and cannot be silently overwritten through this API.
- Partial files remain distinguishable from sealed evidence and can support later reconciliation.
- Native installers must add platform-specific ACL hardening; Python permission changes are only a baseline.
- Physical-device pulling and manifest persistence remain separate operations and are not implied by these primitives.
