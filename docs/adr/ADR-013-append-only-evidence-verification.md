# ADR-013: Append-Only Evidence Verification

**Status:** Accepted
**Date:** 16 July 2026

## Context

An acquisition-time SHA-256 value is only useful if the system can later confirm that both the sealed evidence bytes and their provenance manifest still match. A verification failure must not rewrite the expected hash or hide earlier results.

## Decision

ForensiX independently re-hashes the contained evidence file and its canonical manifest. Verification requires case access and the evidence-analysis permission. The service reads no Android device and modifies no evidence file.

Every attempt creates a new record containing expected and observed hashes, observed file size, file and manifest match decisions, actor, timestamp, tool version, a stable outcome (`verified`, `mismatch`, `missing`, or `error`), and a SHA-256 over the canonical verification record. Original acquisition hashes remain unchanged.

Missing files, storage-boundary failures, and read failures are recorded as explicit outcomes rather than converted into a successful result. A safe case event references the verification ID and outcome without exposing workstation paths.

## Alternatives

- Updating a `verified` flag on the evidence row was rejected because it loses history and can conceal a later mismatch.
- Trusting only the file hash was rejected because the provenance manifest must be protected independently.
- Treating mismatch as an API exception was rejected because a mismatch is a forensic result that must be persisted and reviewed.

## Consequences

Investigators can repeatedly verify integrity and review all outcomes. The verification-record hash detects accidental serialization changes and prepares the record for the future audit chain, but a local SQLite row is not immutable or tamper-proof. Chained audit logging, custody records, external signatures, and physical-device validation remain separate release gates.
