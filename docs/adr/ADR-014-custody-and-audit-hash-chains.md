# ADR-014: Custody and Audit Hash Chains

**Status:** Accepted
**Date:** 16 July 2026

## Context

Evidence handling requires a reviewable history that cannot be silently corrected in place. Security-sensitive custody actions also need a separately verifiable audit trail. A local SQLite database cannot honestly be described as immutable or tamper-proof.

## Decision

ForensiX stores custody as append-only events. Evidence sealing automatically records `evidence_registered`; integrity checks record `integrity_verified` or `integrity_exception`. Investigators may add transfers with from/to custodians, purpose, and location. Corrections create an `amendment` referencing the original event; there is no update or delete endpoint.

Each case has an independent custody chain. The first record uses a 64-zero genesis hash. Every later event stores the previous event hash and calculates `SHA256(previous_hash + canonical_event)`. Canonical data includes IDs, sequence, actor, evidence reference, event details, and UTC timestamp.

Every custody event also appends a minimal entry to a global audit chain in the same database transaction. Audit entries use the same genesis/link/canonical-hash pattern and record only safe structured details. Administrators and supervisors can list and verify the audit chain; case-authorized custody reviewers can verify a case chain.

## Alternatives

- Editable custody rows were rejected because corrections could erase history.
- Database triggers alone were rejected because canonical serialization and authorization must be testable in application code.
- Calling the chains immutable was rejected because an administrator with filesystem/database access can alter multiple rows and recompute hashes.

## Consequences

Single-row edits, deletions, insertion gaps, and broken links are detected by chain verification. The design is tamper-evident rather than tamper-proof. External anchoring, signed exports, trusted timestamps, write-once storage, concurrency hardening beyond the local single-workstation model, and formal forensic validation remain production release gates.
