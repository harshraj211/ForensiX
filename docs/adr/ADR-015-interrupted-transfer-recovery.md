# ADR-015: Interrupted transfer recovery uses durable partials and byte-zero restart

## Status

Accepted for the ForensiX MVP.

## Context

An ADB pull may stop because the cable disconnects, the backend exits, storage fails, or the operator cancels. A Boolean saying that some partial bytes exist cannot identify the file, prove whether it changed, support a reviewable retention decision, or prevent unsafe cleanup. ADB pull does not provide a portable, validated byte-range resume contract across supported Android and host versions.

## Decision

Before a transfer begins, ForensiX creates a database record and a contained, opaque partial storage key. The ADB process may write only to that destination. On a caught failure or backend startup, ForensiX reconciles the database record with the filesystem and classifies the attempt as retained, discarded, sealed, or missing. Retained bytes receive a size and SHA-256 digest but are not indexed as evidence.

An operator must explicitly retain or discard every unreviewed retained partial before restarting that inventory item. Discard first re-hashes the file and refuses deletion if its size or digest changed. Retain preserves the old attempt for later examination. Both decisions create case and chained audit events. A restart revalidates the live device identity and begins a new transfer from byte zero; the UI and API do not call this byte-level resume.

Startup reconciliation never automatically reconnects to a device or runs ADB commands. If the final sealed file exists after a process interruption, normal idempotent completion reconstructs and verifies its manifest on the next explicit attempt.

## Alternatives considered

- Delete every partial automatically: rejected because it destroys potentially useful diagnostic bytes and provides no review trail.
- Keep anonymous hidden files: rejected because they cannot be safely reconciled with an acquisition item.
- Append a new ADB pull to the old partial: rejected until source identity, remote stability, offset semantics, and cross-platform behavior are validated.
- Treat partial bytes as evidence: rejected because incomplete bytes have not passed sealing, manifesting, and provenance completion.

## Consequences and limitations

- Interrupted bytes consume storage until reviewed; the UI exposes their size and digest.
- Retained partials are quarantined transfer artifacts, not completed evidence.
- The local audit chain is tamper-evident, not tamper-proof or externally notarized.
- A future validated item-level resume protocol may add immutable source stat/hash checkpoints, but it must not reinterpret existing byte-zero restart records.
