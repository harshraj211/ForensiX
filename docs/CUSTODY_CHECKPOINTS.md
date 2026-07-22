# Custody checkpoint exports

ForensiX can create a sealed JSON checkpoint for a case after both the per-case custody chain and
the global audit chain verify successfully.

The checkpoint contains the case identifier, custody head hash, audit head hash, record counts,
schema version, package metadata, and the SHA-256 hash of the canonical JSON export. Downloads are
re-verified against the stored package hash before the API returns the file.

## What this proves

- The exported JSON matched the verified custody and audit heads at the moment of checkpoint
  creation.
- The downloaded package still matches the SHA-256 value recorded by ForensiX.
- Any later database or file tampering can be compared against the preserved checkpoint package and
  its hash.

## What this does not prove

- It is not an external timestamp.
- It is not a digital signature.
- It is not write-once storage.
- It does not make a local SQLite database tamper-proof.

The checkpoint is deliberately labelled `not_externally_anchored`. To create an external anchor,
an agency workflow must preserve the JSON file and SHA-256 value outside the ForensiX workstation,
for example in a signed case-management system, evidence vault, append-only log, or approved
notarization process.

## Operator flow

1. Open a case as an administrator or supervisor with custody-review and audit-view permissions.
2. Verify the chain-of-custody panel is valid.
3. Create a sealed checkpoint package.
4. Download the JSON package.
5. Preserve the JSON file and displayed SHA-256 hash through the agency-controlled process.
6. Record the external provider, external reference, anchored time, and optional receipt SHA-256
   in the checkpoint's **Anchor receipts** panel.

## Anchor receipts

An anchor receipt is an append-only ForensiX record describing an external preservation action.
The operator must provide the exact checkpoint SHA-256. The backend re-verifies the sealed
checkpoint file and rejects a mismatched hash before recording the receipt.

Each receipt has a canonical `anchor_hash` covering its checkpoint, provider, reference, time,
optional receipt hash, notes, actor, and creation time. Recording the receipt also appends a
tamper-evident audit event. The supported classifications are case management, evidence vault,
digital signature, external timestamp, and other.

This record does not contact, validate, or control the named external provider. It proves only what
was recorded in ForensiX. Independent verification must compare the checkpoint and receipt with the
agency-controlled external system.
