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

## Detached signature verification

ForensiX can verify a detached signature over the sealed checkpoint using a supplied public X.509
certificate. Supported algorithms are RSA PKCS#1 v1.5 with SHA-256, RSA-PSS with SHA-256, and
ECDSA with SHA-256. The operator supplies a public certificate, detached signature, declared
signing time, and the checkpoint SHA-256. Private keys must never be supplied.

Before accepting the verification, ForensiX:

1. Re-verifies the checkpoint file against its stored SHA-256.
2. Requires the acknowledged checkpoint SHA-256 to match.
3. Parses the bounded PEM X.509 certificate.
4. Checks that the certificate was valid at the declared signing time.
5. Enforces digital-signature key usage when that certificate extension is present.
6. Verifies the signature using the selected algorithm and certificate public key.
7. Stores an append-only receipt containing certificate, signature, checkpoint, and verification
   fingerprints and appends an audit-chain event.

This verifies the cryptographic relationship between the supplied certificate, signature, and
checkpoint. It does not build or validate a certificate chain, query revocation services, prove the
real-world identity of the certificate subject, or provide a trusted timestamp. Those controls must
come from the agency PKI or an approved external validation process.
