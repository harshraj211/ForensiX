# Evidence Twin roadmap completion audit

**Audited:** 22 July 2026

**Scope:** the implemented Evidence Twin roadmap on `agent/phase0-foundation`

**Claim boundary:** software implementation and controlled known-answer verification; not a claim
of universal Android access, physical-device matrix completion, hardware write blocking, deleted
data recovery, or evidentiary admissibility.

## Requirement evidence

| Roadmap requirement | Current evidence | Audit result |
|---|---|---|
| Evidence image/import source models | `EvidenceSourceRecord`, source/chunk/verification/working-copy models in `server/src/forensix_server/db/models.py`; versioned enums in `evidence_twin/domain.py`; import REST boundary in `apps/api/src/forensix_api/routers/evidence_sources.py` | Implemented |
| Streaming sealed master, chunk ledger, whole-source and manifest hashes | `EvidenceTwinService._seal_stream` streams fixed chunks through `EvidenceStore`, persists per-chunk SHA-256, seals the master/chunk ledger/canonical manifest, and refuses empty or size-conflicting input | Implemented; known-answer and tamper tests in `server/tests/test_evidence_twin.py` |
| Verified examination working copies | independent copy creation and master/copy re-hashing in `evidence_twin/service.py`; originals remain separate and append-oriented | Implemented; corruption and copy-isolation tests |
| Import UI and signature-based detection | `EvidenceTwinPage.tsx` exposes import, source history, copy creation/verification, inspection, native parser, recovery, and ALEAPP actions; `evidence_twin/inspection.py` detects SQLite, ZIP/TAR, Android sparse/ext4/F2FS indicators without trusting filename extensions | Implemented; API/component and inspection tests |
| Offline contacts, SMS/MMS, and call-log parsing | closed native registry plus bounded read-only immutable SQLite reader; provider parsers in `android_artifacts/contacts.py` and `communications.py` | Implemented for compatible lawfully obtained plaintext databases; known-answer tests in `forensic/tests/test_android_provider_parsers.py` |
| Browser/download/calendar/notes/notification/location/Wi-Fi/Bluetooth parsing | system SQLite parsers and bounded entity-safe document parsers in `android_artifacts/system.py` and `documents.py` | Implemented for recognized plaintext schemas/files; known-answer, path-gating, credential-hashing, and entity-rejection tests |
| Social-application parser framework | trusted registry, version/access/maturity/path declarations, WhatsApp and Telegram plaintext parsers, and Messenger/Facebook/Instagram interchange parsers | Framework implemented and path-gated; Signal and Snapchat remain truthful detection-only entries because supported inputs are commonly encrypted, binary, ephemeral, or server-side |
| ALEAPP integration | pinned local executable plus SHA-256 verification, shell-free argument vector, timeout/output limits, verified ZIP/TAR working-copy input, sealed derived outputs, audit/custody links in `integrations/aleapp.py` and `evidence_twin/aleapp.py` | Implemented as optional integration; no bundled or unpinned executable is trusted |
| Normalization and timeline | parser outputs retain source/copy/input hashes, parser version, locator, confidence, timestamps, limitations, and immutable artifacts; timeline links back to sources | Implemented; provider/system/social/archive and Evidence Twin pipeline tests |
| Custody, audit, checkpoint, and reports | chained custody/audit records, amendment-only corrections, sealed checkpoints/anchor receipts/detached signature verification, preliminary PDF/JSON/CSV, redaction profiles, independent approval/rejection chain | Implemented; tamper, crypto, authorization, formula-neutralization, redaction, approval, and download tests |
| Root capability and bounded filesystem acquisition | expiring case/device-bound `su -c id` proof, closed provider/system profiles, bounded streaming TAR capture, Evidence Twin sealing, API and UI acknowledgements | Implemented as elevated-access mode; does not bypass locks/encryption and is not a bit-for-bit image |
| Experimental block acquisition | configuration-off default, fixed `userdata` profile, root and exact-size probes, four risk acknowledgements, bounded raw stream, chunk/whole hashing, Evidence Twin registration | Implemented as experimental only; no physical-acquisition or decryption guarantee |
| Deleted-data research | metadata-only SQLite/WAL/journal readiness assessment over verified copies with no deleted-row inference | Implemented at experimental readiness level; recovery claims remain unsupported until controlled validation |
| Forensic validation | sealed software-known-answer pipeline; fixed-path two-pass physical fixture; interactive disconnect/reauthorization/reacquisition protocol; sealed matrix verifier that rejects tampered, mock, duplicate, or identity-deficient inputs | Harness implemented; controlled physical matrix execution remains outstanding |

## Verification evidence

- Repository-wide Python gate after the validation implementation: 313 passed, 2 environment-only
  symlink skips; Ruff and strict mypy passed across 109 source files.
- Frontend gate: 16 tests, ESLint, strict TypeScript, and production Vite build passed.
- Evidence Twin known-answer runner validates source/chunk/manifest hashing, working-copy integrity,
  signature detection, contacts/SMS/MMS/calls, normalized timeline, custody/audit chains, and sealed
  PDF/JSON/CSV output without retaining fixture PII.
- The physical matrix gate requires sealed system-mode records with a hashed ADB executable,
  hashed device serial/build identity, every declared host/Android release, at least two manufacturer
  families, rooted and non-rooted runs, and passing known-file plus transport-cycle checks.

## Outstanding external proof

The software roadmap above is implemented, but production forensic validation is not complete until
real controlled devices produce the required sealed matrix. At audit time, the configured Windows
ADB installation returned `List of devices attached` with no transport, so no physical result was
fabricated or marked passed.

Required release evidence remains:

1. Windows, Linux, and macOS controlled runs.
2. Every declared Android version/API range and at least two manufacturer families.
3. Authorized non-rooted and controlled rooted devices.
4. Two-pass known-file acquisition plus disconnect/reconnect/reacquisition on every accepted run.
5. Hostile filename, source timestamp, disk-full, timeout, and byte-zero restart observations.
6. Independent examiner review and disposition of every warning/failure.

Signal/Snapchat decryption or universal private-app parsing is not an outstanding coding checkbox:
it requires lawful key/input availability, version-specific research, and known-answer validation.
ForensiX must continue showing these sources as detection-only when those conditions are absent.
