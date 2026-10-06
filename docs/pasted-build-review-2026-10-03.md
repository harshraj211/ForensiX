# Pasted A–K build review (2026-10-03)

Source: `C:\Users\harsh\.codex\attachments\08c26fed-7972-4132-909b-0c8737e2eb72\Pasted text.txt`.

| Draft section | Disposition in this repository |
| --- | --- |
| A: mega timeline | Its NDJSON export was added to the existing case timeline endpoint. The UI now loads past 200 events. The proposed router used absent `AsyncSessionDep`, `enqueue_job`, and `MegaTimelineEvent` types. |
| A: social graph | Existing `/analytics/social-graph` service and correlation UI already cover this path; a duplicate router was not added. |
| A/I: cloud tokens | The draft stores and displays raw account tokens. No token inventory or export was added. The existing five-provider cloud **export** importer does not provide live account token acquisition. |
| A/H: carved artifacts | The verified-image scanner runs through the versioned evidence parser, saves a scan summary and candidate source artifacts, and exposes a hash-checked candidate download in Evidence Twin. It does not classify allocated versus unallocated bytes. |
| B: deep pull | The proposed script copies private data through shared storage and deletes the staged copy. It was not connected to acquisition; existing approved ADB and evidence-source paths retain provenance and explicit capability checks. |
| C: capability gate | Existing `forensix_forensic.capabilities.assessor` already provides device-level decisions. |
| D/E: Telegram and system decoders | Existing cloud export, rooted Telegram, Android application, communication, and system parsers cover overlapping sources. The pasted decoders were not imported as parallel registries. |
| F: image carver | Replaced the existing hardcoded raw-disk sample findings with actual read-only signature scanning on a reverified working copy. The pasted offset arithmetic and delimiter-only validation were not used. |
| G: timeline view | Applied to the existing `TimelinePage` with paged loading and full NDJSON download. |
| J: AI PDF | Existing AI narrative and report renderer are separate workflows. The draft's direct unescaped narrative-to-ReportLab flow was not added. |
| K: demo script | Its URLs do not match registered routes and it does not handle the authenticated session/CSRF flow. It was not installed as a working end-to-end script. |

## Verified scope

- API integration: imported agent bundle produces timeline records; full NDJSON contains the same event hashes and source links.
- API integration: a sealed `.img` and verified working copy yield an actual PNG signature finding across a scan-chunk boundary. Its saved artifact is available for a second hash-verified byte download; a repeated scan does not duplicate artifacts.
- Unit: false JPEG signatures are skipped; a real JPEG's exact offset, size, and hash are reported.
- Inspection: a zero-prefixed raw image is not mislabeled as an empty TAR archive.
- Web production build, Ruff, and mypy pass for changed paths.

The image scanner is limited to raw byte streams and decodable JPEG/PNG candidates up to 32 MiB each. It does not decode Android sparse images, decrypt FBE, recover overwritten bytes, or prove that a candidate was deleted. Physical-device validation remains outstanding.

## Follow-up parser review (2026-10-06)

The follow-up draft proposed standalone Instagram, Snapchat, and Contacts decoders. ForensiX already had these application adapters, so the compatible additions were made within the existing registry:

- `android.instagram.direct` recognizes `direct_v2_message_items` from `direct.db`, distinguishes microsecond and millisecond timestamps, captures thread/sender/item metadata, and records the app's unsent marker as a database status claim.
- `android.snapchat.arroyo` recognizes a bounded plaintext `messages` schema from `arroyo.db`, including conversation, sender, saved-state, and content-type metadata.
- ContactsProvider parsing now retains aggregate `contacts` fields when available: contact ID, raw-contact IDs, contact count, last-contact time, starred status, and photo presence.

The proposed WhatsApp media-key derivation code was not added. Existing WhatsApp parsing remains limited to supported plaintext database and export formats.
