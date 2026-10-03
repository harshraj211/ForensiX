# ForensiX implementation plan

**Revision:** 2026-10-01  
**Demo target:** 2026-10-10  
**Definition of done:** every completed capability has a source hash, a capability-state record, parser/test coverage, an API result, a visible UI path, and a report representation.

## Current baseline

| Area | Shipped now | Proof location |
| --- | --- | --- |
| Unlocked logical collection | Android agent bundle collection for contacts, SMS, calls, installed apps, device state, MediaStore metadata, downloads, readable shared files, hashes, and manifest sealing | `agent_apk/forensix_agent`, `extractors/agent_apk` |
| No-ADB transfer | `.fxz` agent bundle validation, import, sealing, parser run, custody event, UI intake panel | Agent-bundle API and Evidence Twin |
| Android artifact parsing | Core telephony, contacts, calendar, notifications, downloads, Wi-Fi, Bluetooth, user profiles, Chrome, Firefox, Samsung Internet, Edge, Maps searches, usage stats, WhatsApp, Telegram, Signal, Gmail and several social/export parsers | `android_artifacts` registry |
| Backup/import intake | Google Takeout, WhatsApp backup/export, vendor-backup and filesystem-image intake paths | `extractors/cloud`, `vendor_backup.py` |
| Deleted-data recovery | SQLite carving/WAL-journal recovery, recovery-state artifact records, Evidence Twin and external PhotoRec controller for verified working copies | `evidence_io`, `evidence_twin` |
| Analysis | Timeline, correlation graph, location, OCR/EXIF, face regions and clusters, object ONNX adapter, Whisper adapter, visual similarity | API, web Evidence Explorer and Media Map |
| Visual ML | Locally installed, verified ViT-B-32 image encoder with exact OpenCLIP preprocessing and gallery similarity | `models/vision`, `docs/forensix-clip-model.md` |
| Reporting and custody | PDF, JSON, CSV, portable static HTML, source/parser/artifact hashes, custody chain, verification paths | `reporting`, `custody` |

## Build sequence

### Completed extension: Agent bundle v2

The no-ADB Android Agent now exports Wi-Fi connection state, bonded Bluetooth
metadata, and active subscription/SIM metadata alongside its existing logical
collection. The desktop importer accepts both the previous v1 bundle and v2,
validates every manifest hash, and emits the added records as searchable system
artifacts. Per-source platform and permission limitations remain in the bundle
manifest and Evidence Twin intake response.

| Phase | Outcome | Concrete implementation | Acceptance check | State dependency |
| --- | --- | --- | --- | --- |
| 1 | Demo-spine hardening | Build agent APK, run one agent collection, import `.fxz`, parse, run media analysis, inspect timeline/graph, generate portable HTML/PDF | One case demonstrates acquisition through report without a manual database edit | Unlocked Android or prepared bundle |
| 2 | Logical collection breadth | Add agent-visible Wi-Fi connection state, bonded Bluetooth metadata, SAF-selected shared files, MediaStore hashing, app inventory permission/installer fields | Fixture bundle exposes every implemented category and explicit unavailable records | Android permissions and user-granted document tree |
| 3 | Backup and import pack | Finish Samsung Smart Switch import mapping, ADB backup ingestion for legacy inputs, memory-card directory/image intake, browser profile import mapping | Imported backup records produce normalized artifacts and source hashes | Supplied backup or mounted card/image |
| 4 | Five deep cloud paths | Google Takeout/Drive/Photos/Gmail/Maps imports; WhatsApp exports/local backup; Microsoft export; Telegram export; iCloud export | Connector/import request ledger, account scope, response hashes, timeline/artifact/report output | Account authorization or exported data |
| 5 | Parser and recovery pack | Expand application schema fixtures; add browser downloads/bookmarks/searches; improve SQLite freeblock/WAL association and recovered-row confidence | Recovered artifacts show source page/offset, status and confidence in UI/report | Readable SQLite, WAL, journal, or recovered file |
| 6 | Analysis maturity | Timeline gap filters/timezone basis, graph entity merge review, location clustering, OCR boxes/language packs, visual search quality labels, transcript language/confidence | One review workflow moves from raw artifact to a cited report observation | Input artifacts and local ML models where selected |
| 7 | Portable case review | Expand static HTML with verification page, thumbnails, graph/timeline navigation, manifest verification, annotations and bookmarks | Bundle opens offline, verifies every included file and renders a reviewable case | Completed case snapshot |
| 8 | Deployment and release | Signed build, dependency SBOM, migration test, backup/restore test, local-only launcher, Docker volume model mount, release smoke test | Fresh workstation can install, start, import a fixture, report and verify | Release signing material and target OS |

## Android access tracks

| Requested capability | Product implementation | Evidence shown to examiner | Blocker class |
| --- | --- | --- | --- |
| Unlocked Android logical acquisition | Agent plus ADB collectors, document-tree selection, MediaStore and content-provider scopes | Permission state, collector manifest, file hashes, unavailable fields | Platform permission |
| Full file system | Rooted-device allowlisted path acquisition, raw/image import, parser scheduling and sealed source records | Device/build profile, acquisition manifest, image hash, parser run | Root, boot state, filesystem encryption |
| Physical acquisition | Chipset/device detection, sealed external tool/image import, GPT/filesystem parser pipeline, hardware workflow record | VID/PID, chipset matrix, external tool version, source hash | Hardware, vendor loader/license, device state |
| Locked-device access | Compatibility assessment that records model, chipset, Android build, patch level, lock state, available authorized acquisition surface and an external-result import path | Signed capability assessment and selected source result | Platform, hardware, vendor method |
| Temporary-root registry | Reviewed profile metadata, input compatibility checks, pre/post state capture, cleanup and result verification | Exact build fingerprint, profile version, before/after state, source manifest | Platform, technical validation |
| Samsung Exynos | Download-mode/device metadata, external physical-image import and parser profile selection | Download-mode record, device/build and image hash | Hardware, vendor method |
| Passcode recovery | State assessment and import of authorized external recovery result; preserve result provenance and validation status | Recovery job/input/output hashes and verifier result | TEE/Gatekeeper, hardware, vendor method |

## Cloud breadth plan

| Tier | Services | Delivery form |
| --- | --- | --- |
| Deep connectors | Google, WhatsApp, Microsoft, Telegram, iCloud | OAuth/export import, request ledger, account scope, normalized artifacts |
| Messaging/social imports | Facebook/Messenger, Instagram, Discord, Slack, Signal exports, Snapchat, TikTok, X, Reddit | Export package parsers and attachments correlation |
| Storage/mail imports | Dropbox, Box, OneDrive, Google Drive, Gmail, Outlook, IMAP | Metadata/files/messages/attachments with stable source locators |
| Consumer/transaction imports | Amazon, Uber, Lyft, PayPal, Venmo, banking CSV, LinkedIn, GitHub | Export parsers normalized to timeline, entities and source hashes |
| Browser/account exports | Chrome Sync export, Firefox profile export, Google Takeout, Samsung Smart Switch | History, bookmarks, downloads, session/account metadata where present |

The catalog exposes more than 50 service entries. A service only moves from catalog coverage to implemented coverage after it has a parser or connector, fixtures, normalized output, custody recording and a UI/report path.

## Capability gates

| Gate | Required proof before a release claim |
| --- | --- |
| Agent | Signed APK build, physical-device collection, bundle import and parser fixture |
| ADB backup | Device/API compatibility fixture and sealed backup import |
| Smart Switch | Representative export fixtures across supported schema versions |
| SIM/card | Reader/tool output import fixture, ICCID/IMSI redaction controls, source hash and report path |
| Memory card | Read-only acquisition manifest, filesystem inventory, carved-file provenance and hash verification |
| Cloud | Provider scope ledger, retry/rate-limit handling, fixture export, response hash and revocation handling |
| ML | Model hash, preprocessing contract, held-out evaluation, real inference, UI and report provenance |
| Physical/locked | Device-specific lab validation, supported-state matrix, signed tool/image provenance and repeatability record |

## Hackathon execution order

1. Run a real `.fxz` bundle through collection, import, parsing, timeline, graph, media analysis and portable report.
2. Complete Smart Switch, legacy ADB-backup and browser-profile import fixtures.
3. Complete the first five cloud import flows with a visible service-status dashboard.
4. Add OCR bounding boxes/language selection and attach visual-search provenance to reports.
5. Run release smoke tests on a fresh database and prepare the demo case bundle.

## Remaining claims after the hackathon

### Implemented slice: five offline cloud export import flows

Google, WhatsApp, Microsoft, Telegram and iCloud export inputs now enter the sealed-source,
verified-working-copy, versioned-parser, search, timeline, custody and report pipeline.
Provider controls, persisted summaries, issues and detailed artifact fields are visible in
Evidence Twin. See [supported formats, limits and usage](cloud-export-imports.md).
Live cloud acquisition, encrypted backup decryption and the remaining catalog services stay pending.

### Implemented slice: Smart Switch archive examination

The backup intake seals ZIP-compatible `.sbu` archives and Smart Switch identified
ZIP archives, creates a verified working copy, then runs the versioned
`samsung.smart_switch.archive` parser. It indexes readable contacts, messages,
calls, settings, media and standard Android SQLite records; each derived record
carries the archive member path, SHA-256 and size. The summary artifact lists
unsupported members and parse issues. Generic ZIP archives remain classified as
generic and do not automatically run the Samsung parser. See
[Smart Switch import coverage](smart-switch-imports.md).

Smart Switch PC backup directories can now be selected in the browser and
packaged with per-file hashes for the same verified-copy parser path. Readable
CSV/JSON and standard SQLite contents are normalized; opaque `.spbm` members
are retained as hashed file records with an unsupported status. The fixtures
are synthetic, so native version compatibility and proprietary decoding still
need representative exports and format adapters.

### Implemented slice: legacy Android Backup parsing

Unencrypted `.ab` files now enter the same sealed-source and verified-working-copy
path. A bounded decompressor opens the TAR payload, indexes regular members with
their SHA-256 and package path, and applies supported Android SQLite parsers.
The API returns the parser run ID, and the UI shows its status and artifact count. Encrypted `.ab` files remain
sealed and inventoried without decryption. The tests cover a compressed backup
with an SMS SQLite database and API persistence of a shared-file backup.

### Implemented slice: FAT32 card-image examination

`.img`, `.dd`, and `.raw` intake now identifies FAT32 at sector zero or in a
primary MBR partition. After sealing and working-copy verification, the
`memory_card.fat32.image` parser indexes active files and directories, hashes
bounded readable files, and records deleted directory entries. A deleted file
with contiguous, currently unallocated clusters is labeled as a recovery
candidate and can be downloaded through an API that rechecks the working-copy
hash, FAT allocation state, and candidate content hash. The UI exposes this
state and download. Synthetic parser and HTTP tests cover import through
candidate byte export. [Exact scope and limits](memory-card-imports.md).

The project should describe logical acquisition, image/import analysis, authorized cloud/export processing and case review as implemented only after their acceptance checks pass. Full filesystem, physical, locked-device and passcode tracks require a supported device state, hardware or vendor method and per-profile validation; they remain compatibility-matrix entries until those proofs exist.
