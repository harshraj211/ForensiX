# ForensiX Commercial Readiness Plan

Date: 2026-09-29

This plan turns the Oxygen parity gaps into build phases for ForensiX. It separates what can be built directly in software from what requires user consent, Android platform privilege, root, vendor hardware, a device-specific lab method, or paid service access.

## Phase 0: Hackathon Demo Spine

Target date: 2026-10-10

Goal: make ForensiX look and behave like a coherent commercial product for the strongest owner-consented paths: Android agent collection, sealed evidence intake, parser runs, search, timeline, reporting, and analyst review.

Current implementation status:

| Status | Capability | Evidence |
| --- | --- | --- |
| Done | `.fxz` Android agent bundle upload, validation, and sealing | `POST /api/v1/cases/{case_id}/evidence-sources/import/agent-bundle` |
| Done | Agent bundle parser | Native parser `android.agent_bundle.v1` normalizes contacts, SMS, calls, apps, device metadata, and accessible files |
| Done | Agent artifacts visible in evidence flows | Parser output enters artifact search, timeline materialization, custody events, parser runs, and reports |
| Done | Evidence Twin UI path | UI has a dedicated no-ADB Android agent bundle import panel, source summary, record counts, and agent parser button |
| Done | Agent MediaStore breadth | Agent collects MediaStore images, video, audio, downloads, and readable shared-storage artifacts with SHA-256 where streams are readable |
| Done | Cloud breadth foundation | `/api/v1/integrations/cloud-services` exposes 50-plus services, five deep targets, artifact types, auth methods, and blocker classes |
| Done | Case-level media/OCR batch action | Media Map can trigger `/api/v1/cases/{case_id}/media/analyses/backfill`; image artifacts run through the existing OCR/EXIF worker, and video/audio receive explicit model-ready unavailable records |
| Done | Portable HTML report output | Report generation now emits PDF, JSON, CSV, and static HTML with evidence sources, parsed artifacts, timeline, and custody tables |
| Done | Local ML inference foundation | Image analysis runs OpenCV face boxes when available and generic ONNX classification when `FORENSIX_OBJECT_ONNX_MODEL` is configured; audio/video run local Whisper transcription when `FORENSIX_WHISPER_MODEL` and runtime are available |
| Done | Media detection/transcript UI | Evidence Explorer now shows media analysis for image, video, and audio artifacts, grouped face/object/speech detections, normalized face-region coordinates, class indexes, transcript text, and timestamped speech segments |
| Done | Case-level face grouping records and UI | Media face clustering stores per-face embeddings, deterministic person groups, cluster hashes, API list/rebuild endpoints, and a Media Map face groups panel |
| Done | YOLO-style object regions and stronger face embeddings | ONNX object adapter now records detector bounding boxes for YOLO/SSD-shaped outputs and attaches optional ONNX face embeddings to face-region details for downstream clustering |
| Done | CLIP-style image embeddings and gallery visual similarity | Configurable ONNX image-embedding detection, persisted `media_visual_embeddings` gallery records, cosine-distance similarity API, and Media Analysis visual-match panel |
| Blocked | Android APK rebuild verification | Local JDK exists, but Gradle distribution download from `services.gradle.org` timed out on this machine |

| Workstream | Build for demo | Acceptance check |
| --- | --- | --- |
| Android agent bundle intake | `.fxz` upload, validation, source status, record counts, parser run | Upload a bundle and see contacts, SMS, calls, apps, files, and metadata in artifacts |
| No-ADB transfer | Agent export flow with local `.fxz`; later add LAN transfer window with pairing code | Bundle can be imported without ADB |
| Artifact visibility | Normalize agent records into parser artifacts, FTS, timeline, report snapshot | Search finds agent SMS; timeline shows dated records; JSON/PDF report includes artifacts |
| Evidence integrity | Preserve sealed source hash, manifest hash, parser run hash, artifact hash, custody events | Repeated parser run is idempotent and report contains source provenance |
| Reporting | PDF/JSON/CSV plus static HTML portable report | Downloadable report opens without backend |
| UI polish | Surface agent bundle summary, parser run state, artifact facets, timeline | Examiner can demo end to end from one case |

## Phase 1: Unlocked Android Logical Acquisition

| Capability | Build or buy | Implementation detail | Blocker class |
| --- | --- | --- | --- |
| Contacts, SMS, calls, installed apps | Build | Agent collectors using Android content providers and package manager APIs | Platform permissions |
| Wi-Fi metadata | Build partial | Unrooted Android cannot read saved PSKs; collect visible networks, current network, and agent-declared unavailable status. Rooted/FFS parser handles `/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml`. | Platform |
| Bluetooth metadata | Build partial | Unrooted agent can collect bonded device names/classes through public APIs when permitted. Link keys require root/FFS parser for `bt_config.conf`. | Platform |
| Shared files/media | Build | Storage Access Framework and MediaStore collectors; hash files, MIME type, timestamps, scoped storage status | Platform permissions |
| Browser history | Build where accessible | Parse Chrome/Firefox/Edge SQLite history from rooted/backup/import sources; unrooted third-party app history is sandboxed | Platform |
| App inventory surfaces | Build | Record package name, version, SDKs, permissions, backup/debuggable flags, installer, source dir, collection surface map | None |

## Phase 2: Android FFS, Physical, And Locked Device Tracks

ForensiX can own the workflow, validation, import, parser, and reporting layers. Broad device access itself depends on chipset state, bootloader state, patch level, OEM security, and hardware.

| Capability | Build or buy | Implementation detail | Blocker class |
| --- | --- | --- | --- |
| Full file system from rooted devices | Build | Rooted ADB profile runner with allowlisted paths, per-profile manifests, hash ledger, and parser scheduling | Root/platform |
| Temporary root | Build framework, buy/source vetted method | Fill profile registry with documented lab profiles that declare device, build fingerprint, patch range, expected shell identity, commands, cleanup, and validation. Do not ship opaque exploit code in the core app. | Technical/legal |
| Qualcomm EDL/Firehose | Buy/license/import | Add loaders and raw image import only when the user supplies legally obtained programmer files; parse GPT, userdata images, and filesystem archives | Vendor license/hardware |
| MediaTek BROM/preloader | Buy/license/import | Integrate SP Flash Tool/libusb style acquisition only through external tool runner and sealed output import | Vendor license/hardware |
| Samsung Exynos selected methods | Buy/license/import | Support external extraction packages and Odin/download-mode metadata; parse sealed outputs | Vendor license/hardware |
| Locked Android extraction | Build capability matrix and import workflow | Detect model/build/patch/chipset and show supported external lab path; locked FBE devices generally require passcode, token, exploit, or vendor method | Platform/hardware |
| Passcode recovery | Build only for owned lab profiles and imported external results | Add hashcat/John job integration for recoverable legacy hashes or vendor-exported challenge material. Modern Android FBE passcode verification is TEE/gatekeeper-bound and not generally offline-crackable. | Platform/hardware/cost |

## Phase 3: Cloud Acquisition

Build OAuth/token-based connectors where the user provides credentials or exported data. Each connector must record account ID, scopes, provider API version, request ledger, response hashes, rate limits, and consent timestamp.

| Priority | Service | Depth target |
| --- | --- | --- |
| 1 | Google account | Drive metadata/files, Photos metadata/media export, Gmail metadata/messages, Maps Timeline/Takeout import, Android backup metadata where APIs expose it |
| 2 | WhatsApp | Google Drive backup discovery where authorized, local `msgstore` parser, exported chat parser, media correlation |
| 3 | iCloud | Photos, Drive files, contacts/calendar import through official or user-exported data |
| 4 | Microsoft | OneDrive, Outlook mail/calendar/contacts, Teams export import |
| 5 | Telegram | Account export parser and Bot/API collection where authorized |
| Breadth pack | 50 services | Start as import/connectors with common contract: provider, account, artifact type, timestamp, participants, file hashes. Add Dropbox, Box, Facebook, Instagram, X, Snapchat export, Signal export, Discord package, Slack export, LinkedIn export, TikTok export, Uber, Lyft, Amazon, PayPal, Venmo, banking CSV imports, Reddit, GitHub, Google Takeout modules, and common email IMAP. |

## Phase 4: Artifact Parsing And Deleted Data Recovery

| Capability | Build plan | Acceptance check |
| --- | --- | --- |
| Android core databases | Contacts, SMS/MMS, calls, downloads, media, calendar, browser history, notifications, Wi-Fi, Bluetooth, accounts from FFS imports | Parser registry lists coverage and produces normalized artifacts |
| App parsers | WhatsApp, Telegram, Signal where decrypted DB is available, Messenger, Instagram, Chrome, Firefox, Gmail caches, Maps, Photos, common launchers | Each parser has fixtures, source path hints, deleted-row handling |
| Deleted SQLite rows | Extend page/freeblock carving and WAL/journal parsing; mark `deleted` or `recovered` with confidence and source page offsets | Recovery report links carved row to artifact and timeline |
| Filesystem deleted recovery | Integrate PhotoRec/TestDisk controller and hash recovered files into evidence twin | External recovery run creates sealed recovered artifacts |
| Encrypted app databases | Detect SQLCipher/opaque DBs and require key material from agent/root/keychain/import; never fake decrypt | Parser failure states key requirement |

## Phase 5: Analysis Modules

| Module | Build plan | ML needed |
| --- | --- | --- |
| Timeline | Merge source artifact events, media EXIF, acquisition events, custody, cloud events, recovered records; add filters, gaps, confidence, timezone basis | No |
| Graph | Entities for phone/email/account/package/device/location; relationships from calls, SMS, app accounts, cloud data | No for graph, optional ML for entity resolution |
| Location | EXIF GPS, Google Timeline, Wi-Fi/Bluetooth sightings, app location DBs, map clustering | No |
| OCR | Tesseract path plus queue, language packs, confidence, bounding boxes, searchable text, redaction support | OCR engine yes |
| Face analysis | Local OpenCV face detection emits completed face count and normalized face regions; optional ONNX face embedding model attaches normalized vectors; case-level clustering groups detected faces into deterministic person groups with UI rebuild/list support | Yes |
| Object/media classification | Generic ONNX adapter supports simple image-classification vectors and YOLO/SSD-style detector outputs with normalized object regions, labels, thresholds, and class indexes; configurable CLIP-style embeddings now power gallery similarity | Yes |
| Speech | Local faster-whisper/openai-whisper transcription runs for audio/video when configured, storing transcript text and timestamped segments in detection details | Yes |

## Phase 6: Reporting, Viewer, And Enterprise Readiness

| Capability | Build plan |
| --- | --- |
| Broad exports | Keep PDF/JSON/CSV; add HTML portable viewer, XLSX, XML, STIX-like graph JSON, RSMF-like conversation export |
| Portable viewer | Static HTML bundle with embedded signed manifest, artifacts index, timeline, graph, thumbnails, and verification page |
| Evidence integrity | Add Merkle manifest over source chunks, artifacts, parser runs, reports, and review decisions; expose verify button in UI |
| Case collaboration | Reviewer roles, annotations, bookmarks, report approval workflow, immutable comments |
| Deployment | Docker compose, signed release bundles, local-only mode, network mode, backup/restore, license gate |
| MDM/enterprise | Optional Android Enterprise DPC companion for managed devices: policy-based collection grants, app inventory, compliance state, logs |

## Bang-For-Buck Ranking

| Rank | Feature | Why first |
| --- | --- | --- |
| 1 | Agent bundle parser and UI visibility | Implemented |
| 2 | Media/files collector | Implemented for MediaStore/shared-storage metadata plus case-level media analysis trigger |
| 3 | Browser/history/app parser pack | Next parser expansion |
| 4 | Portable HTML viewer | Implemented first static portable report; next add manifest verification page and richer artifact navigation |
| 5 | Google + WhatsApp cloud depth | Catalog implemented; connector/import implementations next |

## Next Build Queue

| Order | Slice | Concrete output |
| --- | --- | --- |
| 1 | OCR maturity | Implemented case-level batch queue into current Tesseract-capable worker; next add bounding boxes, language-pack selection, and OCR search facets |
| 2 | Face/object/speech analysis | Implemented concrete local inference, UI panels for OpenCV face regions, generic ONNX image labels, YOLO/SSD-style object regions, optional ONNX face embeddings, Whisper transcripts, case-level face clustering, and gallery-level CLIP-style visual similarity |
| 3 | Portable viewer | First static HTML report implemented; next add embedded manifest, offline verification page, thumbnails, and graph pane |
| 4 | Browser history pack | Chrome, Firefox, Edge, Samsung Internet SQLite parsers for rooted/backup/import sources |
| 5 | Cloud deep imports | Google Takeout expansion, WhatsApp export/cloud metadata parser, Microsoft Graph connector skeleton, Telegram export parser, iCloud export importer |

## Hard Limits To Represent Honestly

| Requested parity item | Commercial-ready ForensiX stance |
| --- | --- |
| Universal locked Android extraction | Not a universal software feature. Implement compatibility matrix, external-tool import, and lab validation records. |
| Modern Android passcode recovery | Only for legacy/recoverable material or external vendor output. Modern FBE/Gatekeeper/TEE designs block general offline recovery. |
| Broad physical extraction | Build image import, parser, validation, and selected hardware integrations. Broad coverage requires vendor loaders, dongles, paid licenses, and lab validation. |
| App sandbox escape on stock unrooted Android | Not generally available without platform exploit, DPC privilege, debug/backup flags, or user-granted export surfaces. |

