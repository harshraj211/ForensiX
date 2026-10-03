# Cloud export imports — implemented 2026-10-01

## Delivery scope

Five **offline export import** flows share the existing sealed evidence, working-copy,
parser-run, custody, search, timeline, correlation and reporting infrastructure.
There are no network calls, OAuth connectors, account downloads or credential collection in
these flows. `cloud_service_catalog()` now describes the implemented formats separately
from the remaining live connector targets.

| Provider | Accepted records | Preserved details | Current format boundaries |
| --- | --- | --- | --- |
| Google | Takeout Chrome `Browser History`; Locations `locations` with E7 coordinates; legacy `timelineObjects`; on-device `semanticSegments` visit/activity/path points; My Activity JSON arrays; Photos `photoTakenTime`; Gmail MBOX/EML; contacts CSV/VCF; calendars ICS | URLs, client IDs, original microsecond timestamps, coordinates, accuracy, activity products, photo metadata, MIME attachment hashes, calendar recurrence | Other Takeout schemas, HTML activity, Chrome bookmarks, and live Android/Drive backups are not decoded/downloaded |
| WhatsApp | Android dash-delimited and iOS bracket-delimited TXT exports; ZIP with chats/media; recognized plaintext `msgstore` message and `wa_contacts` SQLite schemas through the existing WhatsApp adapter | Multiline messages, sender, source line, system events, selected DMY/MDY, timezone basis, attachment references/resolution, omitted-media flags; embedded SQLite decoder ID/version | `.crypt12`–`.crypt15` and other encrypted backups are not decrypted; database schema coverage is that of the existing versioned adapter; a SQLite WAL is not merged |
| Microsoft | Offline Graph JSON objects/arrays/`value` collections for mail, contacts, events, drive items; EML/MBOX; contact CSV/VCF; ICS | Message and conversation IDs, recipients, bodies, attachment metadata, calendar start/end/attendees/recurrence, drive IDs/sizes/MIME/hash metadata | No live Graph requests, PST/OST decoding or file fetching from `webUrl`; Graph calendar Windows/custom timezone names remain undated when not recognized as IANA or UTC |
| Telegram | Desktop account `result.json` and single-chat JSON, optionally in ZIP | Account/contacts, rich-text segments, message and sender IDs, replies, service actions, file/photo references, shared coordinates, conversation IDs | HTML exports and live Telegram API acquisition are not implemented |
| iCloud | Exported VCF contacts, ICS calendars, EML/MBOX mail, compatible contact CSV and photo CSV with `Filename` / `Photo Taken Date`, optionally in ZIP | Contact properties/multiple emails/phones, folded lines, calendar UID/recurrence/TZID, MIME attachment metadata, source CSV columns | No iCloud account login, device-backup download, arbitrary Apple privacy-export schema parsing or encrypted-backup decoding |

All accepted records are fixture tested. This does not establish compatibility with every
provider export version. No live account or representative customer export was used for validation.

## Use in the UI

Open a case's **Evidence Twin** page and find **Cloud export import**.

1. Choose Google, WhatsApp, Microsoft, Telegram or iCloud.
2. Select a ZIP or supported standalone document/database.
3. Set the **source** IANA timezone for timestamps without offsets. The initial suggestion
   comes from the browser timezone; it must reflect the exported data's timezone.
4. For WhatsApp, choose DMY or MDY explicitly. There is no date-order guessing.
5. Import. A sealed master, verified working copy and versioned parser run are created automatically.

The result shows record-class counts, file counts, undated records, malformed/unsupported
files, original SHA-256 and parser-run hash. Source cards reload persisted summaries after
navigation/restart. Parsed artifact cards show provider fields/provenance and attachment
resolution. The same artifacts are searchable and included in existing case reports and
portable HTML output.

Media bytes remain in the original sealed ZIP. ZIP inventory artifacts carry each member's
SHA-256, byte count and parse status. Chat attachment links carry exact matching member paths
and hashes; absent or ambiguous references are identified. This slice does not create media
analysis records or individual member download endpoints. MIME attachments are inventoried
and hashed after transfer decoding; their source EML/MBOX remains sealed.

## API

`POST /api/v1/cases/{case_id}/evidence-sources/import/cloud-export`

Multipart fields:

| Field | Meaning |
| --- | --- |
| `source` | Uploaded original ZIP/JSON/TXT/CSV/VCF/ICS/EML/MBOX/plaintext DB |
| `provider` | `google`, `whatsapp`, `microsoft`, `telegram`, `icloud` |
| `source_timezone` | IANA name, default `UTC`; applies only where a source offset is absent |
| `date_order` | `DMY` (default) or `MDY`, used for WhatsApp text exports |

Returns `evidence_source`, `parser_run`, `summary`. HTTP 201 means the original was sealed;
**always inspect `parser_run.status`**. Unsafe archives, unknown schemas and unsupported-only
inputs produce an auditable failed run with zero normalized artifacts. Recognized documents
in a mixed archive can complete with a visible issue list for malformed/unsupported members.
Configuration/size/extension failures reject intake before sealing.

`GET /api/v1/cases/{case_id}/evidence-sources/{source_id}/cloud-export-summary`
reloads source configuration, latest parser run and persisted counts. Manifest hashes are
checked before provider configuration is used. The legacy Takeout POST route delegates to
this pipeline and returns a real persisted timeline-event count rather than inserting events directly.

Standard native-parser replay recognizes cloud sources from their sealed manifests. Replay
on the **same** working copy/parser version reuses the existing run. Separate evidence imports
remain separate sources; there is no automatic case-wide deduplication.

## Integrity, bounds and time handling

- Session authentication, CSRF protection, case authorization, acquisition+analysis permissions
  and case-state checks precede intake processing.
- Upload maximum: 2 GiB. Standalone and parsed text/JSON/MBOX members: 64 MiB.
- ZIP extraction uses `SafeArchiveExtractor`: 10,000 members, 512 MiB/member, 2 GiB total,
  compression ratio 200, depth 20. Traversal, links, duplicate paths and encrypted ZIPs are rejected.
- Generated temporary filenames are used; multipart filenames are labels, not filesystem paths.
- The limit is 100,000 **normalized artifacts**, including inventory and summary records.
  Oversized inputs fail rather than silently truncate. Split larger exports into bounded parts.
- Original bytes are sealed before examination. Parsers use verified working copies and
  record whole-input/member hashes, source locators, decoder versions and custody events.
- Explicit offsets and Unix epochs normalize to UTC. Floating timestamps record the examiner
  timezone; invalid/date-only timestamps remain undated. Ambiguous/gap DST floating timestamps
  remain undated. ICS TZID and Graph IANA timestamps retain their source zone fields;
  custom timezone definitions and recurrence expansion are outside current coverage.
- Contact/calendar parsing handles UTF-8, folded lines and standard backslash escapes.
  Legacy vCard quoted-printable/alternate charsets and custom `VTIMEZONE` definitions are not decoded.
- Provider HTML/body text is retained as evidence text and rendered through normal escaped
  report/UI paths. External URLs and attachment references are never fetched.
- Original hashes establish byte consistency, not provider authenticity, account ownership,
  source completeness or proof that a sender is a specific person.

## Implementation map

| Responsibility | Code |
| --- | --- |
| Provider parsers, bounds, inventory, attachment links, time conversion | `forensic/src/forensix_forensic/extractors/cloud/exports.py` |
| Intake authorization, bounded stream, seal/copy/parse orchestration, persisted summary | `server/src/forensix_server/evidence_twin/cloud_exports.py` |
| Sealed provider configuration and manifest-based parser replay | `server/src/forensix_server/evidence_twin/service.py`, `examination.py` |
| Timezone/source time retained in materialized timeline | `server/src/forensix_server/evidence/timeline.py` |
| Multipart API and compatibility Takeout route | `apps/api/src/forensix_api/routers/evidence_sources.py`, `takeout.py` |
| Five-provider controls and persisted source/artifact views | `apps/web/src/features/evidence/TakeoutImportPanel.tsx`, `features/evidence-twin/EvidenceTwinPage.tsx` |

## Validation

- 37 parser tests: provider formats, UTF-8/folding, SQLite, MIME hashes, timestamp/DST behavior,
  attachment linking, malformed input, path traversal, record/byte limits and provenance spoofing.
- 12 API integration tests: all five providers through seal/copy/parse/search/timeline/report,
  persistent summaries, same-copy replay, legacy Takeout compatibility, CSRF, case-state/permission
  gates and manifest-tampering rejection.
- Web component tests cover provider selection/import results, failed-parser visibility and
  closed-case controls. TypeScript, targeted Python lint/type checks and the production web build
  are also checked. Reporting and correlation regression tests pass.

## Format references

Primary provider descriptions: [Google Takeout](https://support.google.com/accounts/answer/3024190),
[Microsoft Graph message resource](https://learn.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0),
[Telegram export](https://telegram.org/blog/export-and-more), and
[Apple export/archive guidance](https://support.apple.com/en-ie/108306).
The format list above states implemented parser coverage; these sources do not imply universal schema compatibility.
