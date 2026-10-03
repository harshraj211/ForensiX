# Smart Switch archive import coverage

## Accepted intake

Use Evidence Twin's **Import device backup** control with a ZIP-compatible
`.sbu` file, or a ZIP whose file name or member paths contain `SmartSwitch`. The intake
inspects path safety, member count, expanded size and encrypted-member flags;
seals the original bytes; and runs the parser on a verified working copy.
An unrelated ZIP is retained as a generic backup archive and is not labeled
as Smart Switch.

For a Smart Switch PC backup directory, use **Smart Switch PC backup folder**
and select one saved backup folder in the browser. The server streams the
selected files into a bounded ZIP, records every relative path, SHA-256 and
size in the sealed source manifest, and examines a verified copy of that ZIP.
The sealed source is this generated package; it is not a byte-for-byte image
of the original directory. No server filesystem path is accepted from the
browser.

## Normalized records

| Member content | Output |
| --- | --- |
| vCard `.vcf` | Names, phone numbers and email addresses |
| CSV/TSV and JSON with readable contact, message, call or setting fields | Searchable contact, communication and system artifacts |
| Samsung-shaped `sms_restore.json` and UTF-16/semicolon contact CSV | Message times, addresses, bodies, names, multiple phone numbers and email addresses |
| Settings XML entries | Key and value artifacts; credential-like values are withheld |
| Standard Android contacts, telephony, call, calendar and downloads SQLite schemas | Existing versioned Android parser artifacts |
| Images, audio, video and PDF members | File artifacts with MIME type, size and SHA-256 |
| Proprietary or unrecognized members, including opaque `.spbm` | Preserved file artifacts with hash, signature and explicit unsupported status |

Message attachment references are linked to matching media member names where
present. Every normalized record stores its archive member path, SHA-256 and
size. The parser emits a summary with per-type counts, unsupported members and
parse issues. The import response reports parser run ID, status and artifact
count; records enter the normal case search, timeline and reporting pipeline.

## Tested boundary

The automated fixtures cover folder upload with traversal rejection and member
hashes, UTF-16 contact CSV, Samsung-shaped SMS JSON, VCF contacts, SQLite SMS, CSV messages with an
attachment, JSON calls, XML settings with a redacted credential, media hashing,
unsupported member reporting and API persistence. It is a synthetic
ZIP-compatible export, not a captured Samsung PC backup.

Proprietary `.spbm` payloads without a recognized embedded format, encrypted
members and vendor-specific databases are not decoded by this parser. Samsung
Smart Switch can save contacts as both `.spbm` and CSV; selecting that export
option gives the parser readable contact records. No live Samsung device backup
transport is implemented. A representative, redacted native export is required
to validate real-version compatibility and map opaque formats.

## Format references

- [Samsung Smart Switch PC backup help](https://www.samsungsvc.co.kr/solution/38683?sns=Y) documents PC folder locations, supported categories and media formats.
- [Samsung contact export instructions](https://www.samsungsvc.co.kr/solution/39700) document the `.spbm` plus CSV option.
- [Smart Switch team reply](https://r1.community.samsung.com/t5/%EC%84%9C%EB%B9%84%EC%8A%A4-%EA%B8%B0%ED%83%80/%EC%8A%A4%EB%A7%88%ED%8A%B8%EC%8A%A4%EC%9C%84%EC%B9%98-%EC%A3%BC%EC%86%8C%EB%A1%9D-%EB%B0%B1%EC%97%85%ED%8C%8C%EC%9D%BC-%EC%A7%88%EB%AC%B8/m-p/31112516/highlight/true) states that native PC contacts are `.spbm` and can be converted to CSV in Smart Switch.
