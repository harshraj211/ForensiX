# ForensiX Android Application Artifact Framework

## Overview

The ForensiX **Unified Android Application Artifact Framework** provides a contract-driven, version-resilient architecture for identifying, parsing, and normalizing application artifacts acquired from Android devices.

Rather than relying on brittle hardcoded assumptions or one-off script parsers, the framework establishes explicit lifecycle stages and standard status classifications for every artifact target:

```text
Artifact Discovery
        ↓
Artifact Classification
        ↓
Format & Schema Detection
        ↓
Parsing & B-Tree Carving
        ↓
Normalization & Timestamp Provenance
        ↓
Relationship Correlation (Person / Contact / Account / Conversation / Message / Media)
        ↓
Timeline Event Generation
        ↓
Evidence Twin & Search Indexing
```

---

## Adapter Contract & Interface

Every application adapter inherits from `BaseApplicationAdapter` (or implements `ApplicationAdapter`) in [adapter.py](file:///C:/Users/harsh/ForensiX/forensic/src/forensix_forensic/android_artifacts/adapter.py):

### Metadata Requirements (`AdapterMetadata`)
- `parser_id`: Unique identifier (e.g. `android.whatsapp.message`).
- `name`: Human-readable title.
- `version`: SemVer string (e.g. `2.1.0`).
- `package_name`: Canonical Android package name (e.g. `com.whatsapp`).
- `application_name`: Display app title (e.g. `WhatsApp`).
- `supported_schema_families`: Tuple of supported schemas (e.g. `("whatsapp_v14_message", "whatsapp_legacy_message")`).
- `supported_formats`: Input file formats (e.g. `("sqlite", "xml", "json")`).

### Explicit Parse Status Classifications (`AdapterParseStatus`)
- **`SUPPORTED`**: Schema recognized and records parsed completely.
- **`PARTIAL`**: Partial schema match or partial record extraction.
- **`UNSUPPORTED`**: File format or structure is unsupported by this adapter.
- **`ENCRYPTED_UNPARSED`**: Database or archive is encrypted (e.g. SQLCipher or `.crypt12/14/15`). 0 false records emitted.
- **`CORRUPTED`**: Database header or B-Tree pages are damaged/corrupted.
- **`UNKNOWN_SCHEMA`**: Recognized database format but unhandled schema version.

---

## Supported Application Adapters

### 1. WhatsApp Reference Adapter (`WhatsAppAdapter`)
- **Package**: `com.whatsapp`
- **Supported Schemas**: `message` (v14+), `messages` (legacy), `wa_contacts` (`wa.db`), `.crypt12/.crypt14/.crypt15` encrypted backups.
- **Key Features**:
  - JID cross-resolution via `jid` table.
  - Contact display name resolution via `wa_contacts`.
  - Media correlation via `message_media` table (`file_path`, `file_hash`, `mime_type`).
  - Quoted message resolution via `message_quoted`.
  - Non-destructive B-Tree deleted cell carving via `SQLiteCarver`.
  - Encrypted backup classification with `encrypted=True` and 0 false message records.

### 2. Telegram Adapter (`TelegramAdapter`)
- **Package**: `org.telegram.messenger`
- **Supported Schemas**: `userconf.xml` (account metadata), `cache4.db` (`messages`, `messages_v2`, `dialogs`, `users`).
- **Key Features**:
  - Pure-Python MTProto / Type Language (TL) binary blob deserialization for encoded message payloads (`data` column).
  - XML configuration parsing for account `user_id`, phone number, and user profile names.
  - Plaintext and binary fallback handling.

### 3. Signal Adapter (`SignalAdapter`)
- **Package**: `org.thoughtcrime.securesms`
- **Supported Schemas**: SQLCipher encrypted `signal.db` vs plaintext/decrypted exports (`sms`, `mms`, `recipient`, `thread`).
- **Key Features**:
  - Header inspection detecting SQLCipher encrypted database files.
  - Encrypted databases tagged as `ENCRYPTED_UNPARSED` with `encrypted=True` and 0 false message extractions.
  - Plaintext/decrypted schema normalization for SMS/MMS tables.

### 4. Android System Database Adapters
- **Contacts Provider (`AndroidContactsAdapter`)**: Parses `contacts2.db` (`raw_contacts`, `data`, `mimetypes`).
- **Call Log (`AndroidCallLogAdapter`)**: Parses `calllog.db` (`calls`).
- **Telephony Provider (`AndroidTelephonyAdapter`)**: Parses `mmssms.db` / `telephony.db` (`sms`, `pdu`, `part`, `addr`).

---

## Forensic Relationships & Entity Graph

[relationships.py](file:///C:/Users/harsh/ForensiX/forensic/src/forensix_forensic/android_artifacts/relationships.py) defines normalized nodes and directed relationships preserving full source provenance:

```text
Person ↕ Contact ↕ Account ↕ Conversation ↕ Message ↕ Media ↕ Artifact
```

Every `ForensicRelationship` includes:
- `source_entity`: Identifier of source node.
- `target_entity`: Identifier of target node.
- `relationship_type`: `sender`, `recipient`, `member_of`, `attached_to`, `quoted_by`, `belongs_to`.
- `source_database`: Origin SQLite database file.
- `source_table`: Origin table name.
- `source_row_id`: Primary key ID in origin table.

---

## Adding New Application Adapters

To add a new application adapter:
1. Create adapter class subclassing `BaseApplicationAdapter` in `applications.py` (or dedicated module).
2. Set `metadata = AdapterMetadata(...)`.
3. Implement `parse_adapter(self, reader, context)` returning `AdapterParseResult`.
4. Register the adapter instance in `android_parser_registry()` in `registry.py`.
5. Add unit tests with synthetic database fixtures in `tests/`.
