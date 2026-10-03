"""Bounded offline cloud exports. No network calls or credential acquisition."""

import csv
import io
import json
import mailbox
import mimetypes
import re
import tempfile
import zipfile
from dataclasses import replace
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from zoneinfo import ZoneInfo

from forensix_forensic.evidence_io import (
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    SafeArchiveExtractor,
    SafeSQLiteReader,
)
from forensix_forensic.storage import EvidenceStore

PROVIDERS = frozenset({"google", "whatsapp", "microsoft", "telegram", "icloud"})
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACTS = 100_000
VERSION = "1.0.0"


def _geo_point(value: Any) -> tuple[float | None, float | None]:
    if isinstance(value, str) and value.startswith("geo:"):
        lat, lon = map(float, value[4:].split(","))
        return lat, lon
    return None, None


def _local_utc(parsed: datetime, zone: ZoneInfo) -> datetime | None:
    a = parsed.replace(tzinfo=zone, fold=0)
    b = parsed.replace(tzinfo=zone, fold=1)
    if (
        a.utcoffset() != b.utcoffset()
        or a.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != parsed
    ):
        return None
    return a.astimezone(UTC)


class CloudExportError(ValueError):
    """Unsupported input, invalid configuration, or exceeded import limit."""


class CloudExportParser:
    """One explicitly selected provider, with an auditable member inventory."""

    def __init__(self, provider: str, *, source_timezone: str = "UTC", date_order: str = "DMY"):
        if provider not in PROVIDERS:
            raise CloudExportError("Unknown cloud export provider")
        if date_order not in {"DMY", "MDY"}:
            raise CloudExportError("Date order must be DMY or MDY")
        try:
            self.zone = ZoneInfo(source_timezone)
        except (ValueError, KeyError) as exc:
            raise CloudExportError("Unknown IANA source timezone") from exc
        self.provider = provider
        self.source_timezone = source_timezone
        self.date_order = date_order
        self.metadata = ParserMetadata(
            parser_id=f"cloud.{provider}.export",
            name=f"{provider.title()} offline export",
            version=VERSION,
            artifact_categories=(
                "communication",
                "contact",
                "location",
                "file",
                "system",
                "application",
            ),
            required_tables=frozenset(),
            access_level="logical",
            input_formats=("cloud-export",),
            description="Offline exports; timestamps retain source values and examiner settings.",
        )
        self.artifacts: list[ParsedArtifact] = []
        self.inventory: list[dict[str, Any]] = []

    def can_parse(self, source_locator: str) -> bool:
        return True  # This parser is selected explicitly, never through general discovery.

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        self.artifacts = []
        self.inventory = []
        with tempfile.TemporaryDirectory(prefix="cloud-export-") as temp:
            store = EvidenceStore(Path(temp))
            if zipfile.is_zipfile(path):
                members = SafeArchiveExtractor().extract(path, store, "members")
                inputs = [
                    (
                        m.original_name,
                        store.resolve(m.storage_key, require_file=True),
                        m.sha256,
                        m.size_bytes,
                    )
                    for m in members
                ]
            else:
                if path.stat().st_size > MAX_DOCUMENT_BYTES:
                    raise CloudExportError("Standalone document exceeds 64 MiB")
                inputs = [
                    (
                        context.source_label,
                        path,
                        sha256(path.read_bytes()).hexdigest(),
                        path.stat().st_size,
                    )
                ]
            for name, member_path, digest, size in inputs:
                if len(name) > 900:
                    raise CloudExportError("Export member name exceeds 900 characters")
                entry: dict[str, Any] = {
                    "name": name,
                    "sha256": digest,
                    "bytes": size,
                    "status": "unsupported",
                    "artifact_count": 0,
                }
                before = len(self.artifacts)
                self.member_name = name
                self.member_sha256 = digest
                try:
                    recognized = self._document(member_path, name, size, context)
                    if recognized:
                        entry["status"] = "parsed"
                    elif (mimetypes.guess_type(name)[0] or "").split("/")[0] in {
                        "image",
                        "audio",
                        "video",
                    }:
                        entry["status"] = "preserved_file"
                    entry["artifact_count"] = len(self.artifacts) - before
                except CloudExportError:
                    raise
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    UnicodeError,
                    OverflowError,
                    OSError,
                    RecursionError,
                ) as exc:
                    del self.artifacts[before:]
                    entry.update(
                        status="malformed", error=f"{type(exc).__name__}: {str(exc)[:300]}"
                    )
                self.inventory.append(entry)
                self._emit(
                    "file",
                    "cloud_export_member",
                    name,
                    f"{size} bytes; {entry['status']}",
                    None,
                    "member",
                    dict(entry),
                    status="unverified",
                )
        # Attachments are resolved only inside the uploaded archive. No URL is fetched.
        indexed = {item["name"]: item for item in self.inventory}
        for artifact in self.artifacts:
            reference = artifact.metadata.get(
                "attachment_reference", artifact.metadata.get("attachment")
            )
            if not isinstance(reference, str) or not reference:
                continue
            origin = PurePosixPath(str(artifact.metadata.get("member_name", ""))).parent
            candidates = {reference, str(origin / reference)} & indexed.keys()
            if len(candidates) == 1:
                linked = indexed[candidates.pop()]
                artifact.metadata["attachment_resolution"] = "matched"
                artifact.metadata["attachment_member"] = {
                    key: linked[key] for key in ("name", "sha256", "bytes")
                }
            else:
                artifact.metadata["attachment_resolution"] = (
                    "missing" if not candidates else "ambiguous"
                )
        parsed_count = sum(i["artifact_count"] for i in self.inventory)
        if not any(i["status"] == "parsed" for i in self.inventory):
            raise CloudExportError(
                "No recognized provider records. Supply a supported export; encrypted backups, PST, and HTML chat exports are not decoded."
            )
        counts: dict[str, int] = {}
        for artifact in self.artifacts:
            if artifact.subtype != "cloud_export_member":
                counts[artifact.subtype] = counts.get(artifact.subtype, 0) + 1
        warnings = [
            f"{i['name']}: {i['status']}"
            for i in self.inventory
            if i["status"] in {"unsupported", "malformed"}
        ]
        self.member_name = context.source_label
        self.member_sha256 = context.source_sha256
        self._emit(
            "system",
            "cloud_export_summary",
            f"{self.provider.title()} export import",
            f"{parsed_count} parsed records in {len(self.inventory)} files",
            None,
            "summary",
            {
                "provider": self.provider,
                "mode": "offline_export",
                "source_timezone": self.source_timezone,
                "date_order": self.date_order,
                "parsed_count": parsed_count,
                "record_counts": counts,
                "member_count": len(self.inventory),
                "warnings": warnings,
                "unsupported_count": sum(i["status"] == "unsupported" for i in self.inventory),
                "malformed_count": sum(i["status"] == "malformed" for i in self.inventory),
                "preserved_file_count": sum(
                    i["status"] == "preserved_file" for i in self.inventory
                ),
                "undated_count": sum(
                    a.event_time is None and a.subtype != "cloud_export_member"
                    for a in self.artifacts
                ),
                "limitations": [
                    "Offline source export; completeness and account identity are unverified.",
                    "No encrypted-backup decryption or live cloud acquisition.",
                    "Calendar recurrence retained; occurrences are not expanded.",
                ],
            },
            status="unverified",
        )
        return self.artifacts

    def _emit(
        self,
        category: str,
        subtype: str,
        title: Any,
        content: Any,
        raw_time: Any,
        locator: str,
        metadata: dict[str, Any],
        *,
        status: Literal["active", "unverified"] = "active",
        source_time: Any = None,
    ) -> None:
        if len(self.artifacts) >= MAX_ARTIFACTS:
            raise CloudExportError("Export exceeds 100,000 normalized artifacts; split the export")
        event_time, basis = self._time(raw_time)
        text = str(content or "")
        # Never treat malformed or absent timestamps as the acquisition time.
        data = {
            **metadata,
            "provider": self.provider,
            "application": self.provider,
            "original_time": str(source_time if source_time is not None else raw_time)
            if source_time is not None or raw_time is not None
            else None,
            "timezone_basis": basis,
            "member_sha256": self.member_sha256,
            "member_name": self.member_name,
            "source_timezone": self.source_timezone,
            "date_order": self.date_order,
            "content": text,
        }
        # Existing case correlation reads these canonical fields, while provider fields remain.
        if "conversation_id" in metadata:
            data["thread_id"] = str(metadata["conversation_id"])
        if subtype == "whatsapp_export_message" and metadata.get("sender"):
            data["sender_name"] = metadata["sender"]
        if category == "contact":
            data["display_name"] = str(title or "")
            email_values = metadata.get("emailAddresses", metadata.get("emails", []))
            if isinstance(email_values, list):
                data["emails"] = [
                    {"address": value} if isinstance(value, str) else value
                    for value in email_values
                ]
            phone_values = metadata.get("businessPhones", metadata.get("phones", []))
            if isinstance(phone_values, list):
                data["phones"] = [
                    {"number": value} if isinstance(value, str) else value for value in phone_values
                ]
            if metadata.get("phone_number"):
                data["number"] = metadata["phone_number"]
        if subtype == "microsoft_mail":
            sender = (metadata.get("from") or {}).get("emailAddress", {})
            data["sender_name"] = sender.get("name")
            recipients = (
                (metadata.get("toRecipients") or [])
                + (metadata.get("ccRecipients") or [])
                + (metadata.get("bccRecipients") or [])
            )
            data["emails"] = [
                sender,
                *[recipient.get("emailAddress", {}) for recipient in recipients],
            ]
        self.artifacts.append(
            ParsedArtifact(
                category=category,
                subtype=subtype,
                title=str(title or subtype)[:512],
                summary=(text or str(title or subtype))[:2000],
                content=text,
                event_time=event_time,
                source_locator=f"{self.member_name}#{locator}"[:1024],
                status=status,
                confidence="medium",
                metadata=data,
            )
        )

    def _time(self, value: Any) -> tuple[datetime | None, str]:
        if value is None or value == "":
            return None, "No timestamp in source"
        try:
            if isinstance(value, (int, float)) or str(value).isdigit():
                number = float(value)
                if abs(number) >= 1e14:
                    number /= 1e6
                elif abs(number) >= 1e11:
                    number /= 1e3
                return datetime.fromtimestamp(number, UTC), "Unix epoch normalized to UTC"
            text = str(value)
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text) or re.fullmatch(r"\d{8}", text):
                return None, "Date-only value; no event time inferred"
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                # Reject DST gaps/overlaps rather than guessing a fold.
                normalized = _local_utc(parsed, self.zone)
                if normalized is None:
                    return None, "Ambiguous/nonexistent local time; retained without normalization"
                return normalized, f"Examiner-selected timezone {self.source_timezone}"
            return parsed.astimezone(UTC), "Explicit source timezone offset"
        except (ValueError, OverflowError, OSError, TypeError):
            return None, "Invalid timestamp retained without normalization"

    def _document(self, path: Path, name: str, size: int, context: ParserContext) -> bool:
        suffix = Path(name).suffix.lower()
        if self.provider == "whatsapp" and suffix in {".db", ".sqlite", ".sqlite3"}:
            from forensix_forensic.android_artifacts import WhatsAppMessageParser

            parser = WhatsAppMessageParser()
            with SafeSQLiteReader(path) as reader:
                if not parser.can_parse(reader.table_names()):
                    return False
                records = parser.parse(
                    reader, replace(context, input_locator=name, input_sha256=self.member_sha256)
                )
            for record in records:
                if len(self.artifacts) >= MAX_ARTIFACTS:
                    raise CloudExportError("Export artifact limit exceeded")
                self.artifacts.append(
                    replace(
                        record,
                        source_locator=f"{name}#{record.source_locator}"[:1024],
                        metadata={
                            **record.metadata,
                            "provider": self.provider,
                            "member_sha256": self.member_sha256,
                            "member_name": name,
                            "decoder_id": parser.metadata.parser_id,
                            "decoder_version": parser.metadata.version,
                        },
                    )
                )
            return True
        if suffix not in {".json", ".txt", ".csv", ".vcf", ".ics", ".eml", ".mbox"}:
            return False
        if size > MAX_DOCUMENT_BYTES:
            raise CloudExportError(f"Document {name} exceeds 64 MiB")
        if suffix in {".eml", ".mbox"} and self.provider in {"google", "microsoft", "icloud"}:
            if suffix == ".eml":
                self._email(
                    BytesParser(policy=policy.default).parsebytes(path.read_bytes()), "message"
                )
            else:
                box = mailbox.mbox(path, create=False)
                try:
                    for index, message in enumerate(box):
                        self._email(
                            BytesParser(policy=policy.default).parsebytes(message.as_bytes()),
                            f"message/{index}",
                        )
                finally:
                    box.close()
            return True
        text = path.read_text(encoding="utf-8-sig")
        if suffix in {".vcf", ".ics"} and self.provider != "whatsapp":
            return self._cards(text, suffix)
        if suffix == ".txt" and self.provider == "whatsapp":
            return self._whatsapp(text)
        if suffix == ".csv" and self.provider in {"google", "microsoft", "icloud"}:
            return self._csv(text)
        if suffix == ".json":
            data = json.loads(text)
            if self.provider == "google":
                return self._google(data)
            if self.provider == "telegram":
                return self._telegram(data)
            if self.provider == "microsoft":
                return self._microsoft(data)
        return False

    def _google(self, data: Any) -> bool:
        recognized = False
        if isinstance(data, dict) and "Browser History" in data:
            recognized = True
            for i, item in enumerate(data["Browser History"]):
                # Takeout time_usec is Unix microseconds, unlike Chrome SQLite's 1601 epoch.
                raw = float(item["time_usec"]) / 1e6 if item.get("time_usec") is not None else None
                self._emit(
                    "application",
                    "google_browser_visit",
                    item.get("title", item.get("url")),
                    item.get("url"),
                    raw,
                    f"Browser History/{i}",
                    {
                        "url": item.get("url"),
                        "client_id": item.get("client_id"),
                        "raw_time_usec": item.get("time_usec"),
                    },
                )
        if isinstance(data, dict) and "locations" in data:
            recognized = True
            for i, item in enumerate(data["locations"]):
                lat = item.get("latitudeE7", 0) / 1e7 if "latitudeE7" in item else None
                lon = item.get("longitudeE7", 0) / 1e7 if "longitudeE7" in item else None
                timestamp = item.get("timestamp", item.get("timestampMs"))
                if isinstance(timestamp, dict):
                    timestamp = timestamp.get("epoch_ms")
                self._location(item, lat, lon, timestamp, f"locations/{i}")
        if isinstance(data, dict) and "timelineObjects" in data:
            recognized = True
            for i, obj in enumerate(data["timelineObjects"]):
                for kind in ("placeVisit", "activitySegment"):
                    if kind in obj:
                        item = obj[kind]
                        location = item.get("location", item.get("startLocation", {}))
                        lat = location.get("latitudeE7")
                        lon = location.get("longitudeE7")
                        duration = item.get("duration", {})
                        self._location(
                            item,
                            lat / 1e7 if lat is not None else None,
                            lon / 1e7 if lon is not None else None,
                            duration.get("startTimestamp", duration.get("startTimestampMs")),
                            f"timelineObjects/{i}/{kind}",
                        )
        if isinstance(data, dict) and isinstance(data.get("semanticSegments"), list):
            recognized = True
            for i, segment in enumerate(data["semanticSegments"]):
                if isinstance(segment.get("visit"), dict):
                    candidate = segment["visit"].get("topCandidate", {})
                    lat, lon = _geo_point(candidate.get("placeLocation"))
                    self._location(
                        segment, lat, lon, segment.get("startTime"), f"semanticSegments/{i}/visit"
                    )
                if isinstance(segment.get("activity"), dict):
                    lat, lon = _geo_point(segment["activity"].get("start"))
                    self._location(
                        segment,
                        lat,
                        lon,
                        segment.get("startTime"),
                        f"semanticSegments/{i}/activity",
                    )
                for j, point in enumerate(segment.get("timelinePath", [])):
                    lat, lon = _geo_point(point.get("point"))
                    self._location(
                        point, lat, lon, point.get("time"), f"semanticSegments/{i}/timelinePath/{j}"
                    )
        if isinstance(data, dict) and "photoTakenTime" in data:
            recognized = True
            self._emit(
                "file",
                "google_photo_metadata",
                data.get("title"),
                data.get("description"),
                data["photoTakenTime"].get("timestamp"),
                "photo",
                {
                    "url": data.get("url"),
                    "geoData": data.get("geoData"),
                    "creationTime": data.get("creationTime"),
                },
            )
        if isinstance(data, list) and (
            not data
            or all(isinstance(item, dict) and "title" in item and "time" in item for item in data)
        ):
            recognized = True
            for i, item in enumerate(data):
                self._emit(
                    "application",
                    "google_activity",
                    item.get("title"),
                    item.get("titleUrl", item.get("title")),
                    item.get("time"),
                    f"activity/{i}",
                    {
                        "url": item.get("titleUrl"),
                        "products": item.get("products"),
                        "subtitles": item.get("subtitles"),
                    },
                )
        return recognized

    def _location(
        self, item: dict[str, Any], lat: Any, lon: Any, raw_time: Any, locator: str
    ) -> None:
        if lat is not None and lon is not None and not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError("Coordinates outside latitude/longitude ranges")
        self._emit(
            "location",
            "google_location",
            "Google location",
            f"Latitude {lat}; longitude {lon}",
            raw_time,
            locator,
            {
                "latitude": lat,
                "longitude": lon,
                "accuracy": item.get("accuracy"),
                "source_record": item,
            },
        )

    def _telegram(self, data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        recognized = False
        if isinstance(data.get("personal_information"), dict):
            recognized = True
            self._emit(
                "system",
                "telegram_account",
                "Telegram account",
                json.dumps(data["personal_information"], ensure_ascii=False),
                None,
                "personal_information",
                data["personal_information"],
            )
        contacts = (
            data.get("contacts", {}).get("list", [])
            if isinstance(data.get("contacts"), dict)
            else []
        )
        for i, contact in enumerate(contacts):
            recognized = True
            self._emit(
                "contact",
                "telegram_contact",
                f"{contact.get('first_name', '')} {contact.get('last_name', '')}".strip(),
                contact.get("phone_number"),
                contact.get("date_unixtime", contact.get("date")),
                f"contacts/{i}",
                contact,
            )
        chats = data.get("chats", {}).get("list", []) if isinstance(data.get("chats"), dict) else []
        if "messages" in data:
            chats = [data]
        if "chats" in data or "messages" in data:
            recognized = True
        for c, chat in enumerate(chats):
            for i, message in enumerate(chat.get("messages", [])):
                content = message.get("text", "")
                if isinstance(content, list):
                    content = "".join(
                        part if isinstance(part, str) else str(part.get("text", ""))
                        for part in content
                    )
                self._emit(
                    "communication",
                    "telegram_message",
                    message.get(
                        "from", message.get("actor", chat.get("name", "Telegram service event"))
                    ),
                    content or message.get("action", ""),
                    message.get("date_unixtime", message.get("date")),
                    f"chats/{c}/messages/{i}",
                    {
                        "message_id": message.get("id"),
                        "sender": message.get("from_id", message.get("actor_id")),
                        "sender_name": message.get("from"),
                        "conversation_id": chat.get("id"),
                        "conversation_name": chat.get("name"),
                        "message_type": message.get("type"),
                        "reply_to_message_id": message.get("reply_to_message_id"),
                        "attachment": message.get("file", message.get("photo")),
                        "mime_type": message.get("mime_type"),
                        "text_entities": message.get("text_entities"),
                        "location": message.get("location_information"),
                        "action": message.get("action"),
                    },
                )
                if isinstance(message.get("location_information"), dict):
                    loc = message["location_information"]
                    self._emit(
                        "location",
                        "telegram_location",
                        "Telegram shared location",
                        content,
                        message.get("date_unixtime", message.get("date")),
                        f"chats/{c}/messages/{i}/location",
                        loc,
                    )
        return recognized

    def _microsoft(self, data: Any) -> bool:
        items = data.get("value", [data]) if isinstance(data, dict) else data
        if not isinstance(items, list):
            return False
        recognized = False
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            if "receivedDateTime" in item or "internetMessageId" in item:
                recognized = True
                self._emit(
                    "communication",
                    "microsoft_mail",
                    item.get("subject"),
                    item.get("body", {}).get("content", item.get("bodyPreview", "")),
                    item.get("receivedDateTime", item.get("sentDateTime")),
                    f"value/{i}",
                    {
                        k: item.get(k)
                        for k in (
                            "id",
                            "internetMessageId",
                            "from",
                            "sender",
                            "toRecipients",
                            "ccRecipients",
                            "bccRecipients",
                            "hasAttachments",
                            "conversationId",
                            "body",
                            "attachments",
                        )
                    },
                )
            elif "start" in item and "end" in item:
                recognized = True
                start = item.get("start", {})
                raw = start.get("dateTime")
                source_zone = start.get("timeZone")
                # Graph uses Windows zones too; never silently substitute UTC for these.
                if (
                    raw
                    and source_zone == "UTC"
                    and not str(raw).endswith("Z")
                    and not re.search(r"[+-]\d\d:\d\d$", str(raw))
                ):
                    raw += "Z"
                elif raw and source_zone:
                    try:
                        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                        if parsed.tzinfo is None:
                            normalized = _local_utc(parsed, ZoneInfo(source_zone))
                            raw = normalized.isoformat() if normalized else None
                    except (ValueError, KeyError):
                        raw = None
                self._emit(
                    "application",
                    "microsoft_calendar",
                    item.get("subject"),
                    item.get("bodyPreview", ""),
                    raw,
                    f"value/{i}",
                    {
                        k: item.get(k)
                        for k in (
                            "id",
                            "start",
                            "end",
                            "location",
                            "organizer",
                            "attendees",
                            "recurrence",
                        )
                    },
                    source_time=start.get("dateTime"),
                )
            elif "emailAddresses" in item or "businessPhones" in item:
                recognized = True
                self._emit(
                    "contact",
                    "microsoft_contact",
                    item.get("displayName"),
                    json.dumps(item, ensure_ascii=False),
                    None,
                    f"value/{i}",
                    item,
                )
            elif "file" in item or "folder" in item:
                recognized = True
                self._emit(
                    "file",
                    "microsoft_drive_item",
                    item.get("name"),
                    item.get("webUrl"),
                    item.get("lastModifiedDateTime"),
                    f"value/{i}",
                    {
                        k: item.get(k)
                        for k in (
                            "id",
                            "size",
                            "file",
                            "folder",
                            "parentReference",
                            "createdDateTime",
                            "lastModifiedDateTime",
                        )
                    },
                )
        return recognized

    def _whatsapp(self, text: str) -> bool:
        # Android dash and iOS bracket exports; multiline messages stay together.
        pattern = re.compile(
            r"^\[?(\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APap][Mm])?)\]?\s*(?:-\s*)?(.*)$"
        )
        rows: list[tuple[int, str, str, str]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            clean = line.replace("\u200e", "").replace("\u202f", " ").replace("\u00a0", " ")
            match = pattern.match(clean)
            if match:
                rows.append((line_number, match[1], match[2], match[3]))
            elif rows:
                n, d, t, body = rows[-1]
                rows[-1] = (n, d, t, body + "\n" + line)
            elif clean.strip():
                raise ValueError(
                    "Unrecognized WhatsApp chat header; expected dated Android/iOS text export"
                )
        for line_number, date, time, body in rows:
            pieces = re.split(r"[/.\-]", date)
            first, second, year = map(int, pieces)
            if year < 100:
                year += 2000
            day, month = (first, second) if self.date_order == "DMY" else (second, first)
            fmt = (
                "%I:%M:%S %p"
                if ":" in time and time.count(":") == 2 and re.search(r"[ap]m", time, re.I)
                else "%I:%M %p"
                if re.search(r"[ap]m", time, re.I)
                else "%H:%M:%S"
                if time.count(":") == 2
                else "%H:%M"
            )
            clock = datetime.strptime(time.upper(), fmt).time()
            raw = datetime(year, month, day, clock.hour, clock.minute, clock.second).isoformat()
            sender, separator, content = body.partition(": ")
            attachment = re.search(r"<attached:\s*(.+?)>|(.+?)\s*\(file attached\)", content)
            self._emit(
                "communication",
                "whatsapp_export_message",
                sender if separator else "WhatsApp system event",
                content if separator else body,
                raw,
                f"line/{line_number}",
                {
                    "sender": sender if separator else None,
                    "message_type": "message" if separator else "system",
                    "raw_timestamp": f"{date} {time}",
                    "conversation_name": Path(self.member_name).stem,
                    "attachment_reference": (attachment[1] or attachment[2]).strip()
                    if attachment
                    else None,
                    "media_omitted": "<Media omitted>" in body,
                },
            )
        return bool(rows)

    def _email(self, message: Any, locator: str) -> None:
        bodies: list[str] = []
        attachments: list[dict[str, Any]] = []
        for part in message.walk():
            if part.is_multipart():
                continue
            payload = part.get_payload(decode=True) or b""
            if part.get_filename() or part.get_content_disposition() == "attachment":
                attachments.append(
                    {
                        "name": part.get_filename(),
                        "mime_type": part.get_content_type(),
                        "bytes": len(payload),
                        "sha256": sha256(payload).hexdigest(),
                    }
                )
            elif part.get_content_type() in {"text/plain", "text/html"}:
                bodies.append(
                    payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                )
        raw = str(message.get("Date", ""))
        try:
            timestamp = parsedate_to_datetime(raw).isoformat()
        except (ValueError, TypeError):
            timestamp = raw
        self._emit(
            "communication",
            f"{self.provider}_mail",
            message.get("Subject"),
            "\n".join(bodies),
            timestamp,
            locator,
            {
                "sender": str(message.get("From", "")),
                "recipients": str(message.get("To", "")),
                "cc": str(message.get("Cc", "")),
                "message_id": str(message.get("Message-ID", "")),
                "in_reply_to": str(message.get("In-Reply-To", "")),
                "attachments": attachments,
                "raw_date": raw,
            },
            source_time=raw,
        )

    def _cards(self, text: str, suffix: str) -> bool:
        kind = "VCARD" if suffix == ".vcf" else "VEVENT"
        lines = re.sub(r"\r?\n[ \t]", "", text).splitlines()
        card: dict[str, list[dict[str, str]]] | None = None
        count = 0
        for number, line in enumerate(lines, 1):
            if line.upper() == f"BEGIN:{kind}":
                card = {}
            elif line.upper() == f"END:{kind}" and card is not None:
                count += 1

                def val(key: str, component: dict[str, list[dict[str, str]]] | None = card) -> str:
                    return (
                        component.get(key, [{}])[0].get("value", "")
                        if component is not None
                        else ""
                    )

                title = val("FN") or val("N") if kind == "VCARD" else val("SUMMARY")
                raw = None
                if kind == "VEVENT":
                    start = card.get("DTSTART", [{}])[0]
                    value = start.get("value", "")
                    if re.fullmatch(r"\d{8}T\d{6}Z?", value):
                        parsed = datetime.strptime(value.rstrip("Z"), "%Y%m%dT%H%M%S")
                        if value.endswith("Z"):
                            raw = parsed.replace(tzinfo=UTC).isoformat()
                        else:
                            tz_match = re.search(r"(?:^|;)TZID=([^;]+)", start.get("params", ""))
                            if tz_match:
                                try:
                                    normalized = _local_utc(
                                        parsed, ZoneInfo(tz_match[1].strip('"'))
                                    )
                                    raw = normalized.isoformat() if normalized else None
                                except KeyError:
                                    raw = None
                            else:
                                raw = parsed.isoformat()
                self._emit(
                    "contact" if kind == "VCARD" else "application",
                    f"{self.provider}_{'contact' if kind == 'VCARD' else 'calendar'}",
                    title,
                    val("NOTE") if kind == "VCARD" else val("DESCRIPTION"),
                    raw,
                    f"{kind}/{count}/line/{number}",
                    {
                        "properties": card,
                        "uid": val("UID"),
                        "emails": [p["value"] for p in card.get("EMAIL", [])],
                        "phones": [p["value"] for p in card.get("TEL", [])],
                        "recurrence": val("RRULE"),
                        "original_start": val("DTSTART"),
                    },
                    source_time=val("DTSTART") if kind == "VEVENT" else None,
                )
                card = None
            elif card is not None and ":" in line:
                key, value = line.split(":", 1)
                field, _, params = key.partition(";")
                value = re.sub(
                    r"\\([nN,;\\])", lambda m: "\n" if m[1].lower() == "n" else m[1], value
                )
                card.setdefault(field.upper(), []).append({"value": value, "params": params})
        if card is not None:
            raise ValueError("Unterminated contact/calendar component")
        return count > 0

    def _csv(self, text: str) -> bool:
        rows = csv.DictReader(io.StringIO(text))
        headers = set(rows.fieldnames or [])
        contact = bool(
            headers
            & {"E-mail Address", "E-mail 1 - Value", "First Name", "Given Name", "Phone 1 - Value"}
        )
        photo = {"Filename", "Photo Taken Date"}.issubset(headers)
        if not contact and not photo:
            return False
        for i, row in enumerate(rows):
            title = (
                row.get("Name")
                or row.get("Display Name")
                or row.get("First Name")
                or row.get("Given Name")
                or row.get("Filename")
                or "Exported contact"
            )
            self._emit(
                "contact" if contact else "file",
                f"{self.provider}_{'contact' if contact else 'photo_metadata'}",
                title,
                json.dumps(row, ensure_ascii=False),
                row.get("Photo Taken Date") if photo else None,
                f"csv/row/{i + 2}",
                row,
            )
        return True
