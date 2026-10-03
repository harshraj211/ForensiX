"""Bounded Smart Switch archive normalization on an examination copy.

The parser accepts ZIP-compatible .sbu/.zip exports.  Its schema adapters are
deliberately explicit: unknown vendor members remain in the summary instead
of being interpreted as contacts or messages by filename alone.
"""

from __future__ import annotations

import csv
import json
import mimetypes
import re
import tempfile
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from forensix_forensic.android_artifacts import android_parser_registry
from forensix_forensic.evidence_io import (
    ArchivePolicy,
    ParsedArtifact,
    ParserContext,
    ParserMetadata,
    SafeArchiveExtractor,
    SafeSQLiteError,
    SafeSQLiteReader,
)
from forensix_forensic.storage import EvidenceStore

MAX_ARCHIVE_MEMBERS = 10_000
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACTS = 25_000
_NATIVE_PARSERS = (
    "android.contacts_provider",
    "android.telephony.sms",
    "android.telephony.mms",
    "android.call_log",
    "android.calendar.events",
    "android.downloads.provider",
)
_MEDIA_SUFFIXES = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".heic",
        ".mp4",
        ".mov",
        ".3gp",
        ".mp3",
        ".m4a",
        ".wav",
        ".pdf",
        ".opus",
        ".ogg",
        ".bmp",
        ".tif",
        ".tiff",
        ".mkv",
        ".amr",
        ".aac",
    }
)
_SECRET_NAMES = ("password", "passwd", "token", "secret", "key", "credential")


class SmartSwitchArchiveParser:
    metadata = ParserMetadata(
        parser_id="samsung.smart_switch.archive",
        name="Samsung Smart Switch archive",
        version="1.0.0",
        artifact_categories=("contact", "communication", "application", "system", "file"),
        required_tables=frozenset(),
        access_level="filesystem",
        maturity="experimental",
        source_path_hints=(".sbu", ".zip"),
        supported_artifact_types=(
            "smart_switch_contact",
            "smart_switch_message",
            "smart_switch_call",
            "smart_switch_setting",
            "smart_switch_media",
            "smart_switch_member",
            "smart_switch_summary",
        ),
        description="Normalizes readable Smart Switch members and records unsupported ones.",
        input_formats=("zip", "sbu"),
    )

    def can_parse(self, source_locator: str) -> bool:
        return Path(source_locator).suffix.casefold() in {".sbu", ".zip"}

    def parse(self, path: Path, context: ParserContext) -> list[ParsedArtifact]:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Smart Switch input must be a regular examination copy")
        with tempfile.TemporaryDirectory(prefix="smart-switch-") as temp:
            store = EvidenceStore(Path(temp))
            members = SafeArchiveExtractor(
                ArchivePolicy(
                    max_members=MAX_ARCHIVE_MEMBERS,
                    max_member_bytes=512 * 1024 * 1024,
                    max_total_bytes=2 * 1024 * 1024 * 1024,
                    max_path_depth=20,
                )
            ).extract(path, store, "members")
            media_names = Counter(
                Path(member.original_name).name.casefold()
                for member in members
                if Path(member.original_name).suffix.casefold() in _MEDIA_SUFFIXES
            )
            media_by_name = {
                Path(member.original_name).name.casefold(): member.original_name
                for member in members
                if Path(member.original_name).suffix.casefold() in _MEDIA_SUFFIXES
                and media_names[Path(member.original_name).name.casefold()] == 1
            }
            artifacts: list[ParsedArtifact] = []
            unsupported: list[str] = []
            failures: list[str] = []
            for member in members:
                if len(artifacts) >= MAX_ARTIFACTS:
                    failures.append("Artifact count reached the parser limit")
                    break
                member_path = store.resolve(member.storage_key, require_file=True)
                name = member.original_name
                if len(name) > 900:
                    unsupported.append(name[:900])
                    continue
                suffix = Path(name).suffix.casefold()
                try:
                    with member_path.open("rb") as source:
                        signature = source.read(32)
                    if suffix in _MEDIA_SUFFIXES:
                        parsed = [_media_artifact(name, member.sha256, member.size_bytes)]
                    elif signature.startswith(b"SQLite format 3\x00") or suffix in {
                        ".db",
                        ".sqlite",
                        ".sqlite3",
                    }:
                        parsed = _sqlite_artifacts(member_path, name, context)
                    elif suffix == ".spbm" and signature.startswith(b"BEGIN:VCARD"):
                        parsed = _vcard_artifacts(member_path.read_text(encoding="utf-8-sig"))
                    elif (
                        suffix in {".csv", ".tsv", ".vcf", ".json", ".xml"}
                        and member.size_bytes <= MAX_DOCUMENT_BYTES
                    ):
                        parsed = _document_artifacts(member_path, name)
                    else:
                        parsed = []
                    if suffix not in _MEDIA_SUFFIXES:
                        artifacts.append(
                            _member_artifact(
                                name,
                                member.sha256,
                                member.size_bytes,
                                recognized=bool(parsed),
                                signature=signature,
                            )
                        )
                    if not parsed:
                        unsupported.append(name)
                        continue
                    for artifact in parsed[: MAX_ARTIFACTS - len(artifacts)]:
                        metadata = {
                            **artifact.metadata,
                            "archive_member": name,
                            "member_sha256": member.sha256,
                            "member_size_bytes": member.size_bytes,
                        }
                        if artifact.subtype == "smart_switch_message":
                            attachment = str(metadata.get("attachment_reference") or "").casefold()
                            linked = media_by_name.get(Path(attachment).name)
                            if linked:
                                metadata["linked_media_member"] = linked
                        artifacts.append(
                            replace(
                                artifact,
                                source_locator=f"{name}#{artifact.source_locator}",
                                metadata=metadata,
                            )
                        )
                except (
                    UnicodeError,
                    ValueError,
                    SafeSQLiteError,
                    csv.Error,
                    ParseError,
                    DefusedXmlException,
                ) as error:
                    if suffix not in _MEDIA_SUFFIXES:
                        artifacts.append(
                            _member_artifact(
                                name,
                                member.sha256,
                                member.size_bytes,
                                recognized=False,
                                signature=signature,
                            )
                        )
                    failures.append(f"{name}: {type(error).__name__}")
            counts = dict(Counter(item.subtype for item in artifacts))
            summary = ParsedArtifact(
                category="system",
                subtype="smart_switch_summary",
                title="Smart Switch archive examination",
                summary=f"{len(members)} members; {len(artifacts)} normalized records; "
                f"{len(unsupported)} unsupported; {len(failures)} issues",
                event_time=None,
                source_locator="archive#summary",
                status="partial" if unsupported or failures else "active",
                confidence="high",
                metadata={
                    "member_count": len(members),
                    "record_counts": counts,
                    "unsupported_count": len(unsupported),
                    "unsupported_members": unsupported[:200],
                    "issues": failures[:200],
                    "parser_scope": "ZIP-compatible Smart Switch export; readable supported schemas",
                },
            )
            return [summary, *artifacts]


def _media_artifact(name: str, digest: str, size: int) -> ParsedArtifact:
    return ParsedArtifact(
        category="file",
        subtype="smart_switch_media",
        title=Path(name).name,
        summary=name,
        event_time=None,
        source_locator="file",
        status="active",
        confidence="high",
        metadata={
            "file_name": Path(name).name,
            "mime_type": mimetypes.guess_type(name)[0],
            "size_bytes": size,
            "sha256": digest,
        },
    )


def _member_artifact(
    name: str, digest: str, size: int, *, recognized: bool, signature: bytes
) -> ParsedArtifact:
    return ParsedArtifact(
        category="file",
        subtype="smart_switch_member",
        title=Path(name).name,
        summary=name,
        event_time=None,
        source_locator=name,
        status="active" if recognized else "partial",
        confidence="high",
        metadata={
            "file_name": Path(name).name,
            "size_bytes": size,
            "sha256": digest,
            "archive_member": name,
            "member_sha256": digest,
            "member_size_bytes": size,
            "mime_type": mimetypes.guess_type(name)[0],
            "decoding_status": "parsed" if recognized else "unsupported_format",
            "signature_hex": signature[:16].hex(),
        },
    )


def _sqlite_artifacts(path: Path, name: str, context: ParserContext) -> list[ParsedArtifact]:
    result: list[ParsedArtifact] = []
    registry = android_parser_registry()
    with SafeSQLiteReader(path, max_rows=20_000) as reader:
        tables = reader.table_names()
        for parser_id in _NATIVE_PARSERS:
            parser = registry.get(parser_id)
            if not parser.metadata.required_tables.issubset(tables) or not parser.can_parse(tables):
                continue
            try:
                member_context = replace(context, input_locator=name, source_label=name)
                result.extend(parser.parse(reader, member_context))
            except (ValueError, SafeSQLiteError):
                # One schema variant must not suppress another readable table.
                continue
    return result


def _document_artifacts(path: Path, name: str) -> list[ParsedArtifact]:
    payload = path.read_bytes()
    if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = payload.decode("utf-16")
    else:
        text = payload.decode("utf-8-sig")
    suffix = Path(name).suffix.casefold()
    if suffix == ".vcf":
        return _vcard_artifacts(text)
    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else _csv_delimiter(text)
        return _csv_artifacts(text, delimiter=delimiter, hint=name)
    if suffix == ".xml":
        return _xml_artifacts(text, hint=name)
    value = json.loads(text)
    return _json_artifacts(value, hint=name)


def _csv_delimiter(text: str) -> str:
    header = text.splitlines()[0] if text else ""
    return max((",", ";", "\t"), key=header.count)


def _vcard_artifacts(text: str) -> list[ParsedArtifact]:
    result: list[ParsedArtifact] = []
    for index, block in enumerate(text.split("BEGIN:VCARD")[1:], 1):
        if "END:VCARD" not in block:
            continue
        fields: dict[str, list[str]] = {}
        for line in block.split("END:VCARD", 1)[0].splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields.setdefault(key.split(";", 1)[0].upper(), []).append(value.strip())
        title = next(iter(fields.get("FN", [])), "") or next(iter(fields.get("N", [])), "")
        result.append(
            ParsedArtifact(
                category="contact",
                subtype="smart_switch_contact",
                title=title or f"Contact {index}",
                summary=", ".join(fields.get("TEL", []) + fields.get("EMAIL", [])),
                event_time=None,
                source_locator=f"vcard:{index}",
                status="active",
                confidence="high",
                metadata={
                    "name": title,
                    "phone_numbers": fields.get("TEL", []),
                    "emails": fields.get("EMAIL", []),
                },
            )
        )
    return result


def _csv_artifacts(text: str, *, delimiter: str, hint: str) -> list[ParsedArtifact]:
    reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
    return [
        artifact
        for index, row in enumerate(reader, 2)
        if index <= MAX_ARTIFACTS + 1
        if (artifact := _row_artifact(row, f"row:{index}", hint=hint)) is not None
    ]


def _json_artifacts(value: Any, *, hint: str) -> list[ParsedArtifact]:
    rows: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, list):
        rows = [(f"item:{i}", item) for i, item in enumerate(value, 1) if isinstance(item, dict)]
    elif isinstance(value, dict):
        for key in ("contacts", "messages", "sms", "calls", "call_logs", "settings"):
            entries = value.get(key)
            if isinstance(entries, list):
                rows.extend(
                    (f"{key}:{i}", item)
                    for i, item in enumerate(entries, 1)
                    if isinstance(item, dict)
                )
        if not rows:
            rows = [("item:1", value)]
    return [
        artifact
        for locator, row in rows
        if (artifact := _row_artifact(row, locator, hint=hint)) is not None
    ]


def _xml_artifacts(text: str, *, hint: str) -> list[ParsedArtifact]:
    if "setting" not in hint.casefold() and "config" not in hint.casefold():
        return []
    root = fromstring(text)
    result: list[ParsedArtifact] = []
    for index, element in enumerate(root.iter(), 1):
        if index > 10_000:
            raise ValueError("Smart Switch XML exceeds the element limit")
        if element.tag.casefold().rsplit("}", 1)[-1] not in {"setting", "entry", "item"}:
            continue
        name = element.attrib.get("key") or element.attrib.get("name")
        if not name:
            continue
        raw = element.attrib.get("value") or (element.text or "").strip()
        artifact = _row_artifact({"key": name, "value": raw}, f"settings:{index}", hint=hint)
        if artifact is not None:
            result.append(artifact)
    return result


def _row_artifact(row: dict[str, Any], locator: str, *, hint: str = "") -> ParsedArtifact | None:
    normalized = {
        re.sub(r"[^\w]+", "_", str(key).strip().casefold())
        .strip("_")
        .replace("e_mail", "email"): item
        for key, item in row.items()
    }

    def value(*keys: str) -> str:
        return next(
            (
                str(normalized[key]).strip()[:20_000]
                for key in keys
                if normalized.get(key) is not None and str(normalized[key]).strip()
            ),
            "",
        )

    name = value("name", "display_name", "full_name", "contact_name", "fn")
    if not name:
        name = " ".join(
            part
            for part in (
                value("first_name", "given_name"),
                value("middle_name"),
                value("last_name", "family_name", "surname"),
            )
            if part
        )
    phone_numbers = list(
        dict.fromkeys(
            str(item).strip()[:20_000]
            for key, item in normalized.items()
            if ("phone" in key or key in {"mobile", "cell", "telephone", "tel"})
            and "type" not in key
            and item is not None
            and str(item).strip()
        )
    )
    emails = list(
        dict.fromkeys(
            str(item).strip()[:20_000]
            for key, item in normalized.items()
            if "email" in key and "type" not in key and item is not None and str(item).strip()
        )
    )
    phone = phone_numbers[0] if phone_numbers else ""
    email = emails[0] if emails else ""
    body = value("body", "message", "text", "content")
    address = value("address", "sender", "recipient", "number")
    duration = value("duration", "duration_seconds")
    time = _timestamp(value("date", "timestamp", "time", "created_at", "start_time", "date_sent"))
    attachment = value("attachment", "attachment_path", "media_path", "file_name")
    classification = f"{hint}/{locator}".casefold()
    if body and (address or "message" in classification):
        kind, category, title, summary = (
            "smart_switch_message",
            "communication",
            f"Message {address}",
            body,
        )
        metadata = {
            "address": address,
            "body": body,
            "attachment_reference": attachment,
            "direction": value("type", "direction"),
        }
    elif duration and address:
        kind, category, title, summary = (
            "smart_switch_call",
            "communication",
            f"Call {address}",
            f"Duration {duration}",
        )
        metadata = {
            "number": address,
            "duration_seconds": duration,
            "call_type": value("type", "direction"),
        }
    elif name and (phone or email or "contact" in classification):
        kind, category, title, summary = (
            "smart_switch_contact",
            "contact",
            name,
            ", ".join(x for x in (phone, email) if x),
        )
        metadata = {"name": name, "phone_numbers": phone_numbers, "emails": emails}
    elif "setting" in classification and value("key", "setting_name"):
        key = value("key", "setting_name")
        raw = value("value", "setting_value")
        if any(secret in key.casefold() for secret in _SECRET_NAMES):
            raw = "[withheld]"
        kind, category, title, summary = "smart_switch_setting", "system", key, raw
        metadata = {"setting_name": key, "setting_value": raw}
    else:
        return None
    return ParsedArtifact(
        category=category,
        subtype=kind,
        title=title[:500],
        summary=summary[:2000],
        event_time=time,
        source_locator=locator,
        status="active",
        confidence="medium",
        metadata=metadata,
        content=body if kind == "smart_switch_message" else None,
    )


def _timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        if raw.isdecimal():
            number = int(raw)
            seconds = number / 1000 if number > 10**11 else number
            parsed = datetime.fromtimestamp(seconds, UTC)
        else:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return None
            parsed = parsed.astimezone(UTC)
        return parsed if 1990 <= parsed.year <= 2200 else None
    except (OverflowError, ValueError):
        return None
