"""Representative export formats and adversarial input boundaries."""

import json
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from zipfile import ZipFile

import pytest

from forensix_forensic.evidence_io import ParserContext
from forensix_forensic.extractors.cloud.exports import CloudExportError, CloudExportParser


def parse(tmp_path, provider, name, content, **options):
    path = tmp_path / name
    payload = content.encode() if isinstance(content, str) else content
    path.write_bytes(payload)
    context = ParserContext(
        case_id="case",
        evidence_source_id="source",
        working_copy_id="copy",
        source_sha256=sha256(payload).hexdigest(),
        source_label=name,
    )
    return CloudExportParser(provider, **options).parse(path, context)


def records(artifacts):
    return [
        a for a in artifacts if a.subtype not in {"cloud_export_member", "cloud_export_summary"}
    ]


@pytest.mark.parametrize("provider", ["google", "microsoft", "icloud"])
def test_vcard_folded_unicode_multiple_values(tmp_path, provider):
    artifacts = records(
        parse(
            tmp_path,
            provider,
            "contacts.vcf",
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Harsh\r\n  Sharma\r\nEMAIL:a@example.org\r\nEMAIL:b@example.org\r\nTEL:+911234\r\nNOTE:hello\\nworld\r\nEND:VCARD\r\n",
        )
    )
    assert len(artifacts) == 1
    assert artifacts[0].title == "Harsh Sharma"
    assert artifacts[0].metadata["emails"] == [
        {"address": "a@example.org"},
        {"address": "b@example.org"},
    ]
    assert artifacts[0].content == "hello\nworld"


@pytest.mark.parametrize("provider", ["google", "microsoft", "icloud"])
def test_calendar_tzid_all_day_recurrence(tmp_path, provider):
    payload = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:one\nSUMMARY:Meeting\nDTSTART;TZID=Asia/Kolkata:20261001T120000\nRRULE:FREQ=WEEKLY\nEND:VEVENT\nBEGIN:VEVENT\nSUMMARY:All day\nDTSTART;VALUE=DATE:20261002\nEND:VEVENT\nEND:VCALENDAR"
    artifacts = records(parse(tmp_path, provider, "calendar.ics", payload))
    assert artifacts[0].event_time == datetime(2026, 10, 1, 6, 30, tzinfo=UTC)
    assert artifacts[0].metadata["recurrence"] == "FREQ=WEEKLY"
    assert artifacts[0].metadata["original_time"] == "20261001T120000"
    assert artifacts[1].event_time is None
    assert artifacts[1].metadata["original_start"] == "20261002"


@pytest.mark.parametrize("provider", ["google", "microsoft", "icloud"])
@pytest.mark.parametrize("suffix", [".eml", ".mbox"])
def test_mail_mime_attachment_hash(tmp_path, provider, suffix):
    mail = b"From: a@example.org\nTo: b@example.org\nSubject: Proof mail\nDate: Thu, 1 Oct 2026 12:00:00 +0530\nMessage-ID: <one>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain; charset=utf-8\n\nHello evidence\n--x\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=proof.bin\nContent-Transfer-Encoding: base64\n\nYWJj\n--x--\n"
    if suffix == ".mbox":
        mail = b"From a@example.org Thu Oct  1 12:00:00 2026\n" + mail
    artifacts = records(parse(tmp_path, provider, "mail" + suffix, mail))
    assert "Hello evidence" in artifacts[0].content
    assert artifacts[0].event_time == datetime(2026, 10, 1, 6, 30, tzinfo=UTC)
    assert artifacts[0].metadata["attachments"][0]["sha256"] == sha256(b"abc").hexdigest()


def test_google_json_classes_and_microsecond_epoch(tmp_path):
    payload = {
        "Browser History": [
            {"title": "Proof", "url": "https://example.org", "time_usec": 1700000000000000}
        ],
        "locations": [
            {"latitudeE7": 285000000, "longitudeE7": 770000000, "timestampMs": "1700000000000"}
        ],
        "timelineObjects": [
            {
                "placeVisit": {
                    "location": {"latitudeE7": 10000000, "longitudeE7": 20000000},
                    "duration": {"startTimestamp": "2026-10-01T12:00:00Z"},
                }
            }
        ],
    }
    artifacts = records(parse(tmp_path, "google", "Records.json", json.dumps(payload)))
    assert len(artifacts) == 3
    assert artifacts[0].event_time == datetime.fromtimestamp(1700000000, UTC)
    assert artifacts[1].metadata["latitude"] == 28.5


def test_google_activity_and_photos(tmp_path):
    activity = records(
        parse(
            tmp_path,
            "google",
            "activity.json",
            json.dumps(
                [
                    {
                        "title": "Viewed proof",
                        "time": "2026-10-01T12:00:00Z",
                        "titleUrl": "https://example.org",
                    }
                ]
            ),
        )
    )[0]
    assert activity.subtype == "google_activity"
    photo = records(
        parse(
            tmp_path,
            "google",
            "photo.json",
            json.dumps({"title": "proof.jpg", "photoTakenTime": {"timestamp": "1700000000"}}),
        )
    )[0]
    assert photo.subtype == "google_photo_metadata"


@pytest.mark.parametrize(
    "text,date_order,expected",
    [
        (
            "01/10/2026, 12:30 - Alice: Proof\ncontinued\n01/10/2026, 12:31 - System notice",
            "DMY",
            datetime(2026, 10, 1, 7, tzinfo=UTC),
        ),
        ("[10/01/26, 12:30:00 PM] Alice: Proof", "MDY", datetime(2026, 10, 1, 7, tzinfo=UTC)),
    ],
)
def test_whatsapp_export_variants(tmp_path, text, date_order, expected):
    artifacts = records(
        parse(
            tmp_path,
            "whatsapp",
            "chat.txt",
            text,
            source_timezone="Asia/Kolkata",
            date_order=date_order,
        )
    )
    assert artifacts[0].event_time == expected
    assert artifacts[0].metadata["sender"] == "Alice"
    assert "Proof" in artifacts[0].content
    if len(artifacts) > 1:
        assert artifacts[1].metadata["message_type"] == "system"
        assert "continued" in artifacts[0].content


def test_whatsapp_plaintext_database(tmp_path):
    path = tmp_path / "msgstore.db"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE messages (_id INTEGER, key_remote_jid TEXT, key_from_me INTEGER, data TEXT, timestamp INTEGER)"
        )
        db.execute(
            "INSERT INTO messages VALUES (1, '1555000@s.whatsapp.net', 0, 'Proof sqlite message', 1700000000000)"
        )
    artifacts = records(parse(tmp_path, "whatsapp", "input.db", path.read_bytes()))
    assert any("Proof sqlite" in (a.content or a.summary) for a in artifacts)


def test_telegram_rich_text_reply_location_and_account(tmp_path):
    payload = {
        "personal_information": {"user_id": 1},
        "contacts": {"list": [{"first_name": "Alice", "phone_number": "+123"}]},
        "chats": {
            "list": [
                {
                    "id": 7,
                    "name": "Proof chat",
                    "messages": [
                        {
                            "id": 2,
                            "date_unixtime": "1700000000",
                            "from": "Alice",
                            "from_id": "user1",
                            "text": ["Proof ", {"type": "bold", "text": "rich"}],
                            "reply_to_message_id": 1,
                            "photo": "photos/proof.jpg",
                            "location_information": {"latitude": 1.0, "longitude": 2.0},
                        }
                    ],
                }
            ]
        },
    }
    artifacts = records(parse(tmp_path, "telegram", "result.json", json.dumps(payload)))
    message = next(a for a in artifacts if a.subtype == "telegram_message")
    assert message.content == "Proof rich"
    assert message.metadata["reply_to_message_id"] == 1
    assert any(a.category == "location" for a in artifacts)
    assert len(artifacts) == 4


def test_microsoft_graph_resource_classes(tmp_path):
    payload = {
        "value": [
            {
                "subject": "Proof mail",
                "receivedDateTime": "2026-10-01T12:00:00Z",
                "body": {"content": "hello"},
            },
            {"displayName": "Alice", "emailAddresses": [{"address": "a@example.org"}]},
            {
                "subject": "Proof meeting",
                "start": {"dateTime": "2026-10-01T12:00:00", "timeZone": "UTC"},
                "end": {"dateTime": "2026-10-01T13:00:00", "timeZone": "UTC"},
            },
            {"name": "proof.jpg", "file": {"mimeType": "image/jpeg"}, "size": 123},
        ]
    }
    artifacts = records(parse(tmp_path, "microsoft", "graph.json", json.dumps(payload)))
    assert {a.subtype for a in artifacts} == {
        "microsoft_mail",
        "microsoft_contact",
        "microsoft_calendar",
        "microsoft_drive_item",
    }
    assert artifacts[2].event_time == datetime(2026, 10, 1, 12, tzinfo=UTC)


@pytest.mark.parametrize("provider", ["google", "microsoft", "icloud"])
def test_contact_csv_quoted_commas(tmp_path, provider):
    artifact = records(
        parse(
            tmp_path,
            provider,
            "contacts.csv",
            'First Name,E-mail Address\n"Alice, Proof",alice@example.org\n',
        )
    )[0]
    assert artifact.title == "Alice, Proof"


def test_zip_inventory_malformed_unsupported_and_media_preserved(tmp_path):
    path = tmp_path / "export.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("chat.txt", "01/10/2026, 12:30 - Alice: Proof")
        archive.writestr("msgstore.db.crypt15", b"encrypted")
        archive.writestr("photo.jpg", b"image original")
        archive.writestr("broken.json", "{broken")
    artifacts = parse(tmp_path, "whatsapp", "input.zip", path.read_bytes())
    summary = artifacts[-1].metadata
    assert summary["parsed_count"] == 1
    assert summary["unsupported_count"] == 1
    assert summary["malformed_count"] == 1
    assert summary["preserved_file_count"] == 1
    member = next(a for a in artifacts if a.title == "photo.jpg")
    assert member.metadata["sha256"] == sha256(b"image original").hexdigest()


@pytest.mark.parametrize("name", ["../escape.txt", "C:/escape.txt", "/escape.txt"])
def test_zip_paths_are_rejected(tmp_path, name):
    path = tmp_path / "bad.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr(name, "01/10/2026, 12:30 - Alice: Proof")
    with pytest.raises(ValueError):
        parse(tmp_path, "whatsapp", "input.zip", path.read_bytes())
    assert not (tmp_path.parent / "escape.txt").exists()


def test_wrong_provider_or_only_unsupported_input_fails(tmp_path):
    with pytest.raises(CloudExportError, match="No recognized"):
        parse(tmp_path, "telegram", "unknown.json", '{"Browser History": []}')


@pytest.mark.parametrize("timestamp", ["2026-11-01T01:30:00", "2026-03-08T02:30:00"])
def test_dst_ambiguity_does_not_invent_time(timestamp):
    parser = CloudExportParser("whatsapp", source_timezone="America/New_York")
    normalized, basis = parser._time(timestamp)
    assert normalized is None
    assert "Ambiguous" in basis


def test_limits_and_invalid_configuration(tmp_path, monkeypatch):
    import forensix_forensic.extractors.cloud.exports as module

    with pytest.raises(CloudExportError):
        CloudExportParser("unknown")
    with pytest.raises(CloudExportError):
        CloudExportParser("google", source_timezone="unknown/zone")
    monkeypatch.setattr(module, "MAX_DOCUMENT_BYTES", 4)
    with pytest.raises(CloudExportError, match="64 MiB"):
        parse(tmp_path, "google", "too-big.json", "[12345]")


def test_provider_metadata_cannot_override_provenance(tmp_path):
    data = {
        "displayName": "Proof",
        "emailAddresses": [],
        "provider": "forged",
        "member_sha256": "forged",
        "timezone_basis": "forged",
    }
    artifact = records(parse(tmp_path, "microsoft", "contacts.json", json.dumps(data)))[0]
    assert artifact.metadata["provider"] == "microsoft"
    assert artifact.metadata["member_sha256"] != "forged"
    assert artifact.metadata["timezone_basis"] == "No timestamp in source"


@pytest.mark.parametrize("provider", ["whatsapp", "telegram"])
def test_attachment_links_use_exact_member_paths_and_hashes(tmp_path, provider):
    archive_path = tmp_path / "attachment.zip"
    with ZipFile(archive_path, "w") as archive:
        if provider == "whatsapp":
            archive.writestr(
                "export/chat.txt",
                "01/10/2026, 12:30 - Alice: proof.jpg (file attached)\n01/10/2026, 12:31 - Alice: <attached: missing.jpg>",
            )
        else:
            archive.writestr(
                "export/result.json",
                json.dumps(
                    {
                        "messages": [
                            {"text": "Proof", "photo": "proof.jpg"},
                            {"text": "Missing", "photo": "missing.jpg"},
                        ]
                    }
                ),
            )
        archive.writestr("export/proof.jpg", b"original proof image")
    messages = records(parse(tmp_path, provider, "input.zip", archive_path.read_bytes()))
    assert messages[0].metadata["attachment_resolution"] == "matched"
    assert (
        messages[0].metadata["attachment_member"]["sha256"]
        == sha256(b"original proof image").hexdigest()
    )
    assert messages[1].metadata["attachment_resolution"] == "missing"


def test_google_on_device_semantic_segments_and_epoch_object(tmp_path):
    data = {
        "locations": [
            {
                "latitudeE7": 10000000,
                "longitudeE7": 20000000,
                "timestamp": {"epoch_ms": 1700000000000},
            }
        ],
        "semanticSegments": [
            {
                "startTime": "2026-10-01T12:00:00Z",
                "visit": {"topCandidate": {"placeLocation": "geo:28.5,77.0"}},
                "timelinePath": [{"point": "geo:28.6,77.1", "time": "2026-10-01T12:01:00Z"}],
            }
        ],
    }
    artifacts = records(parse(tmp_path, "google", "timeline.json", json.dumps(data)))
    assert len(artifacts) == 3
    assert artifacts[0].event_time == datetime.fromtimestamp(1700000000, UTC)
    assert artifacts[1].metadata["latitude"] == 28.5
    assert artifacts[2].metadata["longitude"] == 77.1


def test_record_budget_fails_instead_of_truncating(tmp_path, monkeypatch):
    import forensix_forensic.extractors.cloud.exports as module

    monkeypatch.setattr(module, "MAX_ARTIFACTS", 1)
    with pytest.raises(CloudExportError, match="artifacts"):
        parse(
            tmp_path, "telegram", "result.json", '{"messages": [{"text": "one"}, {"text": "two"}]}'
        )


def test_graph_explicit_offset_is_preserved_and_dst_ambiguity_undated(tmp_path):
    data = {
        "value": [
            {
                "subject": "Offset",
                "start": {"dateTime": "2026-10-01T12:00:00+05:30", "timeZone": "America/New_York"},
                "end": {},
            },
            {
                "subject": "Ambiguous",
                "start": {"dateTime": "2026-11-01T01:30:00", "timeZone": "America/New_York"},
                "end": {},
            },
            {
                "subject": "Custom zone",
                "start": {"dateTime": "2026-10-01T12:00:00", "timeZone": "Pacific Standard Time"},
                "end": {},
            },
        ]
    }
    artifacts = records(parse(tmp_path, "microsoft", "calendar.json", json.dumps(data)))
    assert artifacts[0].event_time == datetime(2026, 10, 1, 6, 30, tzinfo=UTC)
    assert artifacts[1].event_time is None
    assert artifacts[2].event_time is None
    assert artifacts[0].metadata["original_time"] == "2026-10-01T12:00:00+05:30"
    assert artifacts[2].metadata["start"]["timeZone"] == "Pacific Standard Time"


def test_ics_tzid_dst_overlap_stays_undated(tmp_path):
    text = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Ambiguous\nDTSTART;TZID=America/New_York:20261101T013000\nEND:VEVENT\nEND:VCALENDAR"
    artifact = records(parse(tmp_path, "icloud", "calendar.ics", text))[0]
    assert artifact.event_time is None
    assert artifact.metadata["original_start"] == "20261101T013000"
