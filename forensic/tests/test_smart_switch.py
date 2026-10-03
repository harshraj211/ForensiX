"""Representative readable Smart Switch archive examination."""

import json
import sqlite3
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile

from forensix_forensic.evidence_io import ParserContext
from forensix_forensic.extractors.smart_switch import SmartSwitchArchiveParser


def test_smart_switch_archive_normalizes_members_and_preserves_provenance(tmp_path: Path) -> None:
    database = tmp_path / "messages.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE sms (_id INTEGER, date INTEGER, type INTEGER, address TEXT, body TEXT)"
    )
    connection.execute(
        "INSERT INTO sms VALUES (1, 1704067200000, 1, '+15550001', 'Database message')"
    )
    connection.commit()
    connection.close()

    archive = tmp_path / "SmartSwitch.sbu"
    image_bytes = b"\xff\xd8\xff\xe0sample-media"
    with ZipFile(archive, "w") as bundle:
        bundle.write(database, "messages/messages.db")
        bundle.writestr(
            "contacts/contacts.vcf",
            "BEGIN:VCARD\nVERSION:3.0\nFN:Alice Sample\nTEL:+15550002\nEND:VCARD\n",
        )
        bundle.writestr(
            "messages/export.csv",
            "date,address,body,attachment_path\n"
            "2024-01-01T00:00:00Z,+15550003,Photo attached,media/photo.jpg\n",
        )
        bundle.writestr("media/photo.jpg", image_bytes)
        bundle.writestr(
            "calls/calls.json",
            json.dumps({"calls": [{"number": "+15550004", "duration": 42, "date": 1704067200000}]}),
        )
        bundle.writestr(
            "settings/device.xml",
            '<settings><entry key="theme" value="dark"/>'
            '<entry key="wifi_password" value="private-value"/></settings>',
        )
        bundle.writestr("unknown/vendor.bin", b"opaque")
        bundle.writestr("settings/broken.xml", b"<settings><entry")

    context = ParserContext(
        case_id="CASE-1",
        evidence_source_id="SOURCE-1",
        working_copy_id="COPY-1",
        source_sha256="0" * 64,
        source_label="SmartSwitch.sbu",
    )
    artifacts = SmartSwitchArchiveParser().parse(archive, context)
    subtypes = {item.subtype for item in artifacts}

    assert {
        "smart_switch_summary",
        "smart_switch_contact",
        "smart_switch_message",
        "smart_switch_call",
        "smart_switch_setting",
        "smart_switch_media",
        "sms",
    } <= subtypes
    message = next(item for item in artifacts if item.summary == "Photo attached")
    assert message.metadata["linked_media_member"] == "media/photo.jpg"
    assert message.source_locator.startswith("messages/export.csv#row:2")
    media = next(item for item in artifacts if item.subtype == "smart_switch_media")
    assert media.metadata["member_sha256"] == sha256(image_bytes).hexdigest()
    assert all("private-value" not in str(item.metadata) for item in artifacts)
    summary = artifacts[0]
    assert summary.metadata["member_count"] == 8
    assert summary.metadata["unsupported_members"] == ["unknown/vendor.bin"]
    assert summary.metadata["issues"] == ["settings/broken.xml: ParseError"]
    opaque = next(item for item in artifacts if item.source_locator == "unknown/vendor.bin")
    assert opaque.subtype == "smart_switch_member"
    assert opaque.metadata["decoding_status"] == "unsupported_format"
    assert opaque.metadata["member_sha256"] == sha256(b"opaque").hexdigest()


def test_pc_folder_readable_exports_cover_sms_json_and_utf16_contacts(tmp_path: Path) -> None:
    archive = tmp_path / "SmartSwitch-PC-Folder.zip"
    contact_csv = "First Name;Last Name;Mobile Phone;Home Phone;E-mail Address\nAda;Lovelace;+44111;+44222;ada@example.test\n"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("Backup/CONTACT/contacts.csv", contact_csv.encode("utf-16"))
        bundle.writestr(
            "Backup/MESSAGE/sms_restore.json",
            json.dumps(
                [
                    {
                        "_id": "1",
                        "thread_id": "7",
                        "address": "+44111",
                        "date": "1713701392808",
                        "type": "1",
                        "body": "Readable SMS",
                    }
                ]
            ),
        )
    context = ParserContext(
        case_id="CASE",
        evidence_source_id="SOURCE",
        working_copy_id="COPY",
        source_sha256="0" * 64,
        source_label="SmartSwitch-PC-Folder.zip",
    )

    artifacts = SmartSwitchArchiveParser().parse(archive, context)

    contact = next(item for item in artifacts if item.subtype == "smart_switch_contact")
    assert contact.title == "Ada Lovelace"
    assert contact.metadata["phone_numbers"] == ["+44111", "+44222"]
    assert contact.metadata["emails"] == ["ada@example.test"]
    sms = next(item for item in artifacts if item.subtype == "smart_switch_message")
    assert sms.summary == "Readable SMS"
    assert sms.event_time is not None and sms.event_time.year == 2024
