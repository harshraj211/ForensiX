"""Unencrypted legacy Android Backup parsing from a supplied file."""

import io
import sqlite3
import tarfile
import zlib
from pathlib import Path

from forensix_forensic.evidence_io import ParserContext
from forensix_forensic.extractors.legacy_android_backup import LegacyAndroidBackupParser


def test_legacy_ab_indexes_tar_members_and_android_sqlite(tmp_path: Path) -> None:
    database = tmp_path / "mmssms.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE sms (_id INTEGER, date INTEGER, type INTEGER, address TEXT, body TEXT)"
    )
    connection.execute("INSERT INTO sms VALUES (1, 1704067200000, 1, '+15550001', 'Backup SMS')")
    connection.commit()
    connection.close()
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode="w") as archive:
        payload = database.read_bytes()
        info = tarfile.TarInfo("apps/com.android.providers.telephony/db/mmssms.db")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    backup = tmp_path / "legacy.ab"
    backup.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(tar_data.getvalue()))
    context = ParserContext(
        case_id="CASE",
        evidence_source_id="SOURCE",
        working_copy_id="COPY",
        source_sha256="0" * 64,
        source_label="legacy.ab",
    )

    artifacts = LegacyAndroidBackupParser().parse(backup, context)

    assert {item.subtype for item in artifacts} == {
        "android_backup_summary",
        "android_backup_file",
        "sms",
    }
    sms = next(item for item in artifacts if item.subtype == "sms")
    assert sms.metadata["package_name"] == "com.android.providers.telephony"
    assert sms.source_locator.startswith("apps/com.android.providers.telephony/db/mmssms.db#")
    assert artifacts[0].metadata["record_counts"] == {"android_backup_file": 1, "sms": 1}
