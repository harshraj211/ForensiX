"""An exported agent collection becomes a verified logical case source."""

import json
import tarfile
import zlib
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

from fastapi.testclient import TestClient
from sqlalchemy import select

from forensix_api.main import create_app
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings
from forensix_server.db import (
    EvidenceSourceArtifactRecord,
    EvidenceSourceRecord,
    EvidenceSourceTimelineEventRecord,
)


def _bundle(*, denied: bool = False, corrupt: bool = False) -> bytes:
    files = {
        "contacts.json": json.dumps(
            [{"name": "Alice", "phone_numbers": ["123"], "emails": ["alice@example.test"]}]
        ).encode(),
        "sms.json": json.dumps(
            [
                {
                    "address": "+15550001111",
                    "body": "Known agent SMS",
                    "date_ms": 1700000000000,
                    "type": 1,
                    "thread_id": 42,
                }
            ]
        ).encode(),
        "call_logs.json": json.dumps(
            [
                {
                    "number": "+15550002222",
                    "type": 2,
                    "date_ms": 1700000100000,
                    "duration_seconds": 31,
                    "name": "Bob",
                }
            ]
        ).encode(),
        "installed_apps.json": json.dumps(
            [
                {
                    "package_name": "com.example.chat",
                    "app_label": "Example Chat",
                    "version_name": "5.0",
                    "install_time_ms": 1700000200000,
                    "is_system": False,
                    "surfaces": {"shared_storage": "available"},
                }
            ]
        ).encode(),
        "device_metadata.json": json.dumps(
            {
                "source": "android_agent",
                "category": "device_metadata",
                "collected_at_ms": 1700000300000,
                "data": {"android_release": "14", "device": "test-device"},
                "availability_map": {"sms": "ok", "contacts": "ok"},
            }
        ).encode(),
        "app_artifacts.json": json.dumps(
            [
                {
                    "package_name": "com.example.chat",
                    "artifact_category": "shared_storage",
                    "relative_path": "Download/example.txt",
                    "absolute_path": "/sdcard/Download/example.txt",
                    "size_bytes": 12,
                    "last_modified_ms": 1700000400000,
                    "mime_type": "text/plain",
                    "sha256_hash": "a" * 64,
                    "accessibility_status": "available",
                }
            ]
        ).encode(),
    }
    manifest = {
        "format": "forensix-agent-v1",
        "collection_id": str(uuid4()),
        "complete": not denied,
        "files": {
            name: {
                "sha256": sha256(data).hexdigest(),
                "bytes": len(data),
                "status": "permission_denied" if denied and name == "sms.json" else "ok",
            }
            for name, data in files.items()
        },
    }
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in files.items():
            archive.writestr(name, data + b"bad" if corrupt and name == "sms.json" else data)
    return output.getvalue()


def test_agent_bundle_is_sealed_as_logical_source(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="agent_admin",
                display_name="Agent Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Agent Case").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        headers = {"X-CSRF-Token": issued.csrf_token}

        payload = _bundle(denied=True)
        response = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/agent-bundle",
            files={"source": ("collection.fxz", payload, "application/zip")},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["collection_complete"] is False
        assert body["source_statuses"]["sms.json"] == "permission_denied"
        assert body["record_counts"]["contacts"] == 1
        assert body["evidence_source"]["acquisition_level"] == "logical"
        assert body["evidence_source"]["container_format"] == "zip"
        assert body["evidence_source"]["sha256"] == sha256(payload).hexdigest()
        summary = client.get(
            f"/api/v1/cases/{case_id}/evidence-sources/"
            f"{body['evidence_source']['id']}/agent-bundle-summary"
        )
        assert summary.status_code == 200
        assert summary.json()["collection_id"] == body["collection_id"]
        assert summary.json()["source_statuses"] == body["source_statuses"]
        with database.session() as session:
            record = session.get(EvidenceSourceRecord, body["evidence_source"]["id"])
            assert record is not None
            path = EvidenceStore(database.data_dir / "evidence").resolve(
                record.sealed_storage_key, require_file=True
            )
            assert path.read_bytes() == payload

        invalid = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/agent-bundle",
            files={"source": ("bad.fxz", _bundle(corrupt=True), "application/zip")},
            headers=headers,
        )
        assert invalid.status_code == 422


def test_device_backup_import_inspects_and_seals_original_bytes(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    archive = BytesIO()
    with ZipFile(archive, "w") as backup:
        backup.writestr("contacts/contacts.vcf", b"BEGIN:VCARD\nFN:Alice\nTEL:123\nEND:VCARD\n")
        backup.writestr("messages/messages.db", b"SQLite format 3\x00")
    payload = archive.getvalue()
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="backup_admin",
                display_name="Backup Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Backup Case").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        response = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/device-backup",
            files={"source": ("SmartSwitch.sbu", payload, "application/zip")},
            headers={"X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["backup_kind"] == "samsung_smart_switch_archive"
        assert body["parser_run_id"]
        assert body["parsed_artifact_count"] == 4
        assert body["parser_status"] == "completed"
        assert body["encrypted"] is False
        assert body["package_hints"] == ["contacts", "messages"]
        assert body["evidence_source"]["sha256"] == sha256(payload).hexdigest()
        with database.session() as session:
            record = session.get(EvidenceSourceRecord, body["evidence_source"]["id"])
            assert record is not None and record.manifest_storage_key
            manifest = EvidenceStore(database.data_dir / "evidence").resolve(
                record.manifest_storage_key, require_file=True
            )
            metadata = json.loads(manifest.read_text())["acquisition_metadata"]
            assert metadata["operation"] == "android_backup_import"
            assert metadata["backup_inspection"]["member_count"] == 2
            artifacts = session.scalars(
                select(EvidenceSourceArtifactRecord).where(
                    EvidenceSourceArtifactRecord.parser_run_id == body["parser_run_id"]
                )
            ).all()
            assert {artifact.subtype for artifact in artifacts} == {
                "smart_switch_summary",
                "smart_switch_member",
                "smart_switch_contact",
            }
            contact = next(item for item in artifacts if item.subtype == "smart_switch_contact")
            assert "Alice" in contact.title


def test_smart_switch_pc_folder_upload_preserves_member_hashes(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="folder_admin",
                display_name="Folder Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="PC Folder").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        folder = "SM-S908N_BACKUP"
        paths = [f"{folder}/CONTACT/contacts.spbm", f"{folder}/CONTACT/contacts.csv"]
        response = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/smart-switch-folder",
            files=[
                (
                    "files",
                    ("contacts.spbm", b"opaque-vendor-contact-data", "application/octet-stream"),
                ),
                ("files", ("contacts.csv", b"name,phone\nAlice,12345\n", "text/csv")),
            ],
            data={"relative_paths": paths},
            headers={"X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["backup_kind"] == "samsung_smart_switch_archive"
        assert body["parser_status"] == "completed"
        assert body["parsed_artifact_count"] == 4
        with database.session() as session:
            record = session.get(EvidenceSourceRecord, body["evidence_source"]["id"])
            assert record is not None and record.manifest_storage_key
            manifest = EvidenceStore(database.data_dir / "evidence").resolve(
                record.manifest_storage_key, require_file=True
            )
            metadata = json.loads(manifest.read_text())["acquisition_metadata"]["backup_inspection"]
            members = metadata["source_assembly"]["members"]
            assert members[0] == {
                "path": paths[0],
                "sha256": sha256(b"opaque-vendor-contact-data").hexdigest(),
                "size_bytes": len(b"opaque-vendor-contact-data"),
            }
            artifacts = session.scalars(
                select(EvidenceSourceArtifactRecord).where(
                    EvidenceSourceArtifactRecord.parser_run_id == body["parser_run_id"]
                )
            ).all()
            assert any(
                item.subtype == "smart_switch_contact" and item.title == "Alice"
                for item in artifacts
            )
            assert any(
                item.subtype == "smart_switch_member" and item.title == "contacts.spbm"
                for item in artifacts
            )


def test_smart_switch_pc_folder_rejects_traversal(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="path_admin",
                display_name="Path Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Path Check").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        response = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/smart-switch-folder",
            files=[("files", ("bad.csv", b"name,phone\nAlice,123\n", "text/csv"))],
            data={"relative_paths": "../bad.csv"},
            headers={"X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 422
        duplicate = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/smart-switch-folder",
            files=[
                ("files", ("first.csv", b"name,phone\nA,1\n", "text/csv")),
                ("files", ("second.csv", b"name,phone\nB,2\n", "text/csv")),
            ],
            data={"relative_paths": ["Backup/CONTACT/people.csv", "backup/contact/PEOPLE.csv"]},
            headers={"X-CSRF-Token": issued.csrf_token},
        )
        assert duplicate.status_code == 422


def test_legacy_android_backup_import_indexes_verified_tar_members(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    tar_data = BytesIO()
    with tarfile.open(fileobj=tar_data, mode="w") as archive:
        payload = b"shared photo"
        info = tarfile.TarInfo("shared/0/DCIM/photo.jpg")
        info.size = len(payload)
        archive.addfile(info, BytesIO(payload))
    backup = b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(tar_data.getvalue())
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="legacy_admin",
                display_name="Legacy Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Legacy Backup").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        response = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/device-backup",
            files={"source": ("legacy.ab", backup, "application/octet-stream")},
            headers={"X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["backup_kind"] == "legacy_android_backup"
        assert body["parser_status"] == "completed"
        assert body["parsed_artifact_count"] == 2
        with database.session() as session:
            artifacts = session.scalars(
                select(EvidenceSourceArtifactRecord).where(
                    EvidenceSourceArtifactRecord.parser_run_id == body["parser_run_id"]
                )
            ).all()
            assert {item.subtype for item in artifacts} == {
                "android_backup_summary",
                "android_backup_file",
            }


def test_encrypted_android_backup_is_sealed_without_parser_run(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    backup = b"ANDROID BACKUP\n5\n0\nAES-256\nencrypted-payload"
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="encrypted_admin",
                display_name="Encrypted Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Encrypted Backup").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        response = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/device-backup",
            files={"source": ("encrypted.ab", backup, "application/octet-stream")},
            headers={"X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["encrypted"] is True
        assert body["parser_run_id"] is None
        assert body["parser_status"] is None
        assert body["evidence_source"]["sha256"] == sha256(backup).hexdigest()


def test_fat32_card_image_import_indexes_deleted_candidate(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    image = bytearray(10 * 512)
    image[11:13] = (512).to_bytes(2, "little")
    image[13] = 1
    image[14:16] = (1).to_bytes(2, "little")
    image[16] = 1
    image[32:36] = (10).to_bytes(4, "little")
    image[36:40] = (1).to_bytes(4, "little")
    image[44:48] = (2).to_bytes(4, "little")
    image[82:90] = b"FAT32   "
    image[510:512] = b"\x55\xaa"
    for cluster in (0, 1, 2, 3):
        image[512 + cluster * 4 : 516 + cluster * 4] = (0x0FFFFFFF).to_bytes(4, "little")
    image[1024:1035] = b"HELLO   TXT"
    image[1035] = 0x20
    image[1050:1052] = (3).to_bytes(2, "little")
    image[1052:1056] = (5).to_bytes(4, "little")
    image[1056:1067] = b"\xe5OST    JPG"
    image[1067] = 0x20
    image[1082:1084] = (4).to_bytes(2, "little")
    image[1084:1088] = (4).to_bytes(4, "little")
    image[1536:1541] = b"hello"
    image[2048:2052] = b"\xff\xd8\xff\xd9"
    payload = bytes(image)
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="card_admin",
                display_name="Card Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Card Case").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        response = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/device-backup",
            files={"source": ("card.img", payload, "application/octet-stream")},
            headers={"X-CSRF-Token": issued.csrf_token},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["backup_kind"] == "memory_card_image"
        assert body["filesystem_type"] == "fat32"
        assert body["parser_status"] == "completed"
        assert body["parsed_artifact_count"] == 3
        assert body["evidence_source"]["sha256"] == sha256(payload).hexdigest()
        with database.session() as session:
            artifacts = session.scalars(
                select(EvidenceSourceArtifactRecord).where(
                    EvidenceSourceArtifactRecord.parser_run_id == body["parser_run_id"]
                )
            ).all()
            assert {item.subtype for item in artifacts} == {
                "memory_card_summary",
                "memory_card_file",
                "memory_card_deleted_candidate",
            }
            deleted = next(
                item for item in artifacts if item.subtype == "memory_card_deleted_candidate"
            )
            assert deleted.status == "deleted"
            deleted_id = deleted.id
            live_id = next(item.id for item in artifacts if item.subtype == "memory_card_file")
        recovered = client.get(
            f"/api/v1/cases/{case_id}/evidence-sources/{body['evidence_source']['id']}"
            f"/artifacts/{deleted_id}/candidate-content"
        )
        assert recovered.status_code == 200, recovered.text
        assert recovered.content == b"\xff\xd8\xff\xd9"
        assert (
            recovered.headers["X-ForensiX-Candidate-SHA256"]
            == sha256(recovered.content).hexdigest()
        )
        live_file = client.get(
            f"/api/v1/cases/{case_id}/evidence-sources/{body['evidence_source']['id']}"
            f"/artifacts/{live_id}/file-content"
        )
        assert live_file.status_code == 200, live_file.text
        assert live_file.content == b"hello"
        assert live_file.headers["X-ForensiX-File-SHA256"] == sha256(live_file.content).hexdigest()
        non_candidate = client.get(
            f"/api/v1/cases/{case_id}/evidence-sources/{body['evidence_source']['id']}"
            f"/artifacts/{live_id}/candidate-content"
        )
        assert non_candidate.status_code == 404


def test_agent_bundle_parser_indexes_records_for_search_timeline_and_reports(
    tmp_path: Path,
) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    with TestClient(app) as client:
        database = app.state.database
        with database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="agent_admin",
                display_name="Agent Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Agent Case").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        headers = {"X-CSRF-Token": issued.csrf_token}

        uploaded = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/import/agent-bundle",
            files={"source": ("collection.fxz", _bundle(), "application/zip")},
            headers=headers,
        )
        assert uploaded.status_code == 201, uploaded.text
        source_id = uploaded.json()["evidence_source"]["id"]
        working_copy = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/{source_id}/working-copies",
            headers=headers,
        )
        assert working_copy.status_code == 201, working_copy.text
        working_copy_id = working_copy.json()["id"]

        parsed = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/{source_id}/working-copies/"
            f"{working_copy_id}/native-parsers",
            json={"parser_ids": ["android.agent_bundle.v1"]},
            headers=headers,
        )
        assert parsed.status_code == 200, parsed.text
        assert parsed.json()[0]["parser_id"] == "android.agent_bundle.v1"
        assert parsed.json()[0]["artifact_count"] == 6

        search = client.get(
            f"/api/v1/cases/{case_id}/evidence-sources/artifacts/search?q=Known%20agent%20SMS"
        )
        assert search.status_code == 200, search.text
        assert search.json()["total"] == 1
        assert search.json()["items"][0]["subtype"] == "agent_sms"

        report = client.post(f"/api/v1/cases/{case_id}/reports", json={}, headers=headers)
        assert report.status_code == 201, report.text
        json_output = next(item for item in report.json()["outputs"] if item["format"] == "json")
        downloaded = client.get(
            f"/api/v1/cases/{case_id}/reports/{report.json()['id']}/download/"
            f"{json_output['format']}"
        )
        assert downloaded.status_code == 200, downloaded.text
        report_payload = downloaded.json()
        assert {item["subtype"] for item in report_payload["imported_artifacts"]} == {
            "agent_app_artifact",
            "agent_call_log",
            "agent_contact",
            "agent_device_metadata",
            "agent_installed_app",
            "agent_sms",
        }
        assert len(report_payload["timeline"]) == 5

        with database.session() as session:
            assert len(list(session.scalars(select(EvidenceSourceTimelineEventRecord)))) == 5
