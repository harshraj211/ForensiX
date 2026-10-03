"""Five provider imports exercised through custody, search, timeline and report export."""

import json
from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from forensix_api.main import create_app
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings
from forensix_server.db import EvidenceSourceRecord, EvidenceSourceTimelineEventRecord


@pytest.fixture
def authorized(tmp_path):
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="cloud_admin",
                display_name="Cloud Admin",
                password="StrongPassword123!",
            )
            case_id = CaseService().create(session, issued.principal, title="Cloud export case").id
        client.cookies.set("forensix_session", issued.session_token)
        client.cookies.set("forensix_csrf", issued.csrf_token)
        yield client, app.state.database, case_id, {"X-CSRF-Token": issued.csrf_token}


def payload(provider):
    files = {
        "google": (
            "Takeout/Chrome/BrowserHistory.json",
            json.dumps(
                {
                    "Browser History": [
                        {
                            "title": "CloudProof unique",
                            "url": "https://example.org",
                            "time_usec": 1790830800000000,
                        }
                    ]
                }
            ),
        ),
        "whatsapp": (
            "WhatsApp Chat with Alice.txt",
            "01/10/2026, 12:30 - Alice: CloudProof unique",
        ),
        "microsoft": (
            "mail.json",
            json.dumps(
                {
                    "value": [
                        {
                            "subject": "CloudProof unique",
                            "receivedDateTime": "2026-10-01T07:00:00Z",
                            "body": {"content": "Evidence body"},
                        }
                    ]
                }
            ),
        ),
        "telegram": (
            "result.json",
            json.dumps(
                {
                    "id": 1,
                    "name": "Proof chat",
                    "messages": [
                        {
                            "id": 1,
                            "date": "2026-10-01T07:00:00Z",
                            "from": "Alice",
                            "text": "CloudProof unique",
                        }
                    ],
                }
            ),
        ),
        "icloud": (
            "calendar.ics",
            "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:one\nSUMMARY:CloudProof unique\nDTSTART:20261001T070000Z\nEND:VEVENT\nEND:VCALENDAR",
        ),
    }
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(*files[provider])
        archive.writestr("photos/proof.jpg", b"preserved photo original")
        archive.writestr("unsupported.bin", b"unknown original")
        archive.writestr("broken.json", "{broken")
    return buffer.getvalue()


@pytest.mark.parametrize("provider", ["google", "whatsapp", "microsoft", "telegram", "icloud"])
def test_provider_full_case_pipeline(authorized, provider):
    client, database, case_id, headers = authorized
    original = payload(provider)
    base = f"/api/v1/cases/{case_id}"
    response = client.post(
        f"{base}/evidence-sources/import/cloud-export",
        data={"provider": provider, "source_timezone": "Asia/Kolkata", "date_order": "DMY"},
        files={"source": ("export.zip", original, "application/zip")},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    source_id = body["evidence_source"]["id"]
    run = body["parser_run"]
    assert run["status"] == "completed", run["error_message"]
    assert run["parser_id"] == f"cloud.{provider}.export"
    assert body["summary"]["parsed_count"] == 1
    assert body["summary"]["malformed_count"] == 1
    assert body["summary"]["unsupported_count"] == 1
    assert body["summary"]["preserved_file_count"] == 1
    assert body["evidence_source"]["sha256"] == sha256(original).hexdigest()
    assert body["evidence_source"]["acquisition_level"] == "logical"
    with database.session() as session:
        record = session.get(EvidenceSourceRecord, source_id)
        assert (
            EvidenceStore(database.data_dir / "evidence")
            .resolve(record.sealed_storage_key, require_file=True)
            .read_bytes()
            == original
        )
        event = session.scalar(
            select(EvidenceSourceTimelineEventRecord).where(
                EvidenceSourceTimelineEventRecord.parser_run_id == run["id"]
            )
        )
        assert event is not None
        if provider == "whatsapp":
            assert event.timezone_basis == "Examiner-selected timezone Asia/Kolkata"
    stored = client.get(f"{base}/evidence-sources/{source_id}/cloud-export-summary")
    assert stored.status_code == 200, stored.text
    assert stored.json()["summary"] == {**body["summary"], "operation": "cloud_export_import"}
    searched = client.get(
        f"{base}/evidence-sources/artifacts/search", params={"q": "CloudProof unique"}
    )
    assert searched.status_code == 200, searched.text
    assert searched.json()["total"] == 1
    artifact = searched.json()["items"][0]
    assert artifact["evidence_source_id"] == source_id
    # Idempotent replay on the same working copy must not duplicate artifacts or events.
    replay = client.post(
        f"{base}/evidence-sources/{source_id}/working-copies/{run['working_copy_id']}/native-parsers",
        json={"parser_ids": [run["parser_id"]]},
        headers=headers,
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()[0]["id"] == run["id"]
    custody = client.get(f"{base}/custody/verify")
    assert custody.status_code == 200, custody.text
    report = client.post(f"{base}/reports", json={}, headers=headers)
    assert report.status_code == 201, report.text
    report_id = report.json()["id"]
    exported = client.get(f"{base}/reports/{report_id}/download/json")
    assert exported.status_code == 200, exported.text
    exported_artifact = next(
        item for item in exported.json()["imported_artifacts"] if item["id"] == artifact["id"]
    )
    assert exported_artifact["artifact_hash"] == artifact["artifact_hash"]
    assert len(exported.json()["timeline"]) == 1
    assert any(
        item["subtype"] == "cloud_export_summary" for item in exported.json()["imported_artifacts"]
    )


@pytest.mark.parametrize("input_case", ["wrong-provider", "traversal", "only-encrypted"])
def test_failed_import_has_sealed_original_and_visible_failure(authorized, input_case):
    client, _, case_id, headers = authorized
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        if input_case == "traversal":
            archive.writestr("../outside.txt", "Proof")
        elif input_case == "only-encrypted":
            archive.writestr("msgstore.db.crypt15", b"encrypted")
        else:
            archive.writestr("result.json", '{"unrecognized": "schema"}')
    response = client.post(
        f"/api/v1/cases/{case_id}/evidence-sources/import/cloud-export",
        data={"provider": "whatsapp"},
        files={"source": ("failure.zip", buffer.getvalue())},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["parser_run"]["status"] == "failed"
    assert body["parser_run"]["artifact_count"] == 0
    assert body["evidence_source"]["sha256"] == sha256(buffer.getvalue()).hexdigest()
    stored = client.get(
        f"/api/v1/cases/{case_id}/evidence-sources/{body['evidence_source']['id']}/cloud-export-summary"
    )
    assert stored.json()["parser_run"]["status"] == "failed"


def test_csrf_configuration_and_case_validation(authorized):
    client, _, case_id, headers = authorized
    base = f"/api/v1/cases/{case_id}/evidence-sources/import/cloud-export"
    args = {"data": {"provider": "google"}, "files": {"source": ("export.zip", payload("google"))}}
    assert client.post(base, **args).status_code == 403
    for settings in (
        {"provider": "unknown"},
        {"provider": "google", "source_timezone": "bad/zone"},
        {"provider": "google", "date_order": "guess"},
    ):
        invalid = client.post(base, data=settings, files=args["files"], headers=headers)
        assert invalid.status_code == 422, invalid.text
    missing = client.post(
        "/api/v1/cases/00000000-0000-0000-0000-000000000000/evidence-sources/import/cloud-export",
        **args,
        headers=headers,
    )
    assert missing.status_code == 404, missing.text


def test_upload_limit_and_legacy_takeout_delegate(authorized, monkeypatch):
    client, _, case_id, headers = authorized
    import forensix_server.evidence_twin.cloud_exports as module

    original = payload("google")
    legacy = client.post(
        f"/api/v1/cases/{case_id}/takeout/import",
        files={"file": ("takeout.zip", original)},
        headers=headers,
    )
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["imported_events"] == 1
    assert legacy.json()["status"] == "completed"
    monkeypatch.setattr(module, "MAX_UPLOAD_BYTES", 4)
    too_big = client.post(
        f"/api/v1/cases/{case_id}/evidence-sources/import/cloud-export",
        data={"provider": "google"},
        files={"source": ("export.zip", original)},
        headers=headers,
    )
    assert too_big.status_code == 422, too_big.text


def test_manifest_tampering_blocks_summary_and_parser_replay(authorized):
    import stat

    client, database, case_id, headers = authorized
    base = f"/api/v1/cases/{case_id}/evidence-sources"
    response = client.post(
        f"{base}/import/cloud-export",
        data={"provider": "telegram"},
        files={"source": ("result.json", b'{"messages": [{"text": "Proof"}]}')},
        headers=headers,
    )
    body = response.json()
    source_id = body["evidence_source"]["id"]
    with database.session() as session:
        source = session.get(EvidenceSourceRecord, source_id)
        path = EvidenceStore(database.data_dir / "evidence").resolve(
            source.manifest_storage_key, require_file=True
        )
    path.chmod(stat.S_IWRITE | stat.S_IREAD)
    path.write_text(
        '{"acquisition_metadata": {"operation": "cloud_export_import", "provider": "google"}}'
    )
    summary = client.get(f"{base}/{source_id}/cloud-export-summary")
    assert summary.status_code == 409, summary.text
    assert "manifest hash" in summary.json()["error"]["message"]
    replay = client.post(
        f"{base}/{source_id}/working-copies/{body['parser_run']['working_copy_id']}/native-parsers",
        json={},
        headers=headers,
    )
    assert replay.status_code == 409, replay.text


def test_missing_analysis_permission_and_closed_case_precede_intake(authorized):
    from datetime import UTC, datetime, timedelta

    from forensix_api.dependencies import require_csrf_session
    from forensix_server.auth import AuthenticatedSession, Permission, Principal, RoleName
    from forensix_server.db import CaseRecord

    client, database, case_id, headers = authorized
    with database.session() as session:
        case = session.get(CaseRecord, case_id)
        user_id = case.created_by
    principal = Principal(
        user_id=user_id,
        username="limited",
        display_name="Limited",
        roles=frozenset({RoleName.ADMINISTRATOR}),
        permissions=frozenset({Permission.CASES_READ, Permission.ACQUISITIONS_OPERATE}),
    )
    authenticated = AuthenticatedSession(
        session_id="test",
        principal=principal,
        csrf_hash="test",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    client.app.dependency_overrides[require_csrf_session] = lambda: authenticated
    args = {
        "data": {"provider": "google"},
        "files": {"source": ("export.zip", payload("google"))},
        "headers": headers,
    }
    denied = client.post(f"/api/v1/cases/{case_id}/evidence-sources/import/cloud-export", **args)
    assert denied.status_code == 403, denied.text
    client.app.dependency_overrides.clear()
    with database.session() as session:
        case = session.get(CaseRecord, case_id)
        case.status = "closed"
    closed = client.post(f"/api/v1/cases/{case_id}/evidence-sources/import/cloud-export", **args)
    assert closed.status_code == 409, closed.text
    with database.session() as session:
        assert session.scalar(select(EvidenceSourceRecord)) is None
