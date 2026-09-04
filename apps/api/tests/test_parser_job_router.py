"""Tests for parser background jobs and artifact search API endpoints."""

import sqlite3
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings
from forensix_server.evidence_twin import EvidenceExaminationService, EvidenceTwinService


def _contacts_db(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, deleted INTEGER);
        CREATE TABLE data (
            _id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER,
            data1 TEXT, data2 TEXT, data3 TEXT
        );
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/name');
        INSERT INTO mimetypes VALUES (2, 'vnd.android.cursor.item/phone_v2');
        INSERT INTO raw_contacts VALUES (10, 0);
        INSERT INTO data VALUES (1, 10, 1, 'Sarah Connor', NULL, NULL);
        INSERT INTO data VALUES (2, 10, 2, '+15550199000', '2', 'Mobile');
        """
    )
    connection.commit()
    connection.close()
    return path.read_bytes()


def test_parser_job_api_lifecycle_and_search(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    mock_adb = MagicMock()
    app = create_app(settings, adb_client=mock_adb)

    with TestClient(app) as client:
        db = app.state.database
        with db.session() as session:
            auth_service = AuthService(settings)
            auth_service.ensure_roles(session)
            issued = auth_service.bootstrap_administrator(
                session,
                username="parser_admin",
                display_name="Parser Admin",
                password="StrongPassword123!",
            )
            principal = issued.principal
            case = CaseService().create(session, principal, title="Parser Job Case")
            case_id = case.id
            token = issued.session_token
            csrf_token = issued.csrf_token
            session.commit()

        source = EvidenceTwinService().import_stream(
            db,
            principal,
            case_id,
            BytesIO(_contacts_db(tmp_path / "contacts2.db")),
            source_name="contacts2.db",
        )
        working_copy = EvidenceTwinService().create_working_copy(db, principal, case_id, source.id)
        source_id = source.id
        working_copy_id = working_copy.id

        client.cookies.set("forensix_session", token)
        client.cookies.set("forensix_csrf", csrf_token)
        headers = {"X-CSRF-Token": csrf_token}

        # 1. Create parser job (background task)
        post_res = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/{source_id}/working-copies/{working_copy_id}/parser-jobs",
            json={"parser_ids": None},
            headers=headers,
        )
        assert post_res.status_code == 202
        job_data = post_res.json()
        assert job_data["id"] is not None
        assert job_data["case_id"] == case_id
        assert job_data["progress_percent"] >= 5
        job_id = job_data["id"]

        # 2. Get parser job status
        get_res = client.get(f"/api/v1/cases/{case_id}/evidence-sources/parser-jobs/{job_id}")
        assert get_res.status_code == 200
        fetched_job = get_res.json()
        assert fetched_job["id"] == job_id
        assert fetched_job["state"] in ("ready", "running", "completed")

        # 3. Search parsed artifacts via FTS5
        search_res = client.get(
            f"/api/v1/cases/{case_id}/evidence-sources/artifacts/search?q=Sarah"
        )
        assert search_res.status_code == 200
        search_data = search_res.json()
        assert search_data["total"] >= 1
        assert any("Sarah Connor" in item["title"] for item in search_data["items"])

        # 4. Test cancellation endpoint
        prep_job = EvidenceExaminationService().prepare_parser_job(
            db, principal, case_id, source_id, working_copy_id
        )
        cancel_res = client.post(
            f"/api/v1/cases/{case_id}/evidence-sources/parser-jobs/{prep_job.id}/cancel",
            headers=headers,
        )
        assert cancel_res.status_code == 200
        assert cancel_res.json()["state"] == "cancelled"
        assert cancel_res.json()["cancellation_requested"] is True
