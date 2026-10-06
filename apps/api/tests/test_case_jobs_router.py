"""Unified durable-job observation API tests."""

from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings
from forensix_server.jobs import JobService, JobState, JobType


def test_case_jobs_list_filter_status_and_events(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings, adb_client=MagicMock())

    with TestClient(app) as client:
        with app.state.database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="job_admin",
                display_name="Job Admin",
                password="StrongPassword123!",
            )
            case = CaseService().create(session, issued.principal, title="Unified Jobs")
            case_id = case.id

            parser_job = JobService().create(
                session,
                JobType.PARSING,
                owner_id=issued.principal.user_id,
                case_id=case_id,
            )
            JobService().transition(session, parser_job.id, JobState.VALIDATING)
            JobService().update_progress(
                session,
                parser_job.id,
                25,
                current_step="Inspecting SQLite evidence",
                current_module="android_artifacts",
                checkpoint={"source_id": "source-1"},
            )
            acquisition_job = JobService().create(
                session,
                JobType.ACQUISITION,
                owner_id=issued.principal.user_id,
                case_id=case_id,
            )
            session.commit()
            parser_job_id = parser_job.id
            acquisition_job_id = acquisition_job.id

        client.cookies.set("forensix_session", issued.session_token)

        response = client.get(f"/api/v1/cases/{case_id}/jobs")
        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 2
        assert {item["job_type"] for item in payload["items"]} == {
            "acquisition",
            "parsing",
        }

        filtered = client.get(f"/api/v1/cases/{case_id}/jobs?job_type=parsing")
        assert filtered.status_code == 200
        assert filtered.json()["total"] == 1
        assert filtered.json()["items"][0]["checkpoint"] == {"source_id": "source-1"}

        status_response = client.get(f"/api/v1/cases/{case_id}/jobs/{parser_job_id}")
        assert status_response.status_code == 200
        assert status_response.json()["current_module"] == "android_artifacts"
        assert status_response.json()["progress_percent"] == 25

        events = client.get(f"/api/v1/cases/{case_id}/jobs/{parser_job_id}/events")
        assert events.status_code == 200
        assert [event["sequence"] for event in events.json()] == [1, 2, 3]
        assert events.json()[-1]["event_type"] == "progress_updated"

        wrong_job = client.get(f"/api/v1/cases/{case_id}/jobs/{acquisition_job_id}-missing")
        assert wrong_job.status_code == 404


def test_case_jobs_require_authentication(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings, adb_client=MagicMock())
    with TestClient(app) as client:
        response = client.get("/api/v1/cases/not-a-case/jobs")
        assert response.status_code == 401
