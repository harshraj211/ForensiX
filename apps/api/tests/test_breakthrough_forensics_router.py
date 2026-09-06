"""Unit tests for Breakthrough Forensic Suite API router."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings


def _create_authenticated_client(tmp_path: Path):
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    client = TestClient(app)

    db = app.state.database
    db.initialize()
    with db.session() as session:
        auth_service = AuthService(settings)
        auth_service.ensure_roles(session)
        issued = auth_service.bootstrap_administrator(
            session,
            username="breakthrough_examiner",
            display_name="Breakthrough Examiner",
            password="StrongPassword123!",
        )
        principal = issued.principal
        case = CaseService().create(session, principal, title="Breakthrough Case")
        case_id = case.id
        token = issued.session_token
        csrf_token = issued.csrf_token

    client.cookies.set("forensix_session", token)
    client.cookies.set("forensix_csrf", csrf_token)
    client.headers["X-CSRF-Token"] = csrf_token

    return client, case_id


def test_cloud_token_replay(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "breakthrough_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/breakthrough/cloud-token-replay", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["success"] is False
    assert data["total_artifacts_synced"] == 0
    assert len(data["synced_services"]) == 0


def test_live_touch_record(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {
        "serial": "emulator-5554",
        "case_id": case_id,
        "duration_sec": 15,
        "operator_id": "breakthrough_examiner",
    }
    resp = client.post(f"/api/v1/cases/{case_id}/breakthrough/live-touch-record", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["fps"] == 60
    assert data["sha256_seal"].startswith("SEAL-")


def test_timeline_anomaly_scan(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "breakthrough_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/breakthrough/timeline-anomaly-scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["success"] is False
    assert len(data["anomalies_detected"]) == 0


def test_physical_image_mount(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "image_path": "data/userdata.img"}
    resp = client.post(f"/api/v1/cases/{case_id}/breakthrough/physical-image-mount", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert len(data["carved_inodes"]) == 2
    assert data["filesystem_type"].startswith("EXT4")
