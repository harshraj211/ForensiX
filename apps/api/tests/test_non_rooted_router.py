"""Unit tests for non-rooted extraction router endpoints."""

from pathlib import Path
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
            username="admin_examiner",
            display_name="Admin Examiner",
            password="StrongPassword123!",
        )
        principal = issued.principal
        case = CaseService().create(session, principal, title="Non-Rooted Case")
        case_id = case.id
        token = issued.session_token
        csrf_token = issued.csrf_token

    client.cookies.set("forensix_session", token)
    client.cookies.set("forensix_csrf", csrf_token)
    client.headers["X-CSRF-Token"] = csrf_token

    return client, case_id


def test_dumpsys_telemetry_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "admin_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/non-rooted/dumpsys-telemetry", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["serial"] == "emulator-5554"
    assert "usage_stats" in data
    assert "wifi_networks" in data
    assert "bluetooth_devices" in data


def test_vendor_backup_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {
        "serial": "emulator-5554",
        "case_id": case_id,
        "vendor_type": "samsung_smartswitch",
        "operator_id": "admin_examiner",
    }
    resp = client.post(f"/api/v1/cases/{case_id}/non-rooted/vendor-backup", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["vendor_type"] == "samsung_smartswitch"
    assert len(data["extracted_items"]) > 0


def test_accessibility_scrape_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {
        "serial": "emulator-5554",
        "case_id": case_id,
        "target_package": "com.whatsapp",
        "operator_id": "admin_examiner",
    }
    resp = client.post(f"/api/v1/cases/{case_id}/non-rooted/accessibility-scrape", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["target_package"] == "com.whatsapp"
    assert len(data["transcripts"]) > 0


def test_content_provider_harvest_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "admin_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/non-rooted/content-provider-harvest", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["queried_uris"]) > 0


def test_cloud_tokens_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "admin_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/non-rooted/cloud-tokens", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["extracted_tokens"]) > 0
