"""Unit tests for Tier-1 Deep Forensic Suite router endpoints."""

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
        case = CaseService().create(session, principal, title="Deep Forensic Case")
        case_id = case.id
        token = issued.session_token
        csrf_token = issued.csrf_token

    client.cookies.set("forensix_session", token)
    client.cookies.set("forensix_csrf", csrf_token)
    client.headers["X-CSRF-Token"] = csrf_token

    return client, case_id


def test_keystore_vault_decrypt_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "admin_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/deep/keystore-vault-decrypt", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["decrypted_vaults"]) > 0


def test_raw_disk_carve_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "admin_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/deep/raw-disk-carve", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["carved_media_items"]) > 0
    assert data["gps_locations_plotted_count"] > 0


def test_identity_persona_correlate_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "admin_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/deep/identity-persona-correlate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["personas"]) > 0


def test_fbe_state_matrix_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "admin_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/deep/fbe-state-matrix", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["partitions"]) > 0


def test_ai_vision_ocr_record_endpoint(tmp_path: Path) -> None:
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {
        "serial": "emulator-5554",
        "case_id": case_id,
        "target_app": "com.whatsapp",
        "operator_id": "admin_examiner",
    }
    resp = client.post(f"/api/v1/cases/{case_id}/deep/ai-vision-ocr-record", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert len(data["transcribed_messages"]) == 0
