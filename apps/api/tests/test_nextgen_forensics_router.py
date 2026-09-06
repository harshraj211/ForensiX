"""Unit tests for Next-Gen Non-Rooted Forensic Suite API router."""

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
            username="nextgen_examiner",
            display_name="NextGen Examiner",
            password="StrongPassword123!",
        )
        principal = issued.principal
        case = CaseService().create(session, principal, title="NextGen Case")
        case_id = case.id
        token = issued.session_token
        csrf_token = issued.csrf_token

    client.cookies.set("forensix_session", token)
    client.cookies.set("forensix_csrf", csrf_token)
    client.headers["X-CSRF-Token"] = csrf_token

    return client, case_id


def test_android15_private_space_scan(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "nextgen_examiner"}
    resp = client.post(
        f"/api/v1/cases/{case_id}/nextgen/android15-private-space-scan", json=payload
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["success"] is False
    assert data["total_private_apps_detected"] == 0


def test_whatsapp_crypt16_17_decrypt(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {
        "serial": "emulator-5554",
        "case_id": case_id,
        "backup_file_name": "msgstore.db.crypt16",
        "operator_id": "nextgen_examiner",
    }
    resp = client.post(f"/api/v1/cases/{case_id}/nextgen/whatsapp-crypt16-17-decrypt", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["success"] is False
    assert data["hkdf_key_derived"] is False


def test_ephemeral_ram_key_scan(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"serial": "emulator-5554", "case_id": case_id, "operator_id": "nextgen_examiner"}
    resp = client.post(f"/api/v1/cases/{case_id}/nextgen/ephemeral-ram-key-scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert len(data["keys_extracted"]) >= 2
    assert data["keys_extracted"][0]["package_name"] == "org.thoughtcrime.securesms"
