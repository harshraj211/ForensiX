"""Unit tests for Centralized AI Gateway & Multimodal Suite API router."""

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
            username="admin_ai_examiner",
            display_name="Admin AI Examiner",
            password="StrongPassword123!",
        )
        principal = issued.principal
        case = CaseService().create(session, principal, title="AI Multimodal Case")
        case_id = case.id
        token = issued.session_token
        csrf_token = issued.csrf_token

    client.cookies.set("forensix_session", token)
    client.cookies.set("forensix_csrf", csrf_token)
    client.headers["X-CSRF-Token"] = csrf_token

    return client, case_id


def test_get_ai_gateway_status(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    response = client.get(f"/api/v1/cases/{case_id}/ai-gateway/status")
    assert response.status_code == 200
    data = response.json()
    assert "xkiro_vision_available" in data
    assert "supported_capabilities" in data
    assert "CHAIN_OF_CUSTODY_AUDIT_LOG" in data["supported_capabilities"]


def test_scan_media_intelligence(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {
        "file_names": [
            "DCIM/passport_scan.png",
            "Pictures/crypto_seed_phrase.jpg",
            "Download/receipt_venmo.png",
        ]
    }
    response = client.post(f"/api/v1/cases/{case_id}/ai-gateway/scan-media", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == case_id
    assert data["total_scanned"] == 3
    assert len(data["items"]) == 3
    categories = [item["category"] for item in data["items"]]
    assert "IDENTITY_DOC" in categories
    assert "FINANCIAL_CRYPTO" in categories


def test_copilot_query(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    payload = {"query_text": "Find all crypto seed phrases and bitcoin transactions"}
    response = client.post(f"/api/v1/cases/{case_id}/ai-gateway/copilot-query", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == case_id
    assert "answer" in data
    assert "referenced_artifacts" in data
    assert len(data["referenced_artifacts"]) > 0


def test_get_ai_audit_logs(tmp_path: Path):
    client, case_id = _create_authenticated_client(tmp_path)
    client.post(
        f"/api/v1/cases/{case_id}/ai-gateway/scan-media",
        json={"file_names": ["DCIM/sample.jpg"]},
    )

    response = client.get(f"/api/v1/cases/{case_id}/ai-gateway/audit-logs")
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == case_id
    assert data["total_audit_records"] >= 1
    first_log = data["audit_logs"][0]
    assert "court_admissible_signature" in first_log
    assert first_log["court_admissible_signature"].startswith("FORENSIX-AI-SEAL-")
