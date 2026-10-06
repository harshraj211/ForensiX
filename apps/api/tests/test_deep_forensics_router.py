"""Unit tests for Tier-1 Deep Forensic Suite router endpoints."""

from hashlib import sha256
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image

from forensix_api.dependencies import get_adb_client
from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings


def _create_authenticated_client(tmp_path: Path):
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    client = TestClient(app)

    class FakeAdb:
        async def shell(self, serial: str, command: str) -> str:
            return ""

    app.dependency_overrides[get_adb_client] = lambda: FakeAdb()

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
    output = BytesIO()
    Image.new("RGB", (8, 8), "red").save(output, format="PNG")
    png = output.getvalue()
    offset = 1024 * 1024 - 4  # Header crosses the scanner's chunk boundary.
    image = b"\0" * offset + png + b"\0" * 64
    imported = client.post(
        f"/api/v1/cases/{case_id}/evidence-sources/import",
        files={"source": ("userdata.img", image, "application/octet-stream")},
    )
    assert imported.status_code == 201, imported.text
    source_id = imported.json()["id"]
    copied = client.post(f"/api/v1/cases/{case_id}/evidence-sources/{source_id}/working-copies")
    assert copied.status_code == 201, copied.text
    payload = {"source_id": source_id, "working_copy_id": copied.json()["id"]}
    resp = client.post(f"/api/v1/cases/{case_id}/deep/raw-disk-carve", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["source_sha256"] == sha256(image).hexdigest()
    assert data["truncated"] is False
    assert data["total_carved_files"] == 1
    assert data["carved_media_items"][0]["offset_bytes"] == offset
    assert data["carved_media_items"][0]["sha256_hash"] == sha256(png).hexdigest()
    assert data["gps_locations_plotted_count"] == 0
    artifacts_response = client.get(
        f"/api/v1/cases/{case_id}/evidence-sources/{source_id}/artifacts"
    )
    assert artifacts_response.status_code == 200, artifacts_response.text
    artifacts = artifacts_response.json()
    assert {item["subtype"] for item in artifacts} == {
        "raw_image_scan_summary",
        "raw_image_media_candidate",
    }
    candidate = next(item for item in artifacts if item["subtype"] == "raw_image_media_candidate")
    assert candidate["metadata"]["allocation_state"] == "unknown"
    assert candidate["status"] == "unverified"
    downloaded = client.get(
        f"/api/v1/cases/{case_id}/evidence-sources/{source_id}"
        f"/artifacts/{candidate['id']}/carved-content"
    )
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.content == png
    assert downloaded.headers["X-ForensiX-Candidate-SHA256"] == sha256(png).hexdigest()
    repeated = client.post(f"/api/v1/cases/{case_id}/deep/raw-disk-carve", json=payload)
    assert repeated.status_code == 200, repeated.text
    assert (
        len(client.get(f"/api/v1/cases/{case_id}/evidence-sources/{source_id}/artifacts").json())
        == 2
    )


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
