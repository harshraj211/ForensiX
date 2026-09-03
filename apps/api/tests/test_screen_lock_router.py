"""Unit tests for the screen lock assessment and password/PIN cracking endpoints."""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings


def test_pattern_solve_endpoint(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)

    with TestClient(app) as client:
        db = app.state.database
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
            case = CaseService().create(session, principal, title="Lockscreen Case")
            case_id = case.id
            token = issued.session_token
            csrf_token = issued.csrf_token

        client.cookies.set("forensix_session", token)
        client.cookies.set("forensix_csrf", csrf_token)
        client.headers["X-CSRF-Token"] = csrf_token

        # Android pattern 0-1-2-5-8 (1 -> 2 -> 3 -> 6 -> 9)
        pattern_bytes = bytes([0, 1, 2, 5, 8])
        pattern_sha1 = hashlib.sha1(pattern_bytes).hexdigest()  # noqa: S324

        res = client.post(
            f"/api/v1/cases/{case_id}/extractions/screen-lock/crack",
            json={
                "case_id": case_id,
                "operator_id": "admin_examiner",
                "mode": 10,
                "attack_type": "pattern_solve",
                "raw_hash": pattern_sha1,
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert len(data["cracked_credentials"]) > 0
        assert "12369" in data["recovered_credential"]


def test_pin_4digit_mask_crack(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)

    with TestClient(app) as client:
        db = app.state.database
        with db.session() as session:
            auth_service = AuthService(settings)
            auth_service.ensure_roles(session)
            issued = auth_service.bootstrap_administrator(
                session,
                username="admin_examiner_2",
                display_name="Admin Examiner 2",
                password="StrongPassword123!",
            )
            principal = issued.principal
            case = CaseService().create(session, principal, title="PIN Case")
            case_id = case.id
            token = issued.session_token
            csrf_token = issued.csrf_token

        client.cookies.set("forensix_session", token)
        client.cookies.set("forensix_csrf", csrf_token)
        client.headers["X-CSRF-Token"] = csrf_token

        # 4-digit PIN "2580"
        pin_hash = hashlib.sha256(b"2580").hexdigest()

        res = client.post(
            f"/api/v1/cases/{case_id}/extractions/screen-lock/crack",
            json={
                "case_id": case_id,
                "operator_id": "admin_examiner_2",
                "mode": 13800,
                "attack_type": "mask",
                "mask": "?d?d?d?d",
                "raw_hash": pin_hash,
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["recovered_credential"] == "2580"


def test_screen_lock_extract_hashes_unacknowledged_root(tmp_path: Path) -> None:
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
                username="admin_examiner_3",
                display_name="Admin Examiner 3",
                password="StrongPassword123!",
            )
            principal = issued.principal
            case = CaseService().create(session, principal, title="Root Case")
            case_id = case.id
            token = issued.session_token
            csrf_token = issued.csrf_token

        client.cookies.set("forensix_session", token)
        client.cookies.set("forensix_csrf", csrf_token)
        client.headers["X-CSRF-Token"] = csrf_token

        res = client.post(
            f"/api/v1/cases/{case_id}/extractions/screen-lock/extract-hashes",
            json={
                "serial": "test_serial",
                "case_id": case_id,
                "operator_id": "admin_examiner_3",
                "root_acknowledged": False,
            },
        )
        assert res.status_code == 400

