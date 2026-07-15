from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from forensix_api.main import create_app
from forensix_forensic.adb import MockAdbClient, MockAdbScenario
from forensix_server.auth import RoleName
from forensix_server.config import Settings
from forensix_server.db import (
    DeviceCapabilityRun,
    RoleRecord,
    UserRecord,
    UserRoleRecord,
)

PASSWORD = "StrongPass!2026"


def _settings(tmp_path: Path) -> Settings:
    return Settings(environment="test", data_dir=tmp_path, adb_mode="mock")


def _authorize(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "username": "admin.user",
            "display_name": "Test Administrator",
            "password": PASSWORD,
        },
    )
    assert response.status_code == 201
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def test_health_endpoints(tmp_path: Path) -> None:
    with TestClient(create_app(_settings(tmp_path), adb_client=MockAdbClient())) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.json()["status"] == "ok"
    assert ready.status_code == 200
    assert ready.json()["database"] == "ready"
    assert live.headers["X-Request-ID"]


@pytest.mark.parametrize(
    ("scenario", "result", "states"),
    [
        (MockAdbScenario.NO_DEVICES, "no_devices", []),
        (MockAdbScenario.AUTHORIZED, "single_device", ["authorized"]),
        (MockAdbScenario.UNAUTHORIZED, "single_device", ["unauthorized"]),
        (MockAdbScenario.OFFLINE, "single_device", ["offline"]),
        (MockAdbScenario.MULTIPLE, "multiple_devices", ["authorized", "unauthorized"]),
    ],
)
def test_detect_device_scenarios(
    tmp_path: Path,
    scenario: MockAdbScenario,
    result: str,
    states: list[str],
) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient(scenario))
    with TestClient(app) as client:
        headers = _authorize(client)
        response = client.post("/api/v1/devices/detect", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["result"] == result
    assert [device["state"] for device in body["devices"]] == states
    assert body["detection_id"]


def test_detect_timeout_uses_safe_error_envelope(tmp_path: Path) -> None:
    app = create_app(
        _settings(tmp_path),
        adb_client=MockAdbClient(MockAdbScenario.TIMEOUT),
    )
    with TestClient(app) as client:
        headers = _authorize(client)
        response = client.post("/api/v1/devices/detect", headers=headers)

    assert response.status_code == 504
    assert response.json() == {
        "error": {
            "code": "ADB_TIMEOUT",
            "message": "ADB operation exceeded the 5 second timeout.",
            "details": {},
            "request_id": response.headers["X-Request-ID"],
        }
    }


def test_missing_adb_binary_returns_dependency_error(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        data_dir=tmp_path,
        adb_mode="system",
        adb_path=tmp_path / "missing-adb",
    )
    with TestClient(create_app(settings)) as client:
        headers = _authorize(client)
        response = client.post("/api/v1/devices/detect", headers=headers)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ADB_NOT_FOUND"
    assert "missing-adb" in response.json()["error"]["message"]


def test_authorized_device_capability_assessment(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        response = client.post(
            "/api/v1/devices/assess",
            json={"serial": "FX-DEMO-001"},
            headers=headers,
        )

    assert response.status_code == 200
    body = response.json()
    assert body["assessment_id"]
    assert body["android_version"] == "14"
    assert body["sdk_level"] == 34
    assert body["capabilities"]["device_metadata"]["status"] == "supported"
    assert body["capabilities"]["private_app_data"]["status"] == "unsupported"
    with app.state.database.session() as session:
        persisted = session.execute(select(DeviceCapabilityRun)).scalar_one()
    assert persisted.serial_hash != "FX-DEMO-001"
    assert len(persisted.serial_hash) == 64
    assert "FX-DEMO-001" not in persisted.snapshot_json


def test_assessment_revalidates_transport_state(tmp_path: Path) -> None:
    app = create_app(
        _settings(tmp_path),
        adb_client=MockAdbClient(MockAdbScenario.UNAUTHORIZED),
    )
    with TestClient(app) as client:
        headers = _authorize(client)
        response = client.post(
            "/api/v1/devices/assess",
            json={"serial": "FX-DEMO-001"},
            headers=headers,
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "DEVICE_NOT_AUTHORIZED"


def test_assessment_rejects_stale_serial(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        response = client.post(
            "/api/v1/devices/assess",
            json={"serial": "STALE-SERIAL"},
            headers=headers,
        )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DEVICE_NOT_FOUND"


def test_openapi_exposes_no_arbitrary_shell_operation(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())

    schema = app.openapi()

    assert all("shell" not in path for path in schema["paths"])
    detect = schema["paths"]["/api/v1/devices/detect"]["post"]
    assert "requestBody" not in detect


def test_first_run_bootstrap_creates_secure_local_session(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        status_response = client.get("/api/v1/auth/bootstrap-status")
        headers = _authorize(client)
        me = client.get("/api/v1/auth/me")

    assert status_response.json() == {"bootstrap_required": True}
    assert me.status_code == 200
    assert me.json()["username"] == "admin.user"
    assert me.json()["roles"] == ["administrator"]
    assert "users:manage" in me.json()["permissions"]
    assert headers["X-CSRF-Token"]


def test_bootstrap_is_rejected_after_first_administrator(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        _authorize(client)
        duplicate = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "username": "second.admin",
                "display_name": "Second Administrator",
                "password": PASSWORD,
            },
        )

    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "BOOTSTRAP_ALREADY_COMPLETE"


def test_device_operations_require_session_and_csrf(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as anonymous:
        unauthenticated = anonymous.post("/api/v1/devices/detect")
    with TestClient(app) as client:
        _authorize(client)
        missing_csrf = client.post("/api/v1/devices/detect")
        invalid_csrf = client.post(
            "/api/v1/devices/detect",
            headers={"X-CSRF-Token": "invalid"},
        )

    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert missing_csrf.status_code == 403
    assert invalid_csrf.status_code == 403


def test_device_operation_enforces_rbac_after_role_change(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        with app.state.database.session() as session:
            user = session.scalar(select(UserRecord))
            reviewer = session.scalar(
                select(RoleRecord).where(RoleRecord.name == RoleName.REVIEWER.value)
            )
            assert user is not None
            assert reviewer is not None
            session.execute(delete(UserRoleRecord).where(UserRoleRecord.user_id == user.id))
            session.add(UserRoleRecord(user_id=user.id, role_id=reviewer.id))

        denied = client.post("/api/v1/devices/detect", headers=headers)

    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"


def test_login_refresh_and_logout_rotate_and_revoke_sessions(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        first_headers = _authorize(client)
        logout = client.post("/api/v1/auth/logout", headers=first_headers)
        after_logout = client.get("/api/v1/auth/me")
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "ADMIN.USER", "password": PASSWORD},
        )
        refresh = client.post(
            "/api/v1/auth/refresh",
            headers={"X-CSRF-Token": login.json()["csrf_token"]},
        )
        me = client.get("/api/v1/auth/me")

    assert logout.status_code == 204
    assert after_logout.status_code == 401
    assert login.status_code == 200
    assert refresh.status_code == 200
    assert refresh.json()["csrf_token"] != login.json()["csrf_token"]
    assert me.status_code == 200


def test_invalid_login_uses_generic_error(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        _authorize(client)
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "missing.user", "password": "WrongPass!2026"},
        )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"
    assert "missing.user" not in response.text
