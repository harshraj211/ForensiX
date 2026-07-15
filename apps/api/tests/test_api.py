from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from forensix_api.main import create_app
from forensix_forensic.adb import MockAdbClient, MockAdbScenario
from forensix_server.auth import RoleName
from forensix_server.config import Settings
from forensix_server.db import (
    CaseDeviceAssessmentRecord,
    CaseDeviceDetectionRecord,
    CaseDeviceRecord,
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
    assert body["capabilities"]["shared_storage"]["status"] == "supported"
    assert body["storage_roots"][0]["display_path"] == "/sdcard"
    assert body["storage_roots"][0]["readable"] is True
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


def test_case_create_list_detail_and_events_workflow(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        created = client.post(
            "/api/v1/cases",
            headers=headers,
            json={
                "title": "Controlled Android examination",
                "description": "Known validation device",
                "legal_authority": "Internal validation authorization",
            },
        )
        case_id = created.json()["id"]
        listed = client.get("/api/v1/cases?limit=10")
        detail = client.get(f"/api/v1/cases/{case_id}")
        events = client.get(f"/api/v1/cases/{case_id}/events")
        members = client.get(f"/api/v1/cases/{case_id}/members")

    assert created.status_code == 201
    assert created.json()["case_number"].startswith("FX-")
    assert created.json()["status"] == "open"
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["id"] == case_id
    assert detail.json()["title"] == "Controlled Android examination"
    assert events.json()[0]["event_type"] == "case_created"
    assert members.json()[0]["access_level"] == "owner"


def test_case_update_and_transition_require_current_version(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        created = client.post(
            "/api/v1/cases",
            headers=headers,
            json={"title": "Versioned case"},
        ).json()
        case_id = created["id"]
        updated = client.patch(
            f"/api/v1/cases/{case_id}",
            headers=headers,
            json={"expected_version": 1, "title": "Updated versioned case"},
        )
        stale = client.patch(
            f"/api/v1/cases/{case_id}",
            headers=headers,
            json={"expected_version": 1, "title": "Stale title"},
        )
        activated = client.post(
            f"/api/v1/cases/{case_id}/transition",
            headers=headers,
            json={"expected_version": updated.json()["version"], "status": "active"},
        )
        closed = client.post(
            f"/api/v1/cases/{case_id}/transition",
            headers=headers,
            json={"expected_version": activated.json()["version"], "status": "closed"},
        )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "CASE_VERSION_CONFLICT"
    assert activated.json()["status"] == "active"
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_at"] is not None


def test_case_mutations_require_authentication_and_csrf(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as anonymous:
        unauthorized = anonymous.post("/api/v1/cases", json={"title": "Denied"})
    with TestClient(app) as client:
        _authorize(client)
        missing_csrf = client.post("/api/v1/cases", json={"title": "Denied"})

    assert unauthorized.status_code == 401
    assert missing_csrf.status_code == 403


def test_case_management_enforces_role_permissions(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        created = client.post(
            "/api/v1/cases", headers=headers, json={"title": "Restricted update"}
        ).json()
        with app.state.database.session() as session:
            user = session.scalar(select(UserRecord))
            reviewer = session.scalar(
                select(RoleRecord).where(RoleRecord.name == RoleName.REVIEWER.value)
            )
            assert user is not None
            assert reviewer is not None
            session.execute(delete(UserRoleRecord).where(UserRoleRecord.user_id == user.id))
            session.add(UserRoleRecord(user_id=user.id, role_id=reviewer.id))

        readable = client.get(f"/api/v1/cases/{created['id']}")
        denied = client.patch(
            f"/api/v1/cases/{created['id']}",
            headers=headers,
            json={"expected_version": created["version"], "title": "Denied"},
        )

    assert readable.status_code == 200
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "CASE_ACCESS_DENIED"


def test_case_scoped_detection_assessment_and_history(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post(
            "/api/v1/cases", headers=headers, json={"title": "Readiness history"}
        ).json()
        case_id = case["id"]

        detection = client.post(f"/api/v1/devices/detect?case_id={case_id}", headers=headers)
        assessment = client.post(
            "/api/v1/devices/assess",
            headers=headers,
            json={"serial": "FX-DEMO-001", "case_id": case_id},
        )
        devices = client.get(f"/api/v1/cases/{case_id}/devices")
        device_id = devices.json()[0]["id"]
        snapshots = client.get(f"/api/v1/cases/{case_id}/devices/{device_id}/assessments")
        events = client.get(f"/api/v1/cases/{case_id}/events")

    assert detection.status_code == 200
    assert detection.json()["case_id"] == case_id
    assert assessment.status_code == 200
    assert assessment.json()["case_id"] == case_id
    assert assessment.json()["case_device_id"] == device_id
    assert devices.status_code == 200
    assert devices.json()[0]["serial_suffix"] == "O-001"
    assert snapshots.status_code == 200
    assert snapshots.json()[0]["device_id"] == device_id
    assert snapshots.json()[0]["capabilities"]["device_metadata"]["status"] == "supported"
    assert snapshots.json()[0]["storage_roots"][0]["status"] == "accessible"
    assert {event["event_type"] for event in events.json()} >= {
        "device_detection_run",
        "device_assessed",
    }
    with app.state.database.session() as session:
        persisted_device = session.execute(select(CaseDeviceRecord)).scalar_one()
        persisted_detection = session.execute(select(CaseDeviceDetectionRecord)).scalar_one()
        persisted_assessment = session.execute(select(CaseDeviceAssessmentRecord)).scalar_one()
    assert persisted_device.case_id == case_id
    assert persisted_detection.case_id == case_id
    assert persisted_assessment.case_id == case_id
    assert "FX-DEMO-001" not in persisted_assessment.snapshot_json


def test_closed_case_rejects_case_scoped_device_operation(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post(
            "/api/v1/cases", headers=headers, json={"title": "Closed readiness"}
        ).json()
        closed = client.post(
            f"/api/v1/cases/{case['id']}/transition",
            headers=headers,
            json={"expected_version": case["version"], "status": "closed"},
        )
        detection = client.post(f"/api/v1/devices/detect?case_id={case['id']}", headers=headers)

    assert closed.status_code == 200
    assert detection.status_code == 409
    assert detection.json()["error"]["code"] == "CASE_INVALID_STATE"
