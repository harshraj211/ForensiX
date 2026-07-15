from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from forensix_api.main import create_app
from forensix_forensic.adb import MockAdbClient, MockAdbScenario
from forensix_server.config import Settings
from forensix_server.db import DeviceCapabilityRun


def _settings(tmp_path: Path) -> Settings:
    return Settings(environment="test", data_dir=tmp_path, adb_mode="mock")


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
        response = client.post("/api/v1/devices/detect")

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
        response = client.post("/api/v1/devices/detect")

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
        response = client.post("/api/v1/devices/detect")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ADB_NOT_FOUND"
    assert "missing-adb" in response.json()["error"]["message"]


def test_authorized_device_capability_assessment(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/devices/assess",
            json={"serial": "FX-DEMO-001"},
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
        response = client.post(
            "/api/v1/devices/assess",
            json={"serial": "FX-DEMO-001"},
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "DEVICE_NOT_AUTHORIZED"


def test_assessment_rejects_stale_serial(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/devices/assess",
            json={"serial": "STALE-SERIAL"},
        )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DEVICE_NOT_FOUND"


def test_openapi_exposes_no_arbitrary_shell_operation(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())

    schema = app.openapi()

    assert all("shell" not in path for path in schema["paths"])
    detect = schema["paths"]["/api/v1/devices/detect"]["post"]
    assert "requestBody" not in detect
