import asyncio
import io
import sqlite3
from pathlib import Path
from typing import NoReturn

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import delete, inspect, select

from forensix_api.main import create_app
from forensix_forensic.adb import (
    AdbCommandError,
    MockAdbClient,
    MockAdbScenario,
    SharedStorageRoot,
)
from forensix_server.auth import RoleName
from forensix_server.config import Settings
from forensix_server.db import (
    AcquisitionPlanRecord,
    CaseDeviceAssessmentRecord,
    CaseDeviceDetectionRecord,
    CaseDeviceRecord,
    DeviceCapabilityRun,
    JobEventRecord,
    JobRecord,
    RoleRecord,
    UserRecord,
    UserRoleRecord,
)

PASSWORD = "StrongPass!2026"


class _PartialDisconnectClient(MockAdbClient):
    async def pull_inventory_file(
        self,
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ) -> NoReturn:
        await asyncio.to_thread(destination.write_bytes, b"API interrupted partial")
        raise AdbCommandError(1, "The controlled device disconnected during transfer.")


class _PngEvidenceClient(MockAdbClient):
    async def pull_inventory_file(
        self,
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ):
        if relative_path != "DCIM/Camera/IMG_0001.jpg":
            return await super().pull_inventory_file(serial, root, relative_path, destination)
        buffer = io.BytesIO()
        Image.new("RGB", (32, 24), color=(12, 74, 96)).save(buffer, format="PNG")
        payload = buffer.getvalue()
        await asyncio.to_thread(destination.write_bytes, payload)
        from forensix_forensic.adb import PulledFileResult

        return PulledFileResult(
            root_id=root.value,
            relative_path=relative_path,
            size_bytes=len(payload),
        )


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


def _create_case_plan(
    client: TestClient,
    headers: dict[str, str],
    *,
    title: str = "Execution case",
    scope: str = "metadata_only",
) -> tuple[dict[str, object], dict[str, object]]:
    case = client.post("/api/v1/cases", headers=headers, json={"title": title}).json()
    assessment = client.post(
        "/api/v1/devices/assess",
        headers=headers,
        json={"serial": "FX-DEMO-001", "case_id": case["id"]},
    ).json()
    plan = client.post(
        f"/api/v1/cases/{case['id']}/acquisition-plans",
        headers=headers,
        json={
            "device_id": assessment["case_device_id"],
            "assessment_id": assessment["assessment_id"],
            "scope": scope,
            "limitations_acknowledged": True,
        },
    ).json()
    return case, plan


def test_health_endpoints(tmp_path: Path) -> None:
    with TestClient(create_app(_settings(tmp_path), adb_client=MockAdbClient())) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.json()["status"] == "ok"
    assert ready.status_code == 200
    assert ready.json()["database"] == "ready"
    assert live.headers["X-Request-ID"]


def test_development_startup_applies_workstation_migrations(tmp_path: Path) -> None:
    settings = Settings(environment="development", data_dir=tmp_path, adb_mode="mock")
    app = create_app(settings, adb_client=MockAdbClient())

    with TestClient(app) as client:
        ready = client.get("/health/ready")
        tables = set(inspect(app.state.database.engine).get_table_names())

    assert ready.status_code == 200
    assert {
        "alembic_version",
        "acquired_evidence_files",
        "acquisition_partials",
        "artifacts",
        "artifact_search",
        "artifact_previews",
        "artifact_tags",
        "analyst_notes",
        "bookmarks",
        "tags",
        "timeline_events",
        "audit_logs",
        "acquisition_inventories",
        "acquisition_inventory_items",
        "acquisition_plans",
        "custody_events",
        "evidence_verifications",
        "evidence_sources",
        "evidence_source_chunks",
        "evidence_source_verifications",
        "evidence_source_inspections",
        "evidence_parser_runs",
        "evidence_source_artifacts",
        "evidence_working_copies",
        "jobs",
        "job_events",
        "reports",
        "report_outputs",
    } <= tables


def test_evidence_twin_import_verify_and_working_copy_api(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    payload = b"controlled evidence bytes" * 128
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post(
            "/api/v1/cases", headers=headers, json={"title": "Evidence Twin API case"}
        ).json()
        endpoint = f"/api/v1/cases/{case['id']}/evidence-sources/import"

        missing_csrf = client.post(
            endpoint,
            files={"source": ("capture.raw", payload, "application/octet-stream")},
        )
        imported = client.post(
            endpoint,
            headers=headers,
            data={"display_name": "Controlled image"},
            files={"source": ("capture.raw", payload, "application/octet-stream")},
        )

        assert missing_csrf.status_code == 403
        assert imported.status_code == 201
        source = imported.json()
        assert source["status"] == "sealed"
        assert source["container_format"] == "raw"
        assert source["source_name"] == "capture.raw"
        assert source["display_name"] == "Controlled image"
        assert source["size_bytes"] == len(payload)
        assert len(source["sha256"]) == 64
        assert "sealed_storage_key" not in source

        listed = client.get(f"/api/v1/cases/{case['id']}/evidence-sources")
        verified = client.post(
            f"/api/v1/cases/{case['id']}/evidence-sources/{source['id']}/verify",
            headers=headers,
        )
        copied = client.post(
            f"/api/v1/cases/{case['id']}/evidence-sources/{source['id']}/working-copies",
            headers=headers,
        )
        copies = client.get(
            f"/api/v1/cases/{case['id']}/evidence-sources/{source['id']}/working-copies"
        )
        verifications = client.get(
            f"/api/v1/cases/{case['id']}/evidence-sources/{source['id']}/verifications"
        )

        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()] == [source["id"]]
        assert verified.status_code == 200
        assert verified.json()["status"] == "verified"
        assert copied.status_code == 201
        assert copied.json()["status"] == "ready"
        assert copied.json()["observed_sha256"] == source["sha256"]
        assert len(copies.json()) == 1
        assert [item["status"] for item in verifications.json()] == [
            "verified",
            "verified",
        ]


def test_evidence_twin_native_parser_api(tmp_path: Path) -> None:
    sqlite_path = tmp_path / "contacts2.db"
    connection = sqlite3.connect(sqlite_path)
    connection.executescript(
        """
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, deleted INTEGER);
        CREATE TABLE data (
            _id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER,
            data1 TEXT, data2 TEXT, data3 TEXT
        );
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/name');
        INSERT INTO raw_contacts VALUES (10, 0);
        INSERT INTO data VALUES (1, 10, 1, 'API Contact', NULL, NULL);
        """
    )
    connection.commit()
    connection.close()
    app = create_app(_settings(tmp_path / "runtime"), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post(
            "/api/v1/cases", headers=headers, json={"title": "Parser API case"}
        ).json()
        imported = client.post(
            f"/api/v1/cases/{case['id']}/evidence-sources/import",
            headers=headers,
            files={
                "source": ("contacts2.db", sqlite_path.read_bytes(), "application/octet-stream")
            },
        ).json()
        copied = client.post(
            f"/api/v1/cases/{case['id']}/evidence-sources/{imported['id']}/working-copies",
            headers=headers,
        ).json()
        base = (
            f"/api/v1/cases/{case['id']}/evidence-sources/{imported['id']}"
            f"/working-copies/{copied['id']}"
        )

        inspection = client.post(f"{base}/inspection", headers=headers)
        verification = client.post(f"{base}/verify", headers=headers)
        parsed = client.post(
            f"{base}/native-parsers",
            headers=headers,
            json={"parser_ids": ["android.contacts_provider"]},
        )
        runs = client.get(
            f"/api/v1/cases/{case['id']}/evidence-sources/{imported['id']}/parser-runs"
        )
        artifacts = client.get(
            f"/api/v1/cases/{case['id']}/evidence-sources/{imported['id']}/artifacts"
        )

        assert inspection.status_code == 201
        assert inspection.json()["detected_type"] == "sqlite"
        assert verification.status_code == 200
        assert verification.json()["status"] == "verified"
        assert parsed.status_code == 200
        assert parsed.json()[0]["parser_id"] == "android.contacts_provider"
        assert parsed.json()[0]["artifact_count"] == 1
        assert len(runs.json()) == 1
        assert artifacts.json()[0]["title"] == "API Contact"
        assert artifacts.json()[0]["provenance"]["source_sha256"] == imported["sha256"]


def test_preliminary_report_generation_and_verified_downloads(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post("/api/v1/cases", headers=headers, json={"title": "Report case"}).json()
        generated = client.post(f"/api/v1/cases/{case['id']}/reports", headers=headers)
        assert generated.status_code == 201
        report = generated.json()
        assert report["report_type"] == "preliminary"
        assert report["schema_version"] == "1.0.0"
        assert {item["format"] for item in report["outputs"]} == {"pdf", "json", "csv"}

        listed = client.get(f"/api/v1/cases/{case['id']}/reports")
        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()] == [report["id"]]

        for output in report["outputs"]:
            downloaded = client.get(
                f"/api/v1/cases/{case['id']}/reports/{report['id']}/download/{output['format']}"
            )
            assert downloaded.status_code == 200
            assert downloaded.headers["x-forensix-output-sha256"] == output["sha256"]
            assert downloaded.headers["cache-control"] == "no-store, private"
            assert downloaded.content
        assert client.get(
            f"/api/v1/cases/{case['id']}/reports/{report['id']}/download/pdf"
        ).content.startswith(b"%PDF-")

        custody = client.get(f"/api/v1/cases/{case['id']}/custody").json()
        assert custody[-1]["event_type"] == "report_generated"
        assert custody[-1]["report_id"] == report["id"]


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
    acquire = schema["paths"][
        "/api/v1/cases/{case_id}/acquisitions/{job_id}/inventory/items/{item_id}/acquire"
    ]["post"]
    bulk_acquire = schema["paths"][
        "/api/v1/cases/{case_id}/acquisitions/{job_id}/inventory/acquire-batch"
    ]["post"]
    verify = schema["paths"][
        "/api/v1/cases/{case_id}/acquisitions/{job_id}/files/{evidence_file_id}/verify"
    ]["post"]
    assert "requestBody" not in detect
    assert "requestBody" not in acquire
    assert "requestBody" in bulk_acquire
    assert "requestBody" not in verify


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


def test_bootstrap_sets_spa_readable_csrf_cookie_at_root_path(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "username": "admin.user",
                "display_name": "Test Administrator",
                "password": PASSWORD,
            },
        )

    csrf_headers = [
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith("forensix_csrf=") and "Max-Age=" in value and "Path=/;" in value
    ]
    assert csrf_headers
    assert "Path=/;" in csrf_headers[0]
    assert "HttpOnly" not in csrf_headers[0]


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


def test_acquisition_plan_binds_exact_case_device_and_snapshot(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post("/api/v1/cases", headers=headers, json={"title": "Planning case"}).json()
        assessment = client.post(
            "/api/v1/devices/assess",
            headers=headers,
            json={"serial": "FX-DEMO-001", "case_id": case["id"]},
        ).json()

        created = client.post(
            f"/api/v1/cases/{case['id']}/acquisition-plans",
            headers=headers,
            json={
                "device_id": assessment["case_device_id"],
                "assessment_id": assessment["assessment_id"],
                "scope": "quick_triage",
                "limitations_acknowledged": True,
            },
        )
        listed = client.get(f"/api/v1/cases/{case['id']}/acquisition-plans")
        detail = client.get(f"/api/v1/cases/{case['id']}/acquisition-plans/{created.json()['id']}")

    assert created.status_code == 201
    assert created.json()["status"] == "ready"
    assert created.json()["assessment_id"] == assessment["assessment_id"]
    assert created.json()["modules"] == [
        "device_metadata",
        "package_inventory",
        "shared_storage_inventory",
    ]
    assert len(created.json()["snapshot_hash"]) == 64
    assert len(created.json()["plan_hash"]) == 64
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert detail.json()["plan_hash"] == created.json()["plan_hash"]
    with app.state.database.session() as session:
        plan = session.execute(select(AcquisitionPlanRecord)).scalar_one()
        jobs = list(session.scalars(select(JobRecord)))
    assert plan.assessment_id == assessment["assessment_id"]
    assert jobs == []


def test_blocked_storage_cannot_be_planned_for_quick_triage(tmp_path: Path) -> None:
    app = create_app(
        _settings(tmp_path),
        adb_client=MockAdbClient(MockAdbScenario.STORAGE_BLOCKED),
    )
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post(
            "/api/v1/cases", headers=headers, json={"title": "Blocked storage plan"}
        ).json()
        assessment = client.post(
            "/api/v1/devices/assess",
            headers=headers,
            json={"serial": "FX-DEMO-001", "case_id": case["id"]},
        ).json()
        common = {
            "device_id": assessment["case_device_id"],
            "assessment_id": assessment["assessment_id"],
            "limitations_acknowledged": True,
        }
        blocked = client.post(
            f"/api/v1/cases/{case['id']}/acquisition-plans",
            headers=headers,
            json={**common, "scope": "quick_triage"},
        )
        metadata = client.post(
            f"/api/v1/cases/{case['id']}/acquisition-plans",
            headers=headers,
            json={**common, "scope": "metadata_only"},
        )

    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "ACQUISITION_PLAN_INVALID"
    assert metadata.status_code == 201
    assert metadata.json()["modules"] == ["device_metadata", "package_inventory"]


def test_acquisition_plan_requires_explicit_limitation_acknowledgement(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post(
            "/api/v1/cases", headers=headers, json={"title": "Acknowledgement case"}
        ).json()
        assessment = client.post(
            "/api/v1/devices/assess",
            headers=headers,
            json={"serial": "FX-DEMO-001", "case_id": case["id"]},
        ).json()
        rejected = client.post(
            f"/api/v1/cases/{case['id']}/acquisition-plans",
            headers=headers,
            json={
                "device_id": assessment["case_device_id"],
                "assessment_id": assessment["assessment_id"],
                "scope": "metadata_only",
                "limitations_acknowledged": False,
            },
        )

    assert rejected.status_code == 422


def test_acquisition_job_preparation_is_idempotent_and_reconstructable(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers)
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"

        prepared = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]})
        repeated = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]})
        listed = client.get(endpoint)
        detail = client.get(f"{endpoint}/{prepared.json()['id']}")
        events = client.get(f"{endpoint}/{prepared.json()['id']}/events")

    assert prepared.status_code == 201
    assert repeated.status_code == 200
    assert repeated.json()["id"] == prepared.json()["id"]
    assert prepared.json()["state"] == "ready"
    assert prepared.json()["progress_percent"] == 5
    assert prepared.json()["started_at"] is None
    assert prepared.json()["executor_available"] is False
    assert prepared.json()["checkpoint"]["plan_hash"] == plan["plan_hash"]
    assert listed.json()["total"] == 1
    assert detail.json()["plan_id"] == plan["id"]
    assert [event["sequence"] for event in events.json()] == [1, 2, 3, 4]
    assert [event["event_type"] for event in events.json()] == [
        "job_created",
        "state_changed",
        "progress_updated",
        "state_changed",
    ]
    with app.state.database.session() as session:
        job = session.execute(select(JobRecord)).scalar_one()
        persisted_events = list(session.scalars(select(JobEventRecord)))
    assert job.case_id == case["id"]
    assert job.plan_id == plan["id"]
    assert len(persisted_events) == 4


def test_bounded_inventory_runs_live_revalidation_and_returns_path_metadata(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()

        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers)
        repeated = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers)
        fetched = client.get(f"{endpoint}/{job['id']}/inventory")
        completed_job = client.get(f"{endpoint}/{job['id']}")

    assert inventory.status_code == 200
    assert inventory.json()["status"] == "completed"
    assert inventory.json()["persisted_count"] == 3
    assert inventory.json()["total"] == 3
    assert inventory.json()["items"][0]["relative_path"] == "DCIM/Camera/IMG_0001.jpg"
    assert set(inventory.json()["items"][0]) == {
        "id",
        "ordinal",
        "relative_path",
        "path_hash",
        "extension",
        "size_bytes",
        "modified_time_raw",
        "modified_at",
        "timestamp_source",
        "timestamp_confidence",
    }
    assert inventory.json()["items"][0]["size_bytes"] == 33
    assert inventory.json()["items"][0]["modified_time_raw"] == "1784160000"
    assert inventory.json()["items"][0]["modified_at"].endswith(("Z", "+00:00"))
    assert inventory.json()["items"][0]["timestamp_source"] == "android_stat_mtime_epoch"
    assert inventory.json()["items"][0]["timestamp_confidence"] == "medium"
    assert len(inventory.json()["manifest_hash"]) == 64
    assert repeated.json()["id"] == inventory.json()["id"]
    assert fetched.json()["manifest_hash"] == inventory.json()["manifest_hash"]
    assert completed_job.json()["state"] == "completed"
    assert completed_job.json()["result_reference"] == inventory.json()["id"]


def test_metadata_only_plan_cannot_run_storage_inventory(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers)
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()

        rejected = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers)

    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "ACQUISITION_INVENTORY_INVALID"


def test_inventory_item_file_acquisition_is_selected_hashed_and_idempotent(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers).json()
        item = next(
            entry
            for entry in inventory["items"]
            if entry["relative_path"] == "Documents/timeline.csv"
        )
        acquire_url = f"{endpoint}/{job['id']}/inventory/items/{item['id']}/acquire"

        acquired = client.post(acquire_url, headers=headers)
        repeated = client.post(acquire_url, headers=headers)
        listed = client.get(f"{endpoint}/{job['id']}/files")
        verified = client.post(
            f"{endpoint}/{job['id']}/files/{acquired.json()['id']}/verify",
            headers=headers,
        )
        verifications = client.get(f"{endpoint}/{job['id']}/verifications")
        artifacts = client.get(
            f"/api/v1/cases/{case['id']}/artifacts",
            params={
                "q": "timeline",
                "category": "document",
                "status": "active",
                "extension": "csv",
            },
        )
        artifact_detail = client.get(
            f"/api/v1/cases/{case['id']}/artifacts/{artifacts.json()['items'][0]['id']}"
        )
        artifact_id = artifacts.json()["items"][0]["id"]
        timeline = client.get(f"/api/v1/cases/{case['id']}/timeline")
        bookmark = client.post(
            f"/api/v1/cases/{case['id']}/artifacts/{artifact_id}/bookmark",
            headers=headers,
            json={"reason": "Include in preliminary report"},
        )
        tag = client.post(
            f"/api/v1/cases/{case['id']}/artifacts/{artifact_id}/tags",
            headers=headers,
            json={"name": "Priority"},
        )
        note = client.post(
            f"/api/v1/cases/{case['id']}/artifacts/{artifact_id}/notes",
            headers=headers,
            json={"body": "Initial observation."},
        )
        amendment = client.post(
            f"/api/v1/cases/{case['id']}/artifacts/{artifact_id}/notes",
            headers=headers,
            json={
                "body": "Corrected observation.",
                "supersedes_id": note.json()["id"],
            },
        )
        annotations = client.get(f"/api/v1/cases/{case['id']}/artifacts/{artifact_id}/annotations")

    assert acquired.status_code == 200
    assert acquired.json()["status"] == "completed"
    assert acquired.json()["inventory_item_id"] == item["id"]
    assert len(acquired.json()["sha256"]) == 64
    assert len(acquired.json()["manifest_hash"]) == 64
    assert acquired.json()["validation_state"] == "not_physically_validated"
    assert acquired.json()["storage_key"].startswith("c/")
    assert repeated.json()["id"] == acquired.json()["id"]
    assert listed.status_code == 200
    assert [entry["id"] for entry in listed.json()] == [acquired.json()["id"]]
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"
    assert verified.json()["file_matches"] is True
    assert verified.json()["manifest_matches"] is True
    assert len(verified.json()["verification_hash"]) == 64
    assert [entry["id"] for entry in verifications.json()] == [verified.json()["id"]]
    assert artifacts.status_code == 200
    assert artifacts.json()["total"] == 1
    assert artifacts.json()["category_facets"] == {"document": 1}
    assert artifact_detail.status_code == 200
    assert artifact_detail.json()["title"] == "timeline.csv"
    assert artifact_detail.json()["primary_sha256"] == acquired.json()["sha256"]
    assert artifact_detail.json()["metadata"]["content_parsed"] is False
    assert artifact_detail.json()["metadata"]["source_timestamp"]["original_epoch_seconds"] == (
        "1784246400"
    )
    assert timeline.status_code == 200
    assert timeline.json()["total"] == 2
    assert timeline.json()["items"][0]["timestamp_type"] == "acquisition_collected_at"
    assert timeline.json()["items"][1]["timestamp_type"] == "source_file_modified_at"
    assert bookmark.status_code == 201
    assert tag.status_code == 201
    assert note.status_code == 201
    assert amendment.status_code == 201
    assert amendment.json()["supersedes_id"] == note.json()["id"]
    assert annotations.json()["bookmark"]["reason"] == "Include in preliminary report"
    assert [item["name"] for item in annotations.json()["tags"]] == ["Priority"]
    assert [item["body"] for item in annotations.json()["notes"]] == [
        "Initial observation.",
        "Corrected observation.",
    ]


def test_preview_api_serves_only_verified_png_derivative_with_security_headers(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path), adb_client=_PngEvidenceClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers).json()
        item = next(
            entry
            for entry in inventory["items"]
            if entry["relative_path"] == "DCIM/Camera/IMG_0001.jpg"
        )
        acquired = client.post(
            f"{endpoint}/{job['id']}/inventory/items/{item['id']}/acquire",
            headers=headers,
        ).json()
        artifact = client.get(f"/api/v1/cases/{case['id']}/artifacts").json()["items"][0]
        preview_url = f"/api/v1/cases/{case['id']}/artifacts/{artifact['id']}/preview"

        initial = client.get(preview_url)
        missing_csrf = client.post(preview_url)
        generated = client.post(preview_url, headers=headers)
        repeated = client.post(preview_url, headers=headers)
        content = client.get(f"{preview_url}/content")
        source_path = tmp_path / "evidence" / Path(acquired["storage_key"])
        source_after_preview = source_path.read_bytes()
        derivative_path = (
            tmp_path / "evidence" / "c" / str(case["id"])[:8] / "d" / f"{artifact['id']}.png"
        )
        derivative_path.write_bytes(b"tampered derivative")
        tampered_content = client.get(f"{preview_url}/content")

    assert initial.json()["status"] == "not_generated"
    assert missing_csrf.status_code == 403
    assert generated.status_code == 200
    assert generated.json()["status"] == "available"
    assert generated.json()["detected_mime"] == "image/png"
    assert generated.json()["extension_mismatch"] is True
    assert repeated.json()["id"] == generated.json()["id"]
    assert source_after_preview.startswith(b"\x89PNG\r\n\x1a\n")
    assert content.status_code == 200
    assert content.headers["content-type"] == "image/png"
    assert content.headers["x-content-type-options"] == "nosniff"
    assert content.headers["cross-origin-resource-policy"] == "same-origin"
    assert content.headers["cache-control"] == "no-store, private"
    assert content.headers["x-forensix-derivative-sha256"] == generated.json()["output_sha256"]
    assert content.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert tampered_content.status_code == 409
    assert tampered_content.json()["error"]["code"] == "PREVIEW_NOT_AVAILABLE"


def test_preview_api_rejects_non_image_without_serving_source_bytes(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers).json()
        item = next(
            entry
            for entry in inventory["items"]
            if entry["relative_path"] == "Documents/timeline.csv"
        )
        client.post(
            f"{endpoint}/{job['id']}/inventory/items/{item['id']}/acquire",
            headers=headers,
        )
        artifact = client.get(f"/api/v1/cases/{case['id']}/artifacts").json()["items"][0]
        preview_url = f"/api/v1/cases/{case['id']}/artifacts/{artifact['id']}/preview"
        rejected = client.post(preview_url, headers=headers)
        content = client.get(f"{preview_url}/content")

    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["error_code"] == "UNSUPPORTED_MEDIA_TYPE"
    assert content.status_code == 409
    assert content.json()["error"]["code"] == "PREVIEW_NOT_AVAILABLE"


def test_interrupted_file_api_requires_review_and_restarts_from_zero(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=_PartialDisconnectClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers).json()
        item = inventory["items"][0]
        acquire_url = f"{endpoint}/{job['id']}/inventory/items/{item['id']}/acquire"

        interrupted = client.post(acquire_url, headers=headers)
        files = client.get(f"{endpoint}/{job['id']}/files").json()
        partials = client.get(f"{endpoint}/{job['id']}/partials")
        blocked_retry = client.post(acquire_url, headers=headers)
        app.state.adb_client = MockAdbClient()
        resumed = client.post(
            f"{endpoint}/{job['id']}/files/{files[0]['id']}/resume",
            headers=headers,
            json={"partial_disposition": "retain"},
        )
        reviewed_partials = client.get(f"{endpoint}/{job['id']}/partials").json()

    assert interrupted.status_code == 502
    assert files[0]["status"] == "failed"
    assert files[0]["partial_preserved"] is True
    assert partials.status_code == 200
    assert partials.json()[0]["status"] == "retained"
    assert partials.json()[0]["size_bytes"] == len(b"API interrupted partial")
    assert len(partials.json()[0]["sha256"]) == 64
    assert blocked_retry.status_code == 409
    assert "Review whether" in blocked_retry.json()["error"]["message"]
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "completed"
    assert [partial["status"] for partial in reviewed_partials] == ["retained", "sealed"]
    assert reviewed_partials[0]["disposition_by"] is not None


def test_verification_detects_modified_evidence_without_changing_expected_hash(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers).json()
        item = inventory["items"][0]
        acquired = client.post(
            f"{endpoint}/{job['id']}/inventory/items/{item['id']}/acquire",
            headers=headers,
        ).json()
        expected_hash = acquired["sha256"]
        evidence_path = tmp_path / "evidence" / Path(acquired["storage_key"])
        evidence_path.write_bytes(b"modified after acquisition")

        verification = client.post(
            f"{endpoint}/{job['id']}/files/{acquired['id']}/verify",
            headers=headers,
        )
        unchanged = client.get(f"{endpoint}/{job['id']}/files").json()[0]

    assert verification.status_code == 200
    assert verification.json()["status"] == "mismatch"
    assert verification.json()["file_matches"] is False
    assert verification.json()["manifest_matches"] is True
    assert verification.json()["expected_file_sha256"] == expected_hash
    assert unchanged["sha256"] == expected_hash


def test_custody_history_is_chained_amended_and_audited(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers).json()
        acquired = client.post(
            f"{endpoint}/{job['id']}/inventory/items/{inventory['items'][0]['id']}/acquire",
            headers=headers,
        ).json()
        transfer = client.post(
            f"/api/v1/cases/{case['id']}/custody",
            headers=headers,
            json={
                "event_type": "transferred",
                "evidence_file_id": acquired["id"],
                "from_custodian": "Investigator A",
                "to_custodian": "Forensic Lab",
                "location": "Evidence locker 4",
                "purpose": "Laboratory examination",
            },
        )
        amendment = client.post(
            f"/api/v1/cases/{case['id']}/custody",
            headers=headers,
            json={
                "event_type": "amendment",
                "evidence_file_id": acquired["id"],
                "related_event_id": transfer.json()["id"],
                "notes": "Correct locker reference is evidence locker 5.",
            },
        )
        custody = client.get(f"/api/v1/cases/{case['id']}/custody")
        custody_chain = client.get(f"/api/v1/cases/{case['id']}/custody/verify")
        audit = client.get("/api/v1/audit-logs")
        audit_chain = client.get("/api/v1/audit-logs/verify")

    assert transfer.status_code == 201
    assert amendment.status_code == 201
    assert amendment.json()["related_event_id"] == transfer.json()["id"]
    assert [event["event_type"] for event in custody.json()] == [
        "evidence_registered",
        "transferred",
        "amendment",
    ]
    assert custody_chain.json()["valid"] is True
    assert custody_chain.json()["record_count"] == 3
    assert audit.status_code == 200
    assert len(audit.json()) == 3
    assert audit_chain.json()["valid"] is True


def test_custody_history_exposes_no_update_or_delete_operation(tmp_path: Path) -> None:
    schema = create_app(_settings(tmp_path), adb_client=MockAdbClient()).openapi()
    custody_path = schema["paths"]["/api/v1/cases/{case_id}/custody"]

    assert set(custody_path) == {"get", "post"}
    assert "requestBody" not in schema["paths"]["/api/v1/cases/{case_id}/custody/verify"]["get"]


def test_artifact_api_is_read_only_and_rejects_unapproved_filters(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    schema = app.openapi()

    assert set(schema["paths"]["/api/v1/cases/{case_id}/artifacts"]) == {"get"}
    assert set(schema["paths"]["/api/v1/cases/{case_id}/artifacts/{artifact_id}"]) == {"get"}
    with TestClient(app) as client:
        headers = _authorize(client)
        case = client.post("/api/v1/cases", headers=headers, json={"title": "Filter case"})
        invalid = client.get(
            f"/api/v1/cases/{case.json()['id']}/artifacts",
            params={"category": "private_app_data"},
        )

    assert invalid.status_code == 422


def test_file_acquisition_rejects_caller_supplied_or_unknown_item(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        client.post(f"{endpoint}/{job['id']}/inventory", headers=headers)

        rejected = client.post(
            f"{endpoint}/{job['id']}/inventory/items/00000000-0000-0000-0000-000000000000/acquire",
            headers=headers,
            json={"remote_path": "/sdcard/forged"},
        )

    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "ACQUISITION_FILE_INVALID"


def test_bulk_inventory_file_acquisition_pulls_selected_items(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, scope="quick_triage")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()
        inventory = client.post(f"{endpoint}/{job['id']}/inventory", headers=headers).json()
        item_ids = [entry["id"] for entry in inventory["items"]]

        batch = client.post(
            f"{endpoint}/{job['id']}/inventory/acquire-batch",
            headers=headers,
            json={"item_ids": item_ids},
        )
        listed = client.get(f"{endpoint}/{job['id']}/files")
        repeated = client.post(
            f"{endpoint}/{job['id']}/inventory/acquire-batch",
            headers=headers,
            json={"item_ids": item_ids},
        )
        invalid = client.post(
            f"{endpoint}/{job['id']}/inventory/acquire-batch",
            headers=headers,
            json={"item_ids": ["00000000-0000-0000-0000-000000000000"]},
        )

    assert batch.status_code == 200
    body = batch.json()
    assert body["requested_count"] == 3
    assert body["completed_count"] == 3
    assert body["failed_count"] == 0
    assert body["skipped_count"] == 0
    assert len(body["items"]) == 3
    assert all(item["outcome"] == "completed" for item in body["items"])
    assert all(item["file"]["status"] == "completed" for item in body["items"])
    assert len(listed.json()) == 3
    assert repeated.status_code == 200
    assert repeated.json()["completed_count"] == 0
    assert repeated.json()["skipped_count"] == 3
    assert all(item["outcome"] == "skipped_already_completed" for item in repeated.json()["items"])
    assert invalid.status_code == 409
    assert invalid.json()["error"]["code"] == "ACQUISITION_FILE_INVALID"


def test_prepared_acquisition_job_can_be_cancelled_without_execution(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, title="Cancellation case")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        job = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]}).json()

        cancelled = client.post(f"{endpoint}/{job['id']}/cancel", headers=headers)
        repeated = client.post(f"{endpoint}/{job['id']}/cancel", headers=headers)
        events = client.get(f"{endpoint}/{job['id']}/events")

    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    assert cancelled.json()["cancellation_requested"] is True
    assert cancelled.json()["started_at"] is None
    assert repeated.json()["last_event_sequence"] == cancelled.json()["last_event_sequence"]
    assert events.json()[-1]["event_type"] == "cancellation_requested"
    assert len(events.json()) == 5


def test_acquisition_job_mutations_require_csrf_and_open_case(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), adb_client=MockAdbClient())
    with TestClient(app) as client:
        headers = _authorize(client)
        case, plan = _create_case_plan(client, headers, title="Closed execution case")
        endpoint = f"/api/v1/cases/{case['id']}/acquisitions"
        missing_csrf = client.post(endpoint, json={"plan_id": plan["id"]})
        closed = client.post(
            f"/api/v1/cases/{case['id']}/transition",
            headers=headers,
            json={"expected_version": case["version"], "status": "closed"},
        )
        rejected = client.post(endpoint, headers=headers, json={"plan_id": plan["id"]})

    assert missing_csrf.status_code == 403
    assert closed.status_code == 200
    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "ACQUISITION_JOB_INVALID"
