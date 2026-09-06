import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings
from forensix_server.db import CaseDeviceAssessmentRecord, CaseDeviceRecord


def test_recommend_plan_and_execute_pipeline_endpoints(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    mock_adb = MagicMock()
    mock_adb.shell = AsyncMock(return_value="YES")
    mock_adb.pull = AsyncMock(return_value=None)
    app = create_app(settings, adb_client=mock_adb)

    with TestClient(app) as client:
        db = app.state.database
        with db.session() as session:
            auth_service = AuthService(settings)
            auth_service.ensure_roles(session)
            issued = auth_service.bootstrap_administrator(
                session,
                username="admin_examiner_api",
                display_name="Admin Examiner API",
                password="StrongPassword123!",
            )
            principal = issued.principal
            case = CaseService().create(session, principal, title="Acquisition Pipeline Case")
            case_id = case.id
            token = issued.session_token
            csrf_token = issued.csrf_token

            device = CaseDeviceRecord(
                case_id=case_id,
                serial_hash="FX-API-DEVICE-HASH",
                serial_suffix="EVICE",
                registered_by=principal.user_id,
                manufacturer="Google",
                model="Pixel 7",
            )
            session.add(device)
            session.flush()
            device_id = device.id

            snapshot_json = json.dumps(
                {
                    "assessed_at": "2026-09-05T12:00:00Z",
                    "serial": "FX-API-DEVICE",
                    "manufacturer": "Google",
                    "model": "Pixel 7",
                    "android_version": "13",
                    "sdk_level": 33,
                    "build_fingerprint": "google/pixel7",
                    "security_patch": "2023-08-01",
                    "package_count": 10,
                    "storage_roots": [],
                    "battery_level": 90,
                    "battery_status": "discharging",
                    "device_state": {
                        "adb_state": "authorized",
                        "authorization_state": "authorized",
                        "lock_state": "unlocked",
                        "root_state": "non_rooted",
                        "encryption_state": "file_based",
                        "storage_access_state": "readable",
                        "accessibility_state": "not_installed",
                        "usage_stats_state": "granted",
                        "notification_listener_state": "not_granted",
                        "shared_storage_state": "full_access",
                        "bootloader_state": "locked",
                        "chipset_family": "gs201",
                    },
                    "acquisition_readiness": {
                        "encryption_type": "file_based",
                        "credential_storage_state": "unlocked",
                        "chipset_family": "gs201",
                        "filesystem_status": "verified",
                        "explanation": "Ready",
                    },
                    "temporary_root_readiness": {
                        "eligibility_status": "ineligible",
                        "provider_status": "not_configured",
                        "reference_android_range": "4.0-10.0",
                        "reference_max_security_patch": "2019-10-31",
                        "explanation": "Ineligible",
                    },
                    "locked_device_readiness": {
                        "support_status": "unknown",
                        "operating_mode": "metadata_only",
                        "reference_android_range": "5-13",
                        "profile_status": "no_profile",
                        "destructive_guessing_blocked": True,
                        "supported_actions": [],
                        "prohibited_actions": [],
                        "explanation": "Unknown",
                    },
                    "capabilities": {},
                    "warnings": [],
                }
            )

            assessment = CaseDeviceAssessmentRecord(
                case_id=case_id,
                device_id=device_id,
                assessed_by=principal.user_id,
                package_count=10,
                assessor_version="1.0.0",
                snapshot_json=snapshot_json,
            )
            session.add(assessment)
            session.flush()
            assessment_id = assessment.id

        client.cookies.set("forensix_session", token)
        client.cookies.set("forensix_csrf", csrf_token)
        client.headers["X-CSRF-Token"] = csrf_token

        # 1. Recommend Plan
        res_rec = client.post(
            f"/api/v1/cases/{case_id}/acquisitions/recommend-plan?assessment_id={assessment_id}"
        )
        assert res_rec.status_code == 200
        rec_data = res_rec.json()
        assert rec_data["primary_vector"] == "AGENT_LOGICAL"
        assert "AGENT_LOGICAL" in rec_data["vector_evaluations"]

        # 2. Execute Pipeline
        res_exec = client.post(
            f"/api/v1/cases/{case_id}/acquisitions/execute-pipeline",
            json={
                "device_id": device_id,
                "assessment_id": assessment_id,
            },
        )
        assert res_exec.status_code == 200
        exec_data = res_exec.json()
        assert exec_data["success"] is True
        assert exec_data["state"] == "SEALED"
        assert exec_data["vector_used"] == "AGENT_LOGICAL"
