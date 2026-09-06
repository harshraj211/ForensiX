import json
import zipfile
from pathlib import Path

import pytest
from test_acquisition_decision_engine import _create_test_snapshot

from forensix_forensic.acquisitions import (
    AcquisitionExecutionState,
    AcquisitionPipelineOrchestrator,
    ForensicEvidencePackager,
)
from forensix_forensic.capabilities import (
    AcquisitionVector,
    AcquisitionVectorDecisionEngine,
)


class FakeAdbClientForPipeline:
    def __init__(self, serial: str = "FX-TEST-PIPELINE") -> None:
        self.serial = serial

    async def shell(self, serial: str, command: str) -> str:
        if "test -f" in command:
            return "YES\n"
        if "pm list packages" in command:
            return "package:com.whatsapp\npackage:org.telegram.messenger\n"
        if "dumpsys battery" in command:
            return "level: 90\nstatus: 2\n"
        return ""

    async def pull(self, serial: str, remote_path: str, local_path: str) -> None:
        path_obj = Path(local_path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240
        if "contacts.json" in remote_path:
            path_obj.write_text(  # noqa: ASYNC240
                '[{"name": "Alice", "phone_numbers": ["123"], "emails": [], '
                '"account_type": "google"}]',
                encoding="utf-8",
            )
        elif "sms.json" in remote_path:
            path_obj.write_text(  # noqa: ASYNC240
                '[{"address": "123", "body": "Hello", "date_ms": 1000, "type": 1, "thread_id": 1}]',
                encoding="utf-8",
            )
        elif "call_logs.json" in remote_path:
            path_obj.write_text(  # noqa: ASYNC240
                '[{"number": "123", "type": 1, "date_ms": 1000, '
                '"duration_seconds": 10, "name": "Alice"}]',
                encoding="utf-8",
            )
        elif "installed_apps.json" in remote_path:
            path_obj.write_text(  # noqa: ASYNC240
                '[{"package_name": "com.whatsapp", "app_label": "WhatsApp", "version_name": "1.0",'
                ' "install_time_ms": 0, "is_system": false}]',
                encoding="utf-8",
            )
        elif "app_artifacts.json" in remote_path:
            path_obj.write_text("[]", encoding="utf-8")  # noqa: ASYNC240
        elif "device_metadata.json" in remote_path:
            path_obj.write_text(  # noqa: ASYNC240
                '{"source": "agent_apk", "category": "device_metadata", "collected_at_ms": 1000,'
                ' "data": {}, "availability_map": {}}',
                encoding="utf-8",
            )
        else:
            path_obj.write_text('{"dummy": true}', encoding="utf-8")  # noqa: ASYNC240


@pytest.mark.asyncio
async def test_pipeline_execution_agent_logical(tmp_path: Path) -> None:
    snapshot = _create_test_snapshot(sdk_level=33, root_state="non_rooted")
    engine = AcquisitionVectorDecisionEngine()
    recommendation = engine.evaluate(snapshot)

    adb_client = FakeAdbClientForPipeline()
    orchestrator = AcquisitionPipelineOrchestrator()

    result = await orchestrator.execute_plan(
        recommendation=recommendation,
        adb_client=adb_client,  # type: ignore
        case_id="CASE-P1",
        output_base_dir=tmp_path,
    )

    assert result.success is True
    assert result.state == AcquisitionExecutionState.SEALED
    assert result.vector_used == AcquisitionVector.AGENT_LOGICAL
    assert result.archive_path is not None
    assert Path(result.archive_path).exists()  # noqa: ASYNC240

    manifest = result.manifest
    assert manifest is not None
    assert manifest.case_id == "CASE-P1"
    assert manifest.device_serial == snapshot.serial
    assert manifest.vector_used == AcquisitionVector.AGENT_LOGICAL
    assert len(manifest.artifacts) > 0
    assert manifest.manifest_sha256 != ""

    # Check zip archive content
    with zipfile.ZipFile(result.archive_path, "r") as zf:
        namelist = zf.namelist()
        assert "evidence_manifest.json" in namelist
        manifest_data = json.loads(zf.read("evidence_manifest.json").decode("utf-8"))
        assert manifest_data["case_id"] == "CASE-P1"


@pytest.mark.asyncio
async def test_pipeline_execution_metadata_only_fallback(tmp_path: Path) -> None:
    snapshot = _create_test_snapshot(authorization_state="unauthorized")
    engine = AcquisitionVectorDecisionEngine()
    recommendation = engine.evaluate(snapshot)

    adb_client = FakeAdbClientForPipeline()
    orchestrator = AcquisitionPipelineOrchestrator()

    result = await orchestrator.execute_plan(
        recommendation=recommendation,
        adb_client=adb_client,  # type: ignore
        case_id="CASE-P2",
        output_base_dir=tmp_path,
    )

    assert result.success is True
    assert result.state == AcquisitionExecutionState.SEALED
    assert result.vector_used == AcquisitionVector.METADATA_ONLY
    assert result.archive_path is not None
    assert Path(result.archive_path).exists()  # noqa: ASYNC240


def test_packager_integrity_and_sha256(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw_test"
    raw_dir.mkdir()
    (raw_dir / "contacts.json").write_text('[{"name": "Bob"}]', encoding="utf-8")
    (raw_dir / "device_metadata.json").write_text('{"model": "Pixel"}', encoding="utf-8")

    archive_dir = tmp_path / "sealed_test"
    packager = ForensicEvidencePackager()

    from datetime import UTC, datetime

    now = datetime.now(UTC)

    result = packager.package(
        acquisition_id="ACQ-123",
        case_id="CASE-123",
        device_serial="FX-TEST",
        vector_used=AcquisitionVector.AGENT_LOGICAL,
        yield_score=85,
        started_at=now,
        finished_at=now,
        raw_extraction_dir=raw_dir,
        output_archive_dir=archive_dir,
    )

    assert result.success is True
    assert result.manifest is not None
    assert len(result.manifest.artifacts) == 2
    categories = {art.category for art in result.manifest.artifacts}
    assert "contacts" in categories
    assert "device_metadata" in categories
