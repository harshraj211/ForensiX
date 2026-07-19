import json

import pytest

from forensix_forensic.adb import MockAdbClient, MockAdbScenario
from forensix_forensic.validation import (
    SealedValidationReport,
    ValidationOutcome,
    run_adb_validation,
    verify_validation_report,
)


@pytest.mark.asyncio
async def test_authorized_mock_produces_passing_redacted_sealed_report() -> None:
    sealed = await run_adb_validation(MockAdbClient(), mode="mock")

    assert sealed.report.outcome is ValidationOutcome.PASSED
    assert sealed.report.device_serial_sha256 is not None
    assert "FX-DEMO-001" not in sealed.model_dump_json()
    assert "DCIM/Camera" not in sealed.model_dump_json()
    assert verify_validation_report(sealed)
    checks = {check.check_id: check for check in sealed.report.checks}
    assert checks["inventory_repeatability"].observed["repeatable"] is True


@pytest.mark.asyncio
async def test_no_device_preserves_incomplete_validation_record() -> None:
    sealed = await run_adb_validation(MockAdbClient(MockAdbScenario.NO_DEVICES), mode="mock")

    assert sealed.report.outcome is ValidationOutcome.INCOMPLETE
    assert sealed.report.device_serial_sha256 is None
    assert verify_validation_report(sealed)


@pytest.mark.asyncio
async def test_timeout_preserves_failed_validation_record() -> None:
    sealed = await run_adb_validation(MockAdbClient(MockAdbScenario.TIMEOUT), mode="mock")

    assert sealed.report.outcome is ValidationOutcome.FAILED
    assert sealed.report.checks[-1].observed["error_type"] == "AdbTimeoutError"
    assert verify_validation_report(sealed)


@pytest.mark.asyncio
async def test_modified_validation_report_fails_integrity_verification() -> None:
    sealed = await run_adb_validation(MockAdbClient(), mode="mock")
    payload = json.loads(sealed.model_dump_json())
    payload["report"]["tool_version"] = "modified"
    modified = SealedValidationReport.model_validate(payload)

    assert not verify_validation_report(modified)
