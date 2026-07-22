import asyncio
import json
from pathlib import Path

import pytest

from forensix_forensic.adb import (
    KNOWN_FILE_RELATIVE_PATH,
    KNOWN_FILE_SHA256,
    MockAdbClient,
    MockAdbScenario,
    PulledFileResult,
    SharedStorageRoot,
)
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


@pytest.mark.asyncio
async def test_fixed_known_file_is_acquired_twice_and_hash_verified() -> None:
    sealed = await run_adb_validation(
        MockAdbClient(include_validation_fixture=True),
        mode="mock",
        validate_known_file=True,
    )

    assert sealed.report.outcome is ValidationOutcome.PASSED
    check = next(item for item in sealed.report.checks if item.check_id == "known_file_acquisition")
    assert check.observed["acquisition_count"] == 2
    assert check.observed["expected_sha256"] == KNOWN_FILE_SHA256
    assert check.observed["known_answer_matches"] is True
    assert check.observed["repeatable"] is True
    assert KNOWN_FILE_RELATIVE_PATH not in sealed.model_dump_json()
    assert verify_validation_report(sealed)


@pytest.mark.asyncio
async def test_requested_known_file_validation_is_incomplete_when_fixture_is_absent() -> None:
    sealed = await run_adb_validation(
        MockAdbClient(),
        mode="mock",
        validate_known_file=True,
    )

    assert sealed.report.outcome is ValidationOutcome.INCOMPLETE
    check = next(item for item in sealed.report.checks if item.check_id == "known_file_acquisition")
    assert check.status.value == "skipped"


class CorruptingKnownFileClient(MockAdbClient):
    def __init__(self) -> None:
        super().__init__(include_validation_fixture=True)

    async def pull_inventory_file(
        self,
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ) -> PulledFileResult:
        result = await super().pull_inventory_file(serial, root, relative_path, destination)
        await asyncio.to_thread(destination.write_bytes, b"tampered fixture")
        return result.model_copy(update={"size_bytes": len(b"tampered fixture")})


@pytest.mark.asyncio
async def test_known_file_hash_mismatch_fails_sealed_validation() -> None:
    sealed = await run_adb_validation(
        CorruptingKnownFileClient(),
        mode="mock",
        validate_known_file=True,
    )

    assert sealed.report.outcome is ValidationOutcome.FAILED
    check = next(item for item in sealed.report.checks if item.check_id == "known_file_acquisition")
    assert check.observed["known_answer_matches"] is False
    assert verify_validation_report(sealed)
