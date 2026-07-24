import asyncio
import hashlib
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
    ValidationConnectionType,
    ValidationOutcome,
    ValidationRunContext,
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


@pytest.mark.asyncio
async def test_transport_cycle_observes_disconnect_and_reacquires_known_file() -> None:
    client = MockAdbClient(include_validation_fixture=True)
    checkpoints: list[str] = []

    async def checkpoint(step: str) -> None:
        checkpoints.append(step)
        client.scenario = (
            MockAdbScenario.NO_DEVICES if step == "disconnect" else MockAdbScenario.AUTHORIZED
        )

    sealed = await run_adb_validation(
        client,
        mode="mock",
        validate_known_file=True,
        validate_transport_cycle=True,
        checkpoint=checkpoint,
    )

    assert sealed.report.outcome is ValidationOutcome.PASSED
    assert checkpoints == ["disconnect", "reconnect"]
    check = next(
        item for item in sealed.report.checks if item.check_id == "transport_disconnect_reconnect"
    )
    assert check.observed["disconnected_state"] == "missing"
    assert check.observed["reauthorized"] is True
    assert check.observed["known_answer_matches"] is True
    assert KNOWN_FILE_RELATIVE_PATH not in sealed.model_dump_json()


@pytest.mark.asyncio
async def test_transport_cycle_requires_known_file_and_checkpoint() -> None:
    with pytest.raises(ValueError, match="requires known-file"):
        await run_adb_validation(
            MockAdbClient(),
            mode="mock",
            validate_transport_cycle=True,
        )


@pytest.mark.asyncio
async def test_system_known_file_validation_requires_sealed_run_context() -> None:
    with pytest.raises(ValueError, match="requires sealed operator"):
        await run_adb_validation(
            MockAdbClient(include_validation_fixture=True),
            mode="system",
            validate_known_file=True,
        )


@pytest.mark.asyncio
async def test_run_context_is_sealed_and_version_one_reports_remain_verifiable() -> None:
    context = ValidationRunContext(
        operator_id="examiner-01",
        authority_reference="CONTROLLED-VALIDATION-001",
        connection_type=ValidationConnectionType.WIRED_USB,
        release_commit="abcdef1",
    )
    sealed = await run_adb_validation(MockAdbClient(), mode="mock", run_context=context)

    assert sealed.report.schema_version == "forensix-validation/1.1"
    assert sealed.report.run_context == context
    assert verify_validation_report(sealed)

    legacy_report = sealed.report.model_copy(
        update={"schema_version": "forensix-validation/1.0", "run_context": None}
    )
    legacy_payload = legacy_report.model_dump(mode="json")
    legacy_payload.pop("run_context")
    legacy_hash = hashlib.sha256(
        json.dumps(
            legacy_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    legacy = SealedValidationReport(report=legacy_report, canonical_sha256=legacy_hash)

    assert verify_validation_report(legacy)
    with pytest.raises(ValueError, match="requires an operator checkpoint"):
        await run_adb_validation(
            MockAdbClient(include_validation_fixture=True),
            mode="mock",
            validate_known_file=True,
            validate_transport_cycle=True,
        )
