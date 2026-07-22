import json

import pytest

from forensix_forensic.adb import MockAdbClient, MockAdbScenario
from forensix_forensic.validation import (
    PhysicalMatrixPolicy,
    SealedPhysicalMatrixReport,
    SealedValidationReport,
    ValidationOutcome,
    build_physical_matrix,
    run_adb_validation,
    verify_physical_matrix,
)


async def _physical_record(scenario: MockAdbScenario) -> SealedValidationReport:
    client = MockAdbClient(scenario, include_validation_fixture=True)

    async def checkpoint(step: str) -> None:
        client.scenario = (
            MockAdbScenario.NO_DEVICES if step == "disconnect" else scenario
        )

    return await run_adb_validation(
        client,
        mode="system",
        validate_known_file=True,
        validate_transport_cycle=True,
        checkpoint=checkpoint,
    )


@pytest.mark.asyncio
async def test_complete_unique_system_matrix_passes_and_is_sealed() -> None:
    ordinary = await _physical_record(MockAdbScenario.AUTHORIZED)
    rooted = await _physical_record(MockAdbScenario.ROOTED)
    policy = PhysicalMatrixPolicy(
        required_hosts=(ordinary.report.environment.operating_system,),
        required_android_releases=(ordinary.report.android_release or "14",),
        minimum_manufacturer_families=1,
    )

    sealed = build_physical_matrix((ordinary, rooted, ordinary), policy)

    assert sealed.report.outcome is ValidationOutcome.PASSED
    assert sealed.report.coverage.accepted_system_records == 2
    assert sealed.report.coverage.duplicate_records == 1
    assert sealed.report.coverage.non_rooted_records == 1
    assert sealed.report.coverage.rooted_records == 1
    assert sealed.report.coverage.known_file_passes == 2
    assert sealed.report.coverage.transport_cycle_passes == 2
    assert verify_physical_matrix(sealed)


@pytest.mark.asyncio
async def test_missing_declared_coverage_is_incomplete() -> None:
    ordinary = await _physical_record(MockAdbScenario.AUTHORIZED)
    policy = PhysicalMatrixPolicy(
        required_hosts=("UnobservedOS",),
        required_android_releases=("999",),
        minimum_manufacturer_families=2,
    )

    sealed = build_physical_matrix((ordinary,), policy)

    assert sealed.report.outcome is ValidationOutcome.INCOMPLETE
    assert any("Missing required host" in gap for gap in sealed.report.gaps)
    assert any("No sealed rooted" in gap for gap in sealed.report.gaps)


@pytest.mark.asyncio
async def test_mock_or_tampered_input_fails_matrix_gate() -> None:
    mock = await run_adb_validation(MockAdbClient(), mode="mock")
    payload = json.loads(mock.model_dump_json())
    payload["report"]["tool_version"] = "tampered"
    tampered = SealedValidationReport.model_validate(payload)
    policy = PhysicalMatrixPolicy(
        required_hosts=(mock.report.environment.operating_system,),
        required_android_releases=(mock.report.android_release or "14",),
        minimum_manufacturer_families=1,
    )

    sealed = build_physical_matrix((mock, tampered), policy)

    assert sealed.report.outcome is ValidationOutcome.FAILED
    assert sealed.report.coverage.invalid_records == 1
    assert sealed.report.coverage.rejected_non_system_records == 1


@pytest.mark.asyncio
async def test_modified_matrix_fails_its_canonical_seal() -> None:
    ordinary = await _physical_record(MockAdbScenario.AUTHORIZED)
    policy = PhysicalMatrixPolicy(
        required_hosts=(ordinary.report.environment.operating_system,),
        required_android_releases=(ordinary.report.android_release or "14",),
        minimum_manufacturer_families=1,
        require_rooted=False,
    )
    sealed = build_physical_matrix((ordinary,), policy)
    payload = json.loads(sealed.model_dump_json())
    payload["report"]["coverage"]["accepted_system_records"] = 99
    modified = SealedPhysicalMatrixReport.model_validate(payload)

    assert not verify_physical_matrix(modified)
