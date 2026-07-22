import json
from pathlib import Path

from forensix_forensic.validation import ValidationOutcome, ValidationStatus
from forensix_server.validation import (
    SealedEvidenceTwinValidationReport,
    run_evidence_twin_validation,
    verify_evidence_twin_validation,
)


def test_evidence_twin_known_answer_pipeline_is_sealed_and_privacy_preserving(
    tmp_path: Path,
) -> None:
    sealed = run_evidence_twin_validation(tmp_path)

    assert sealed.report.outcome is ValidationOutcome.PASSED
    assert verify_evidence_twin_validation(sealed)
    assert sealed.report.fixture_sha256 == sealed.report.evidence_source_sha256
    assert sealed.report.evidence_source_sha256 == sealed.report.working_copy_sha256
    assert set(sealed.report.report_output_sha256) == {"csv", "json", "pdf"}
    checks = {check.check_id: check for check in sealed.report.checks}
    assert set(checks) == {
        "custody_audit_chains",
        "fixture_created",
        "normalization_timeline",
        "provider_parsers",
        "report_integrity",
        "signature_inspection",
        "source_sealing",
        "working_copy_integrity",
    }
    assert all(check.status is ValidationStatus.SUCCEEDED for check in checks.values())
    assert checks["provider_parsers"].observed == {
        "artifact_count": 4,
        "known_answers_match": True,
        "parser_count": 4,
    }
    assert checks["normalization_timeline"].observed["timeline_count"] == 3

    serialized = json.dumps(sealed.model_dump(mode="json"), sort_keys=True)
    for sensitive_fixture_value in (
        "+15550000001",
        "+15550000002",
        "+15550000003",
        "+15550000004",
        "Known Contact",
        "Known SMS",
        "Known MMS",
        "Known Caller",
    ):
        assert sensitive_fixture_value not in serialized


def test_modified_evidence_twin_validation_report_fails_verification(tmp_path: Path) -> None:
    sealed = run_evidence_twin_validation(tmp_path)
    modified = SealedEvidenceTwinValidationReport(
        report=sealed.report.model_copy(update={"tool_version": "modified"}),
        canonical_sha256=sealed.canonical_sha256,
    )

    assert not verify_evidence_twin_validation(modified)
