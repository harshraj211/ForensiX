from datetime import UTC, datetime

from forensix_server.reporting.renderers import neutralize_csv, render_csv, render_json, render_pdf
from forensix_server.reporting.snapshot import CaseSnapshot, ReportIdentity, ReportSnapshot


def _snapshot() -> ReportSnapshot:
    now = datetime(2026, 7, 17, 8, 0, tzinfo=UTC)
    return ReportSnapshot(
        tool_version="0.1.0",
        report=ReportIdentity(
            report_id="11111111-1111-1111-1111-111111111111",
            generated_at=now,
            generated_by_id="22222222-2222-2222-2222-222222222222",
            generated_by_name="Test Investigator",
            preliminary_warning="PRELIMINARY: examiner review required.",
        ),
        case=CaseSnapshot(
            id="33333333-3333-3333-3333-333333333333",
            case_number="CASE-2026-0001",
            title="Controlled report fixture",
            description="Known-answer rendering fixture.",
            legal_authority="Training authorization",
            status="active",
            created_at=now,
        ),
        devices=[],
        acquisitions=[],
        evidence_summary={},
        selected_artifacts=[],
        timeline=[],
        hash_manifest=[],
        integrity_summary={},
        custody=[],
        errors=[],
        limitations=["ADB is not a hardware write blocker."],
        methodology=["The snapshot is validated before rendering."],
    )


def test_report_renderers_emit_stable_outputs() -> None:
    snapshot = _snapshot()
    first = render_pdf(snapshot)
    second = render_pdf(snapshot)

    assert first == second
    assert first.startswith(b"%PDF-")
    assert b'"schema_version":"1.0.0"' in render_json(snapshot).replace(b" ", b"")
    assert render_csv(snapshot).startswith(b"record_origin,artifact_id,evidence_reference_id")


def test_csv_formula_prefixes_are_neutralized() -> None:
    for dangerous in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\tvalue", "\rvalue"):
        assert neutralize_csv(dangerous) == f"'{dangerous}"
    assert neutralize_csv("normal") == "normal"
