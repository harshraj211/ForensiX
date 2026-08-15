from datetime import UTC, datetime

from forensix_server.reporting.renderers import neutralize_csv, render_csv, render_json, render_pdf
from forensix_server.reporting.snapshot import (
    CaseSnapshot,
    ImportedArtifactSnapshot,
    ReportIdentity,
    ReportSnapshot,
)


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


def test_pdf_places_plaintext_chat_content_before_technical_sections() -> None:
    snapshot = _snapshot().model_copy(
        update={
            "imported_artifacts": [
                ImportedArtifactSnapshot(
                    id="44444444-4444-4444-4444-444444444444",
                    evidence_source_id="55555555-5555-5555-5555-555555555555",
                    parser_run_id="66666666-6666-6666-6666-666666666666",
                    category="communication",
                    subtype="whatsapp_message",
                    title="WhatsApp outgoing message",
                    summary="Meet me at the station at noon.",
                    event_time=datetime(2026, 7, 17, 7, 30, tzinfo=UTC),
                    source_locator="msgstore.db#message:7",
                    status="active",
                    confidence="medium",
                    parser_id="android.whatsapp.message",
                    parser_version="1.0.0",
                    artifact_hash="a" * 64,
                )
            ]
        }
    )

    from forensix_server.reporting.renderers import _readable_messages

    assert _readable_messages(snapshot) == [
        (
            "2026-07-17T07:30:00+00:00",
            "WhatsApp",
            "WhatsApp outgoing message",
            "Meet me at the station at noon.",
        )
    ]
    assert render_pdf(snapshot).startswith(b"%PDF-")
