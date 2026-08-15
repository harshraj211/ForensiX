import json
from datetime import datetime

from forensix_api.routers.custody import _audit_export_payload, _case_audit_records
from forensix_server.db import AuditLogRecord


def test_audit_export_normalizes_sqlite_timestamp_to_utc() -> None:
    record = AuditLogRecord(
        id="11111111-1111-1111-1111-111111111111",
        sequence=1,
        case_id=None,
        actor_id="22222222-2222-2222-2222-222222222222",
        event_type="test_event",
        object_type="test_object",
        object_id="object-1",
        detail_json=json.dumps({"safe": True}),
        previous_hash="0" * 64,
        entry_hash="a" * 64,
        created_at=datetime(2026, 8, 15, 12, 30),
    )

    payload = _audit_export_payload(record)

    assert payload["created_at"] == "2026-08-15T12:30:00+00:00"
    assert payload["detail"] == {"safe": True}


def test_case_audit_export_selects_only_requested_case() -> None:
    first = _audit_record(sequence=1, case_id="case-a")
    second = _audit_record(sequence=2, case_id=None)
    third = _audit_record(sequence=3, case_id="case-b")
    fourth = _audit_record(sequence=4, case_id="case-a")

    selected = _case_audit_records([first, second, third, fourth], "case-a")

    assert [record.sequence for record in selected] == [1, 4]


def _audit_record(*, sequence: int, case_id: str | None) -> AuditLogRecord:
    return AuditLogRecord(
        id=f"00000000-0000-0000-0000-{sequence:012d}",
        sequence=sequence,
        case_id=case_id,
        actor_id="22222222-2222-2222-2222-222222222222",
        event_type="test_event",
        object_type="test_object",
        object_id=f"object-{sequence}",
        detail_json="{}",
        previous_hash="0" * 64,
        entry_hash=str(sequence) * 64,
        created_at=datetime(2026, 8, 15, 12, sequence),
    )
