from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from forensix_forensic.capabilities import DeviceCapabilitySnapshot
from forensix_forensic.integrations import ScrcpyLaunchResult, ScrcpyRecordingStopResult
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseInvalidStateError, CaseService
from forensix_server.db import (
    CaseEventRecord,
    Database,
    EvidenceSourceRecord,
    ScreenRecordingSessionRecord,
    UserRecord,
)
from forensix_server.screen_recordings import ScreenRecordingService


class FakeScrcpyController:
    def __init__(self) -> None:
        self.destination: Path | None = None

    def start_recording(
        self, recording_id: str, serial: str, destination: Path
    ) -> ScrcpyLaunchResult:
        del recording_id, serial
        self.destination = destination
        return ScrcpyLaunchResult(
            process_id=4411,
            mode="control",
            version="4.1",
            executable_sha256="a" * 64,
            side_effects=("controlled fixture",),
        )

    def stop_recording(
        self, recording_id: str, *, expected_process_id: int
    ) -> ScrcpyRecordingStopResult:
        del recording_id
        assert expected_process_id == 4411
        assert self.destination is not None
        self.destination.write_bytes(b"forensix-screen-recording")
        return ScrcpyRecordingStopResult(
            process_id=expected_process_id,
            exit_code=0,
            already_exited=False,
        )

    def abandon_recording(self, recording_id: str, *, expected_process_id: int) -> None:
        del recording_id, expected_process_id


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'recordings.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _case_device(database: Database) -> tuple[Principal, str, str]:
    with database.session() as session:
        user = UserRecord(
            username="recording.investigator",
            display_name="Recording Investigator",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        principal = Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.INVESTIGATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.INVESTIGATOR],
        )
        case = CaseService().create(session, principal, title="Recorded examination")
        snapshot = DeviceCapabilitySnapshot(
            assessed_at=datetime.now(UTC),
            serial="FX-REC-001",
            manufacturer="ForensiX",
            model="Controlled device",
            android_version="14",
            sdk_level=34,
            build_fingerprint="forensix/test/device:14/TEST:userdebug/test-keys",
            security_patch="2026-08-01",
            package_count=1,
            capabilities={},
            warnings=(),
        )
        device, _ = CaseDeviceService().register_assessment(session, principal, case.id, snapshot)
        return principal, case.id, device.id


def test_recording_session_stops_and_seals_as_case_evidence(database: Database) -> None:
    principal, case_id, device_id = _case_device(database)
    controller = FakeScrcpyController()
    service = ScreenRecordingService()

    started = service.start(
        database,
        principal,
        controller,
        case_id,
        device_id,
        "FX-REC-001",  # type: ignore[arg-type]
    )
    sealed = service.stop_and_seal(
        database,
        principal,
        controller,  # type: ignore[arg-type]
        started.id,
        case_id,
        device_id,
        "FX-REC-001",
    )

    assert started.status == "active"
    assert sealed.status == "sealed"
    assert sealed.evidence_source_id is not None
    assert sealed.mp4_storage_key is not None
    assert sealed.sha256 is not None and len(sealed.sha256) == 64
    assert controller.destination is not None
    assert not controller.destination.exists()
    with database.session() as session:
        source = session.get(EvidenceSourceRecord, sealed.evidence_source_id)
        assert source is not None
        assert source.status == "sealed"
        assert source.source_name.endswith(".mp4")
        assert source.sealed_storage_key is not None
        store = EvidenceStore(database.data_dir / "evidence")
        mp4 = store.resolve(sealed.mp4_storage_key, require_file=True)
        master = store.resolve(source.sealed_storage_key, require_file=True)
        assert mp4.read_bytes() == b"forensix-screen-recording"
        assert mp4.read_bytes() == master.read_bytes()
        assert store.hash(sealed.mp4_storage_key).hexdigest == sealed.sha256
        events = set(session.scalars(select(CaseEventRecord.event_type)))
        assert "screen_recording_session_started" in events
        assert "screen_recording_sealed" in events


def test_second_active_recording_is_rejected(database: Database) -> None:
    principal, case_id, device_id = _case_device(database)
    controller = FakeScrcpyController()
    service = ScreenRecordingService()
    service.start(
        database,
        principal,
        controller,
        case_id,
        device_id,
        "FX-REC-001",  # type: ignore[arg-type]
    )

    with pytest.raises(CaseInvalidStateError, match="already active"):
        service.start(
            database,
            principal,
            controller,  # type: ignore[arg-type]
            case_id,
            device_id,
            "FX-REC-001",
        )

    with database.session() as session:
        assert len(list(session.scalars(select(ScreenRecordingSessionRecord)))) == 1
