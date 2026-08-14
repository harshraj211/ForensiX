"""Lifecycle and evidence sealing for interactive Android screen recordings."""

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select

from forensix_forensic.integrations import ScrcpyController, ScrcpyIntegrationError
from forensix_server.auth import Principal
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseInvalidStateError
from forensix_server.db import (
    CaseEventRecord,
    Database,
    ScreenRecordingSessionRecord,
)
from forensix_server.evidence_twin import EvidenceTwinService


class ScreenRecordingService:
    def list(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        device_id: str,
    ) -> list[ScreenRecordingSessionRecord]:
        with database.session() as session:
            CaseDeviceService().get_device(session, principal, case_id, device_id)
            return list(
                session.scalars(
                    select(ScreenRecordingSessionRecord)
                    .where(
                        ScreenRecordingSessionRecord.case_id == case_id,
                        ScreenRecordingSessionRecord.device_id == device_id,
                    )
                    .order_by(
                        ScreenRecordingSessionRecord.started_at.desc(),
                        ScreenRecordingSessionRecord.id.desc(),
                    )
                )
            )

    def start(
        self,
        database: Database,
        principal: Principal,
        controller: ScrcpyController,
        case_id: str,
        device_id: str,
        serial: str,
    ) -> ScreenRecordingSessionRecord:
        serial_digest = sha256(serial.encode("utf-8")).hexdigest()
        with database.session() as session:
            device = CaseDeviceService().get_device(session, principal, case_id, device_id)
            CaseDeviceService().ensure_operable(session, principal, case_id)
            if serial_digest != device.serial_hash:
                raise CaseInvalidStateError(
                    "The connected Android serial does not match the case-linked device."
                )
            active = session.scalar(
                select(ScreenRecordingSessionRecord).where(
                    ScreenRecordingSessionRecord.device_id == device_id,
                    ScreenRecordingSessionRecord.status == "active",
                )
            )
            if active is not None:
                raise CaseInvalidStateError(
                    "A documented examination recording is already active for this device."
                )

        recording_id = str(uuid4())
        destination = self._recording_path(database, recording_id)
        try:
            launch = controller.start_recording(recording_id, serial, destination)
        except (OSError, ValueError, ScrcpyIntegrationError) as error:
            raise CaseInvalidStateError(
                "The documented examination recording could not be started."
            ) from error

        try:
            with database.session() as session:
                record = ScreenRecordingSessionRecord(
                    id=recording_id,
                    case_id=case_id,
                    device_id=device_id,
                    started_by=principal.user_id,
                    stopped_by=None,
                    evidence_source_id=None,
                    status="active",
                    process_id=launch.process_id,
                    serial_hash=serial_digest,
                    scrcpy_version=launch.version,
                    executable_sha256=launch.executable_sha256,
                    size_bytes=None,
                    sha256=None,
                    error_code=None,
                    error_message=None,
                    started_at=datetime.now(UTC),
                    stopped_at=None,
                )
                session.add(record)
                session.add(
                    CaseEventRecord(
                        case_id=case_id,
                        actor_id=principal.user_id,
                        event_type="screen_recording_session_started",
                        safe_detail=(
                            f"session_id={recording_id};device_id={device_id};"
                            f"scrcpy_version={launch.version};process_id={launch.process_id}"
                        ),
                    )
                )
                session.flush()
            return record
        except Exception:
            controller.abandon_recording(recording_id, expected_process_id=launch.process_id)
            destination.unlink(missing_ok=True)
            raise

    def stop_and_seal(
        self,
        database: Database,
        principal: Principal,
        controller: ScrcpyController,
        recording_id: str,
        case_id: str,
        device_id: str,
        serial: str,
    ) -> ScreenRecordingSessionRecord:
        serial_digest = sha256(serial.encode("utf-8")).hexdigest()
        with database.session() as session:
            CaseDeviceService().get_device(session, principal, case_id, device_id)
            CaseDeviceService().ensure_operable(session, principal, case_id)
            record = session.get(ScreenRecordingSessionRecord, recording_id)
            if record is None or record.case_id != case_id or record.device_id != device_id:
                raise CaseInvalidStateError("The recording session does not exist for this device.")
            if record.status != "active":
                raise CaseInvalidStateError("Only an active recording session can be stopped.")
            if record.serial_hash != serial_digest:
                raise CaseInvalidStateError(
                    "The connected Android serial does not match the recording session."
                )
            process_id = record.process_id

        destination = self._recording_path(database, recording_id)
        try:
            controller.stop_recording(recording_id, expected_process_id=process_id)
            if destination.is_symlink() or not destination.is_file():
                raise CaseInvalidStateError("scrcpy did not produce a recording file.")
            size_bytes = destination.stat().st_size
            if size_bytes < 1:
                raise CaseInvalidStateError("scrcpy produced an empty recording file.")
            with destination.open("rb") as stream:
                source = EvidenceTwinService().seal_logical_stream(
                    database,
                    principal,
                    case_id,
                    device_id,
                    stream,
                    source_name=f"android-examination-{recording_id[:8]}.mp4",
                    display_name="Documented Android examination session",
                    declared_size_bytes=size_bytes,
                    operation="scrcpy_interactive_screen_recording",
                    limitations=(
                        (
                            "This recording documents displayed pixels and operator interaction; "
                            "it is not a physical or filesystem acquisition."
                        ),
                        "Items not displayed during the session are outside the recording's scope.",
                        "Interactive taps and typing alter device state and are audit-recorded.",
                        "Audio and clipboard synchronization were disabled.",
                    ),
                )
        except Exception as error:
            self._mark_failed(database, principal, recording_id, error)
            raise CaseInvalidStateError(
                "The recording stopped but could not be sealed as evidence."
            ) from error

        stopped_at = datetime.now(UTC)
        with database.session() as session:
            record = session.get(ScreenRecordingSessionRecord, recording_id)
            if record is None:
                raise CaseInvalidStateError("The recording session no longer exists.")
            record.status = "sealed"
            record.stopped_by = principal.user_id
            record.evidence_source_id = source.id
            record.size_bytes = source.size_bytes
            record.sha256 = source.sha256
            record.stopped_at = stopped_at
            session.add(
                CaseEventRecord(
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="screen_recording_sealed",
                    safe_detail=(
                        f"session_id={recording_id};device_id={device_id};"
                        f"evidence_source_id={source.id};size_bytes={source.size_bytes};"
                        f"sha256={source.sha256}"
                    ),
                )
            )
            session.flush()
        destination.unlink(missing_ok=True)
        return record

    @staticmethod
    def _recording_path(database: Database, recording_id: str) -> Path:
        root = database.data_dir / "tmp" / "screen-recordings"
        root.mkdir(parents=True, exist_ok=True)
        return root / f"{recording_id}.mp4"

    @staticmethod
    def _mark_failed(
        database: Database, principal: Principal, recording_id: str, error: Exception
    ) -> None:
        with database.session() as session:
            record = session.get(ScreenRecordingSessionRecord, recording_id)
            if record is None or record.status != "active":
                return
            record.status = "failed"
            record.stopped_by = principal.user_id
            record.error_code = type(error).__name__[:64]
            record.error_message = "The local recording could not be sealed as evidence."
            record.stopped_at = datetime.now(UTC)
            session.add(
                CaseEventRecord(
                    case_id=record.case_id,
                    actor_id=principal.user_id,
                    event_type="screen_recording_failed",
                    safe_detail=(
                        f"session_id={recording_id};device_id={record.device_id};"
                        f"error_code={record.error_code}"
                    ),
                )
            )
