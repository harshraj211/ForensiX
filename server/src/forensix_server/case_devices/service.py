"""Case-authorized persistence for Android transport readiness."""

from datetime import datetime
from hashlib import sha256
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.capabilities import DeviceCapabilitySnapshot
from forensix_server.auth import Permission, Principal
from forensix_server.cases import (
    CaseAccessDeniedError,
    CaseInvalidStateError,
    CaseNotFoundError,
    CaseService,
    CaseStatus,
)
from forensix_server.db import (
    CaseDeviceAssessmentRecord,
    CaseDeviceDetectionRecord,
    CaseDeviceRecord,
    CaseEventRecord,
)


class CaseDeviceNotFoundError(CaseNotFoundError):
    code = "CASE_DEVICE_NOT_FOUND"


class CaseDeviceService:
    """Stores case-linked device observations without persisting raw serials."""

    def ensure_operable(self, session: Session, principal: Principal, case_id: str) -> None:
        case = CaseService().get(session, principal, case_id)
        if not principal.can(Permission.DEVICES_OPERATE):
            raise CaseAccessDeniedError("The current user cannot operate Android devices.")
        if case.status in {CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value}:
            raise CaseInvalidStateError(
                "Device operations cannot be added to a closed or archived case."
            )

    def record_detection(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        observed_at: datetime,
        adb_version: str,
        device_count: int,
        result: Literal["no_devices", "single_device", "multiple_devices"],
    ) -> CaseDeviceDetectionRecord:
        self.ensure_operable(session, principal, case_id)
        detection = CaseDeviceDetectionRecord(
            case_id=case_id,
            operator_id=principal.user_id,
            observed_at=observed_at,
            adb_version=adb_version,
            device_count=device_count,
            result=result,
        )
        session.add(detection)
        self._event(
            session,
            case_id=case_id,
            actor_id=principal.user_id,
            event_type="device_detection_run",
            safe_detail=f"result={result};device_count={device_count}",
        )
        session.flush()
        return detection

    def register_assessment(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        snapshot: DeviceCapabilitySnapshot,
    ) -> tuple[CaseDeviceRecord, CaseDeviceAssessmentRecord]:
        self.ensure_operable(session, principal, case_id)
        serial_hash = sha256(snapshot.serial.encode("utf-8")).hexdigest()
        device = session.scalar(
            select(CaseDeviceRecord).where(
                CaseDeviceRecord.case_id == case_id,
                CaseDeviceRecord.serial_hash == serial_hash,
            )
        )
        if device is None:
            device = CaseDeviceRecord(
                case_id=case_id,
                serial_hash=serial_hash,
                serial_suffix=snapshot.serial[-5:],
                registered_by=principal.user_id,
                first_seen_at=snapshot.assessed_at,
                last_seen_at=snapshot.assessed_at,
            )
            session.add(device)
        device.manufacturer = snapshot.manufacturer
        device.model = snapshot.model
        device.android_version = snapshot.android_version
        device.sdk_level = snapshot.sdk_level
        device.build_fingerprint = snapshot.build_fingerprint
        device.security_patch = snapshot.security_patch
        device.last_seen_at = snapshot.assessed_at
        session.flush()

        assessment = CaseDeviceAssessmentRecord(
            case_id=case_id,
            device_id=device.id,
            assessed_by=principal.user_id,
            assessed_at=snapshot.assessed_at,
            package_count=snapshot.package_count,
            assessor_version=snapshot.assessor_version,
            snapshot_json=snapshot.model_dump_json(exclude={"serial"}),
        )
        session.add(assessment)
        session.flush()
        self._event(
            session,
            case_id=case_id,
            actor_id=principal.user_id,
            event_type="device_assessed",
            safe_detail=f"device_id={device.id};assessment_id={assessment.id}",
        )
        session.flush()
        return device, assessment

    def list_devices(
        self, session: Session, principal: Principal, case_id: str
    ) -> list[CaseDeviceRecord]:
        CaseService().get(session, principal, case_id)
        return list(
            session.scalars(
                select(CaseDeviceRecord)
                .where(CaseDeviceRecord.case_id == case_id)
                .order_by(CaseDeviceRecord.last_seen_at.desc(), CaseDeviceRecord.id)
            )
        )

    def get_device(
        self, session: Session, principal: Principal, case_id: str, device_id: str
    ) -> CaseDeviceRecord:
        CaseService().get(session, principal, case_id)
        device = session.get(CaseDeviceRecord, device_id)
        if device is None or device.case_id != case_id:
            raise CaseDeviceNotFoundError("The requested device is not linked to this case.")
        return device

    def list_assessments(
        self, session: Session, principal: Principal, case_id: str, device_id: str
    ) -> list[CaseDeviceAssessmentRecord]:
        self.get_device(session, principal, case_id, device_id)
        return list(
            session.scalars(
                select(CaseDeviceAssessmentRecord)
                .where(
                    CaseDeviceAssessmentRecord.case_id == case_id,
                    CaseDeviceAssessmentRecord.device_id == device_id,
                )
                .order_by(
                    CaseDeviceAssessmentRecord.assessed_at.desc(),
                    CaseDeviceAssessmentRecord.id.desc(),
                )
            )
        )

    @staticmethod
    def _event(
        session: Session,
        *,
        case_id: str,
        actor_id: str,
        event_type: str,
        safe_detail: str,
    ) -> None:
        session.add(
            CaseEventRecord(
                case_id=case_id,
                actor_id=actor_id,
                event_type=event_type,
                safe_detail=safe_detail,
            )
        )
