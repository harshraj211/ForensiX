"""Explicitly authorized rooted-device capability workflow."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import select

from forensix_forensic.adb import AdbClient, DeviceState
from forensix_server.auth import Principal
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseInvalidStateError
from forensix_server.custody import AuditService
from forensix_server.db import CaseEventRecord, Database, RootAccessProbeRecord

ROOT_PROBE_TTL = timedelta(minutes=5)


class RootedDeviceError(CaseInvalidStateError):
    code = "ROOTED_DEVICE_INVALID"


class RootedDeviceService:
    """Persists a short-lived root proof without storing a raw device serial."""

    async def probe_access(
        self,
        database: Database,
        adb_client: AdbClient,
        principal: Principal,
        case_id: str,
        device_id: str,
        *,
        serial: str,
    ) -> RootAccessProbeRecord:
        with database.session() as session:
            CaseDeviceService().ensure_operable(session, principal, case_id)
            device = CaseDeviceService().get_device(session, principal, case_id, device_id)
            if sha256(serial.encode("utf-8")).hexdigest() != device.serial_hash:
                raise RootedDeviceError(
                    "The supplied transport does not match the selected case device."
                )
        transports = await adb_client.list_transports()
        transport = next((item for item in transports if item.serial == serial), None)
        if transport is None or transport.state is not DeviceState.AUTHORIZED:
            raise RootedDeviceError(
                "The selected case device is not present as an authorized ADB transport."
            )
        result = await adb_client.probe_root_access(serial)
        probed_at = datetime.now(UTC)
        expires_at = probed_at + ROOT_PROBE_TTL
        payload = {
            "case_id": case_id,
            "device_id": device_id,
            "expires_at": expires_at.isoformat(),
            "identity": result.identity,
            "potential_side_effect": result.potential_side_effect,
            "probed_at": probed_at.isoformat(),
            "probed_by": principal.user_id,
            "reason_code": result.reason_code,
            "status": result.status.value,
            "uid": result.uid,
        }
        record = RootAccessProbeRecord(
            case_id=case_id,
            device_id=device_id,
            probed_by=principal.user_id,
            status=result.status.value,
            uid=result.uid,
            identity=result.identity,
            reason_code=result.reason_code,
            potential_side_effect=result.potential_side_effect,
            probe_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
            expires_at=expires_at,
            probed_at=probed_at,
        )
        with database.session() as session:
            session.add(record)
            session.flush()
            session.add(
                CaseEventRecord(
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="root_access_probed",
                    safe_detail=(
                        f"device_id={device_id};status={record.status};probe_id={record.id}"
                    ),
                    created_at=probed_at,
                )
            )
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="root_access_probed",
                object_type="root_access_probe",
                object_id=record.id,
                detail={
                    "device_id": device_id,
                    "expires_at": expires_at.isoformat(),
                    "potential_side_effect": record.potential_side_effect,
                    "probe_hash": record.probe_hash,
                    "reason_code": record.reason_code,
                    "status": record.status,
                },
                created_at=probed_at,
            )
            session.flush()
            return record

    def list_probes(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        device_id: str,
    ) -> list[RootAccessProbeRecord]:
        with database.session() as session:
            CaseDeviceService().get_device(session, principal, case_id, device_id)
            return list(
                session.scalars(
                    select(RootAccessProbeRecord)
                    .where(
                        RootAccessProbeRecord.case_id == case_id,
                        RootAccessProbeRecord.device_id == device_id,
                    )
                    .order_by(
                        RootAccessProbeRecord.probed_at.desc(), RootAccessProbeRecord.id.desc()
                    )
                )
            )


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
