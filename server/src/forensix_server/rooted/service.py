"""Explicitly authorized rooted-device capability workflow."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select

from forensix_forensic.adb import AdbClient, DeviceState, RootedCollectionProfile
from forensix_server.auth import Principal
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseInvalidStateError
from forensix_server.custody import AuditService
from forensix_server.db import (
    CaseEventRecord,
    Database,
    EvidenceSourceRecord,
    RootAccessProbeRecord,
)
from forensix_server.evidence_twin import EvidenceTwinService

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

    async def capture_provider_bundle(
        self,
        database: Database,
        adb_client: AdbClient,
        principal: Principal,
        case_id: str,
        device_id: str,
        *,
        serial: str,
        probe_id: str,
        profile: RootedCollectionProfile,
        side_effects_acknowledged: bool,
    ) -> EvidenceSourceRecord:
        """Capture a fixed rooted profile and seal it immediately as Evidence Twin evidence."""
        if not side_effects_acknowledged:
            raise RootedDeviceError("Rooted collection side effects must be acknowledged.")
        with database.session() as session:
            CaseDeviceService().ensure_operable(session, principal, case_id)
            device = CaseDeviceService().get_device(session, principal, case_id, device_id)
            if sha256(serial.encode("utf-8")).hexdigest() != device.serial_hash:
                raise RootedDeviceError(
                    "The supplied transport does not match the selected case device."
                )
            probe = session.get(RootAccessProbeRecord, probe_id)
            if (
                probe is None
                or probe.case_id != case_id
                or probe.device_id != device_id
                or probe.status != "available"
                or probe.uid != 0
            ):
                raise RootedDeviceError(
                    "A current, successful root proof for this case device is required."
                )
            expires_at = _as_utc(probe.expires_at)
            if expires_at <= datetime.now(UTC):
                raise RootedDeviceError("The root proof has expired; run the probe again.")

        transports = await adb_client.list_transports()
        transport = next((item for item in transports if item.serial == serial), None)
        if transport is None or transport.state is not DeviceState.AUTHORIZED:
            raise RootedDeviceError(
                "The selected case device is not present as an authorized ADB transport."
            )

        temporary_path = await asyncio.to_thread(_new_rooted_temporary_path, database.data_dir)
        try:
            captured = await adb_client.capture_rooted_bundle(serial, profile, temporary_path)
            source = await asyncio.to_thread(
                _seal_rooted_path,
                database,
                principal,
                case_id,
                device_id,
                temporary_path,
                captured.size_bytes,
                profile,
            )
        finally:
            await asyncio.to_thread(_remove_temporary, temporary_path)

        now = datetime.now(UTC)
        with database.session() as session:
            session.add(
                CaseEventRecord(
                    case_id=case_id,
                    actor_id=principal.user_id,
                    event_type="rooted_provider_bundle_captured",
                    safe_detail=(
                        f"device_id={device_id};probe_id={probe_id};"
                        f"evidence_source_id={source.id};profile={profile.value}"
                    ),
                    created_at=now,
                )
            )
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="rooted_provider_bundle_captured",
                object_type="evidence_source",
                object_id=source.id,
                detail={
                    "device_id": device_id,
                    "evidence_source_sha256": source.sha256,
                    "probe_id": probe_id,
                    "profile": profile.value,
                    "size_bytes": source.size_bytes,
                    "side_effect_classification": "elevated_read_device_logs_possible",
                },
                created_at=now,
            )
            session.flush()
        return source


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _new_rooted_temporary_path(data_dir: Path) -> Path:
    workspace = (data_dir / "work" / "rooted").resolve()
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    if workspace.is_symlink() or not workspace.is_dir():
        raise RootedDeviceError("The rooted acquisition workspace is not a safe directory.")
    destination = (workspace / f"{uuid4()}.tar.partial").resolve()
    if destination.parent != workspace:
        raise RootedDeviceError("The rooted acquisition workspace path is invalid.")
    return destination


def _seal_rooted_path(
    database: Database,
    principal: Principal,
    case_id: str,
    device_id: str,
    path: Path,
    size_bytes: int,
    profile: RootedCollectionProfile,
) -> EvidenceSourceRecord:
    with path.open("rb") as stream:
        return EvidenceTwinService().seal_rooted_stream(
            database,
            principal,
            case_id,
            device_id,
            stream,
            source_name=f"{profile.value}.tar",
            display_name="Rooted Android provider bundle",
            declared_size_bytes=size_bytes,
        )


def _remove_temporary(path: Path) -> None:
    try:
        if not path.is_symlink() and path.is_file():
            path.unlink()
    except OSError:
        # The sealed master is authoritative; cleanup failure is reported by workstation logs.
        return
