"""Capability-gated creation and retrieval of immutable acquisition plans."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import (
    CaseAccessDeniedError,
    CaseInvalidStateError,
    CaseNotFoundError,
    CaseService,
    CaseStatus,
)
from forensix_server.db import (
    AcquisitionPlanRecord,
    CaseDeviceAssessmentRecord,
    CaseEventRecord,
)

from .domain import (
    MODULE_CAPABILITIES,
    PLAN_SCHEMA_VERSION,
    PRESET_MODULES,
    READINESS_MAX_AGE_MINUTES,
    AcquisitionModule,
    AcquisitionScope,
)


class AcquisitionPlanNotFoundError(CaseNotFoundError):
    code = "ACQUISITION_PLAN_NOT_FOUND"


class AcquisitionPlanValidationError(CaseInvalidStateError):
    code = "ACQUISITION_PLAN_INVALID"


class AcquisitionPlanService:
    def create(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        device_id: str,
        assessment_id: str,
        scope: AcquisitionScope,
        requested_modules: tuple[AcquisitionModule, ...] = (),
        limitations_acknowledged: bool,
        now: datetime | None = None,
    ) -> AcquisitionPlanRecord:
        current_time = _as_utc(now or datetime.now(UTC))
        case = CaseService().get(session, principal, case_id)
        if not principal.can(Permission.ACQUISITIONS_OPERATE):
            raise CaseAccessDeniedError("The current user cannot create acquisition plans.")
        if case.status in {CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value}:
            raise AcquisitionPlanValidationError(
                "Acquisition plans cannot be created for a closed or archived case."
            )
        if not limitations_acknowledged:
            raise AcquisitionPlanValidationError(
                "The operator must acknowledge the forensic limitations before planning."
            )

        CaseDeviceService().get_device(session, principal, case_id, device_id)
        assessment = session.get(CaseDeviceAssessmentRecord, assessment_id)
        if assessment is None or assessment.case_id != case_id or assessment.device_id != device_id:
            raise AcquisitionPlanValidationError(
                "The selected readiness snapshot does not belong to this case device."
            )

        assessed_at = _as_utc(assessment.assessed_at)
        expires_at = assessed_at + timedelta(minutes=READINESS_MAX_AGE_MINUTES)
        if current_time > expires_at:
            raise AcquisitionPlanValidationError(
                "The readiness snapshot is stale; reassess the device before creating a plan."
            )

        modules = self._resolve_modules(scope, requested_modules)
        snapshot = _parse_snapshot(assessment.snapshot_json)
        capabilities = snapshot.get("capabilities")
        if not isinstance(capabilities, dict):
            raise AcquisitionPlanValidationError("The readiness snapshot is malformed.")
        blocked = [
            module.value
            for module in modules
            if not _capability_supported(capabilities, MODULE_CAPABILITIES[module])
        ]
        if blocked:
            raise AcquisitionPlanValidationError(
                "The readiness snapshot does not support: " + ", ".join(blocked)
            )
        if AcquisitionModule.SHARED_STORAGE_INVENTORY in modules and not _has_readable_root(
            snapshot
        ):
            raise AcquisitionPlanValidationError(
                "Shared-storage inventory requires at least one readable approved root."
            )

        warnings = snapshot.get("warnings")
        snapshot_warnings = (
            [item for item in warnings if isinstance(item, str)]
            if isinstance(warnings, list)
            else []
        )
        limitations = [
            "Controlled Logical Triage Mode is not hardware write blocking.",
            "This plan authorizes only registered modules and does not start acquisition.",
            "Capabilities are point-in-time observations and are revalidated before execution.",
            *snapshot_warnings,
        ]
        module_values = sorted(module.value for module in modules)
        snapshot_hash = sha256(assessment.snapshot_json.encode("utf-8")).hexdigest()
        plan_payload = {
            "assessment_id": assessment.id,
            "case_id": case_id,
            "created_at": current_time.isoformat(),
            "created_by": principal.user_id,
            "device_id": device_id,
            "limitations": limitations,
            "modules": module_values,
            "readiness_assessed_at": assessed_at.isoformat(),
            "readiness_expires_at": expires_at.isoformat(),
            "schema_version": PLAN_SCHEMA_VERSION,
            "scope": scope.value,
            "snapshot_hash": snapshot_hash,
        }
        plan_hash = sha256(_canonical_json(plan_payload).encode("utf-8")).hexdigest()
        plan = AcquisitionPlanRecord(
            case_id=case_id,
            device_id=device_id,
            assessment_id=assessment.id,
            created_by=principal.user_id,
            scope=scope.value,
            status="ready",
            modules_json=_canonical_json(module_values),
            limitations_json=_canonical_json(limitations),
            snapshot_hash=snapshot_hash,
            plan_hash=plan_hash,
            schema_version=PLAN_SCHEMA_VERSION,
            readiness_assessed_at=assessed_at,
            readiness_expires_at=expires_at,
            created_at=current_time,
        )
        session.add(plan)
        session.flush()
        session.add(
            CaseEventRecord(
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="acquisition_plan_created",
                safe_detail=f"plan_id={plan.id};scope={scope.value}",
            )
        )
        session.flush()
        return plan

    def list_for_case(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[AcquisitionPlanRecord], int]:
        CaseService().get(session, principal, case_id)
        total = (
            session.scalar(
                select(func.count())
                .select_from(AcquisitionPlanRecord)
                .where(AcquisitionPlanRecord.case_id == case_id)
            )
            or 0
        )
        plans = list(
            session.scalars(
                select(AcquisitionPlanRecord)
                .where(AcquisitionPlanRecord.case_id == case_id)
                .order_by(AcquisitionPlanRecord.created_at.desc(), AcquisitionPlanRecord.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return plans, total

    def get(
        self, session: Session, principal: Principal, case_id: str, plan_id: str
    ) -> AcquisitionPlanRecord:
        CaseService().get(session, principal, case_id)
        plan = session.get(AcquisitionPlanRecord, plan_id)
        if plan is None or plan.case_id != case_id:
            raise AcquisitionPlanNotFoundError("The requested acquisition plan does not exist.")
        return plan

    @staticmethod
    def _resolve_modules(
        scope: AcquisitionScope,
        requested_modules: tuple[AcquisitionModule, ...],
    ) -> tuple[AcquisitionModule, ...]:
        if scope is AcquisitionScope.CUSTOM:
            modules = tuple(sorted(set(requested_modules), key=lambda item: item.value))
            if not modules:
                raise AcquisitionPlanValidationError(
                    "A custom plan must select at least one registered module."
                )
            return modules
        if requested_modules:
            raise AcquisitionPlanValidationError(
                "Preset scopes do not accept a custom module selection."
            )
        return PRESET_MODULES[scope]


def plan_modules(plan: AcquisitionPlanRecord) -> list[str]:
    value = json.loads(plan.modules_json)
    return [item for item in value if isinstance(item, str)]


def plan_limitations(plan: AcquisitionPlanRecord) -> list[str]:
    value = json.loads(plan.limitations_json)
    return [item for item in value if isinstance(item, str)]


def _parse_snapshot(snapshot_json: str) -> dict[str, Any]:
    try:
        value = json.loads(snapshot_json)
    except json.JSONDecodeError as error:
        raise AcquisitionPlanValidationError("The readiness snapshot is malformed.") from error
    if not isinstance(value, dict):
        raise AcquisitionPlanValidationError("The readiness snapshot is malformed.")
    return value


def _capability_supported(capabilities: dict[str, Any], capability: str) -> bool:
    value = capabilities.get(capability)
    return isinstance(value, dict) and value.get("status") == "supported"


def _has_readable_root(snapshot: dict[str, Any]) -> bool:
    roots = snapshot.get("storage_roots")
    return isinstance(roots, list) and any(
        isinstance(root, dict) and root.get("readable") is True for root in roots
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
