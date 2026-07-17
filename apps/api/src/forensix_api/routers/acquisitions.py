"""Protected durable acquisition-job preparation and observation endpoints."""

from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Query, Response, status

from forensix_api.dependencies import (
    get_adb_client,
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import (
    AcquiredEvidenceFileResponse,
    AcquisitionInventoryItemResponse,
    AcquisitionInventoryResponse,
    AcquisitionJobListResponse,
    AcquisitionJobPrepareRequest,
    AcquisitionJobResponse,
    AcquisitionPartialResponse,
    AcquisitionResumeRequest,
    EvidenceVerificationResponse,
    JobEventResponse,
)
from forensix_forensic.adb import AdbClient
from forensix_server.acquisitions import (
    AcquisitionExecutionService,
    AcquisitionFileService,
    AcquisitionInventoryService,
    AcquisitionRecoveryError,
    AcquisitionRecoveryService,
    EvidenceVerificationService,
    event_checkpoint,
    job_checkpoint,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    AcquisitionPartialRecord,
    Database,
    EvidenceVerificationRecord,
    JobEventRecord,
    JobRecord,
)
from forensix_server.jobs import JobState

router = APIRouter(prefix="/api/v1/cases/{case_id}/acquisitions", tags=["acquisitions"])


@router.get("", response_model=AcquisitionJobListResponse)
def list_acquisition_jobs(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> AcquisitionJobListResponse:
    with database.session() as session:
        jobs, total = AcquisitionExecutionService().list_for_case(
            session,
            authenticated.principal,
            case_id,
            offset=offset,
            limit=limit,
        )
        items = [_job_response(job) for job in jobs]
    return AcquisitionJobListResponse(items=items, total=total, offset=offset, limit=limit)


@router.post("", response_model=AcquisitionJobResponse, status_code=status.HTTP_201_CREATED)
def prepare_acquisition_job(
    case_id: str,
    request: AcquisitionJobPrepareRequest,
    response: Response,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AcquisitionJobResponse:
    with database.session() as session:
        job, created = AcquisitionExecutionService().prepare(
            session,
            authenticated.principal,
            case_id,
            request.plan_id,
        )
        result = _job_response(job)
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return result


@router.get("/{job_id}", response_model=AcquisitionJobResponse)
def get_acquisition_job(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AcquisitionJobResponse:
    with database.session() as session:
        job = AcquisitionExecutionService().get(session, authenticated.principal, case_id, job_id)
        return _job_response(job)


@router.get("/{job_id}/events", response_model=list[JobEventResponse])
def list_acquisition_job_events(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[JobEventResponse]:
    with database.session() as session:
        events = AcquisitionExecutionService().list_events(
            session, authenticated.principal, case_id, job_id
        )
        return [_event_response(event) for event in events]


@router.post("/{job_id}/cancel", response_model=AcquisitionJobResponse)
def cancel_acquisition_job(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AcquisitionJobResponse:
    with database.session() as session:
        job = AcquisitionExecutionService().cancel(
            session, authenticated.principal, case_id, job_id
        )
        return _job_response(job)


@router.post("/{job_id}/inventory", response_model=AcquisitionInventoryResponse)
async def run_acquisition_inventory(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
) -> AcquisitionInventoryResponse:
    inventory = await AcquisitionInventoryService().run(
        database,
        authenticated.principal,
        case_id,
        job_id,
        adb_client,
    )
    with database.session() as session:
        inventory, items, total = AcquisitionInventoryService().list_items(
            session,
            authenticated.principal,
            case_id,
            job_id,
        )
        return _inventory_response(inventory, items, total, offset=0, limit=100)


@router.get("/{job_id}/inventory", response_model=AcquisitionInventoryResponse)
def get_acquisition_inventory(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> AcquisitionInventoryResponse:
    with database.session() as session:
        inventory, items, total = AcquisitionInventoryService().list_items(
            session,
            authenticated.principal,
            case_id,
            job_id,
            offset=offset,
            limit=limit,
        )
        return _inventory_response(inventory, items, total, offset=offset, limit=limit)


@router.post(
    "/{job_id}/inventory/items/{item_id}/acquire",
    response_model=AcquiredEvidenceFileResponse,
)
async def acquire_inventory_file(
    case_id: str,
    job_id: str,
    item_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
) -> AcquiredEvidenceFileResponse:
    record = await AcquisitionFileService().acquire(
        database,
        authenticated.principal,
        case_id,
        job_id,
        item_id,
        adb_client,
    )
    return _file_response(record)


@router.get("/{job_id}/partials", response_model=list[AcquisitionPartialResponse])
def list_acquisition_partials(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[AcquisitionPartialResponse]:
    with database.session() as session:
        records = AcquisitionRecoveryService().list_for_job(
            session, authenticated.principal, case_id, job_id
        )
        return [_partial_response(record) for record in records]


@router.post(
    "/{job_id}/files/{evidence_file_id}/resume",
    response_model=AcquiredEvidenceFileResponse,
)
async def resume_acquired_file(
    case_id: str,
    job_id: str,
    evidence_file_id: str,
    request: AcquisitionResumeRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
) -> AcquiredEvidenceFileResponse:
    with database.session() as session:
        AcquisitionExecutionService().get(session, authenticated.principal, case_id, job_id)
        evidence = session.get(AcquiredEvidenceFileRecord, evidence_file_id)
        if (
            evidence is None
            or evidence.case_id != case_id
            or evidence.job_id != job_id
            or evidence.status not in {"failed", "interrupted"}
        ):
            raise AcquisitionRecoveryError(
                "Only a failed or interrupted evidence file from this job can restart."
            )
        item_id = evidence.inventory_item_id
    AcquisitionRecoveryService().review_pending(
        database,
        authenticated.principal,
        case_id,
        job_id,
        evidence_file_id,
        disposition=request.partial_disposition,
    )
    record = await AcquisitionFileService().acquire(
        database,
        authenticated.principal,
        case_id,
        job_id,
        item_id,
        adb_client,
    )
    return _file_response(record)


@router.get("/{job_id}/files", response_model=list[AcquiredEvidenceFileResponse])
def list_acquired_files(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[AcquiredEvidenceFileResponse]:
    with database.session() as session:
        records = AcquisitionFileService().list_for_job(
            session,
            authenticated.principal,
            case_id,
            job_id,
        )
        return [_file_response(record) for record in records]


@router.post(
    "/{job_id}/files/{evidence_file_id}/verify",
    response_model=EvidenceVerificationResponse,
)
async def verify_acquired_file(
    case_id: str,
    job_id: str,
    evidence_file_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceVerificationResponse:
    verification = await EvidenceVerificationService().verify(
        database,
        authenticated.principal,
        case_id,
        job_id,
        evidence_file_id,
    )
    return _verification_response(verification)


@router.get(
    "/{job_id}/verifications",
    response_model=list[EvidenceVerificationResponse],
)
def list_evidence_verifications(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceVerificationResponse]:
    with database.session() as session:
        records = EvidenceVerificationService().list_for_job(
            session,
            authenticated.principal,
            case_id,
            job_id,
        )
        return [_verification_response(record) for record in records]


def _job_response(job: JobRecord) -> AcquisitionJobResponse:
    if job.case_id is None or job.plan_id is None or job.owner_id is None:
        raise RuntimeError("Acquisition jobs require case, plan, and owner references.")
    return AcquisitionJobResponse(
        id=job.id,
        case_id=job.case_id,
        plan_id=job.plan_id,
        owner_id=job.owner_id,
        state=JobState(job.state),
        progress_percent=job.progress_percent,
        current_step=job.current_step,
        current_module=job.current_module,
        cancellation_requested=job.cancellation_requested,
        resume_supported=job.resume_supported,
        checkpoint=job_checkpoint(job),
        error_code=job.error_code,
        error_message=job.error_message,
        result_reference=job.result_reference,
        last_event_sequence=job.last_event_sequence,
        version=job.version,
        created_at=job.created_at,
        updated_at=job.updated_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
    )


def _event_response(event: JobEventRecord) -> JobEventResponse:
    return JobEventResponse(
        id=event.id,
        job_id=event.job_id,
        sequence=event.sequence,
        event_type=event.event_type,
        state=JobState(event.state),
        progress_percent=event.progress_percent,
        current_step=event.current_step,
        current_module=event.current_module,
        checkpoint=event_checkpoint(event),
        safe_detail=event.safe_detail,
        created_at=event.created_at,
    )


def _inventory_response(
    inventory: AcquisitionInventoryRecord,
    items: list[AcquisitionInventoryItemRecord],
    total: int,
    *,
    offset: int,
    limit: int,
) -> AcquisitionInventoryResponse:
    return AcquisitionInventoryResponse(
        id=inventory.id,
        job_id=inventory.job_id,
        case_id=inventory.case_id,
        plan_id=inventory.plan_id,
        device_id=inventory.device_id,
        created_by=inventory.created_by,
        root_id=inventory.root_id,
        display_path=inventory.display_path,
        status="truncated" if inventory.status == "truncated" else "completed",
        discovered_count=inventory.discovered_count,
        persisted_count=inventory.persisted_count,
        skipped_count=inventory.skipped_count,
        max_items=inventory.max_items,
        max_depth=inventory.max_depth,
        manifest_hash=inventory.manifest_hash,
        started_at=inventory.started_at,
        completed_at=inventory.completed_at,
        items=[
            AcquisitionInventoryItemResponse(
                id=item.id,
                ordinal=item.ordinal,
                relative_path=item.relative_path,
                path_hash=item.path_hash,
                extension=item.extension,
                size_bytes=item.size_bytes,
                modified_time_raw=item.modified_time_raw,
                modified_at=(
                    _aware_utc(item.modified_at) if item.modified_at is not None else None
                ),
                timestamp_source=item.timestamp_source,
                timestamp_confidence=("medium" if item.timestamp_confidence == "medium" else None),
            )
            for item in items
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


def _file_response(record: AcquiredEvidenceFileRecord) -> AcquiredEvidenceFileResponse:
    status_value = record.status
    if status_value not in {"acquiring", "completed", "failed", "interrupted"}:
        raise RuntimeError("Acquired evidence file has an invalid persisted status.")
    return AcquiredEvidenceFileResponse(
        id=record.id,
        inventory_id=record.inventory_id,
        inventory_item_id=record.inventory_item_id,
        job_id=record.job_id,
        case_id=record.case_id,
        plan_id=record.plan_id,
        device_id=record.device_id,
        acquired_by=record.acquired_by,
        status=cast(Literal["acquiring", "completed", "failed", "interrupted"], status_value),
        source_root_id=record.source_root_id,
        source_path_hash=record.source_path_hash,
        storage_key=record.storage_key,
        manifest_storage_key=record.manifest_storage_key,
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        manifest_hash=record.manifest_hash,
        transfer_limit_bytes=record.transfer_limit_bytes,
        tool_version=record.tool_version,
        validation_state="not_physically_validated",
        partial_preserved=record.partial_preserved,
        error_code=record.error_code,
        error_message=record.error_message,
        started_at=record.started_at,
        completed_at=record.completed_at,
    )


def _partial_response(record: AcquisitionPartialRecord) -> AcquisitionPartialResponse:
    status_value = record.status
    if status_value not in {"active", "retained", "discarded", "sealed", "missing"}:
        raise RuntimeError("Acquisition partial has an invalid persisted status.")
    return AcquisitionPartialResponse(
        id=record.id,
        evidence_file_id=record.evidence_file_id,
        case_id=record.case_id,
        job_id=record.job_id,
        created_by=record.created_by,
        storage_key=record.storage_key,
        status=cast(
            Literal["active", "retained", "discarded", "sealed", "missing"],
            status_value,
        ),
        reason_code=record.reason_code,
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        disposition_by=record.disposition_by,
        created_at=record.created_at,
        reconciled_at=record.reconciled_at,
        disposition_at=record.disposition_at,
    )


def _verification_response(
    record: EvidenceVerificationRecord,
) -> EvidenceVerificationResponse:
    status_value = record.status
    if status_value not in {"verified", "mismatch", "missing", "error"}:
        raise RuntimeError("Evidence verification has an invalid persisted status.")
    return EvidenceVerificationResponse(
        id=record.id,
        evidence_file_id=record.evidence_file_id,
        case_id=record.case_id,
        job_id=record.job_id,
        verified_by=record.verified_by,
        status=cast(Literal["verified", "mismatch", "missing", "error"], status_value),
        expected_file_sha256=record.expected_file_sha256,
        observed_file_sha256=record.observed_file_sha256,
        file_size_bytes=record.file_size_bytes,
        file_matches=record.file_matches,
        expected_manifest_sha256=record.expected_manifest_sha256,
        observed_manifest_sha256=record.observed_manifest_sha256,
        manifest_matches=record.manifest_matches,
        error_code=record.error_code,
        verification_hash=record.verification_hash,
        tool_version=record.tool_version,
        verified_at=record.verified_at,
    )


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
