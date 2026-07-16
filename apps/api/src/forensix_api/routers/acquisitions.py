"""Protected durable acquisition-job preparation and observation endpoints."""

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
    JobEventResponse,
)
from forensix_forensic.adb import AdbClient
from forensix_server.acquisitions import (
    AcquisitionExecutionService,
    AcquisitionFileService,
    AcquisitionInventoryService,
    event_checkpoint,
    job_checkpoint,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    Database,
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
