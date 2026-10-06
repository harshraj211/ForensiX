"""Unified case-scoped observation API for the durable job ledger."""

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_api.schemas import CaseJobListResponse, CaseJobResponse, JobEventResponse
from forensix_server.auth import AuthenticatedSession
from forensix_server.cases import CaseService
from forensix_server.db import Database, JobEventRecord, JobRecord
from forensix_server.jobs import JobService, JobState, JobType

router = APIRouter(prefix="/api/v1/cases/{case_id}/jobs", tags=["jobs"])


@router.get("", response_model=CaseJobListResponse)
def list_case_jobs(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    job_type: Annotated[JobType | None, Query()] = None,
    state: Annotated[JobState | None, Query()] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> CaseJobListResponse:
    """List acquisition, parsing, analysis, report, and export jobs together."""
    with database.session() as session:
        CaseService().get(session, authenticated.principal, case_id)
        filters: list[Any] = [JobRecord.case_id == case_id]
        if job_type is not None:
            filters.append(JobRecord.job_type == job_type.value)
        if state is not None:
            filters.append(JobRecord.state == state.value)
        total = session.scalar(select(func.count()).select_from(JobRecord).where(*filters)) or 0
        records = list(
            session.scalars(
                select(JobRecord)
                .where(*filters)
                .order_by(JobRecord.updated_at.desc(), JobRecord.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return CaseJobListResponse(
            items=[_job_response(record) for record in records],
            total=total,
            offset=offset,
            limit=limit,
        )


@router.get("/{job_id}", response_model=CaseJobResponse)
def get_case_job(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CaseJobResponse:
    with database.session() as session:
        CaseService().get(session, authenticated.principal, case_id)
        return _job_response(_get_case_job(session, case_id, job_id))


@router.get("/{job_id}/events", response_model=list[JobEventResponse])
def list_case_job_events(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[JobEventResponse]:
    with database.session() as session:
        CaseService().get(session, authenticated.principal, case_id)
        _get_case_job(session, case_id, job_id)
        return [_event_response(event) for event in JobService().list_events(session, job_id)]


def _get_case_job(session: Session, case_id: str, job_id: str) -> JobRecord:
    job = session.get(JobRecord, job_id)
    if job is None or job.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested case job does not exist.",
        )
    return job


def _checkpoint(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _job_response(job: JobRecord) -> CaseJobResponse:
    if job.case_id is None:
        raise RuntimeError("Case job responses require a case reference.")
    return CaseJobResponse(
        id=job.id,
        case_id=job.case_id,
        owner_id=job.owner_id,
        plan_id=job.plan_id,
        job_type=JobType(job.job_type),
        state=JobState(job.state),
        progress_percent=job.progress_percent,
        current_step=job.current_step,
        current_module=job.current_module,
        cancellation_requested=job.cancellation_requested,
        resume_supported=job.resume_supported,
        checkpoint=_checkpoint(job.checkpoint_json),
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
        checkpoint=_checkpoint(event.checkpoint_json),
        safe_detail=event.safe_detail,
        created_at=event.created_at,
    )
