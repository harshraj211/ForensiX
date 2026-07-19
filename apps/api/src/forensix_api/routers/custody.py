"""Append-only custody and tamper-evident audit-chain endpoints."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    require_csrf_session,
)
from forensix_api.schemas import (
    AuditLogResponse,
    ChainVerificationResponse,
    CustodyCheckpointResponse,
    CustodyEventCreateRequest,
    CustodyEventResponse,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.custody import AuditService, CustodyService
from forensix_server.custody_exports import CustodyCheckpointService
from forensix_server.db import AuditLogRecord, CustodyCheckpointRecord, Database

router = APIRouter(tags=["custody", "audit"])


@router.get("/api/v1/cases/{case_id}/custody", response_model=list[CustodyEventResponse])
def list_custody(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[CustodyEventResponse]:
    with database.session() as session:
        records = CustodyService().list(session, authenticated.principal, case_id)
        return [CustodyEventResponse.model_validate(record) for record in records]


@router.post(
    "/api/v1/cases/{case_id}/custody",
    response_model=CustodyEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_custody(
    case_id: str,
    request: CustodyEventCreateRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CustodyEventResponse:
    with database.session() as session:
        record = CustodyService().create_manual(
            session,
            authenticated.principal,
            case_id,
            event_type=request.event_type,
            evidence_file_id=request.evidence_file_id,
            from_custodian=request.from_custodian,
            to_custodian=request.to_custodian,
            location=request.location,
            purpose=request.purpose,
            notes=request.notes,
            related_event_id=request.related_event_id,
        )
        return CustodyEventResponse.model_validate(record)


@router.get(
    "/api/v1/cases/{case_id}/custody/verify",
    response_model=ChainVerificationResponse,
)
def verify_custody(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ChainVerificationResponse:
    with database.session() as session:
        records = CustodyService().list(session, authenticated.principal, case_id)
        valid, broken = CustodyService().verify_chain(session, authenticated.principal, case_id)
        return ChainVerificationResponse(
            valid=valid,
            record_count=len(records),
            broken_sequence=broken,
            head_hash=records[-1].event_hash if records else None,
        )


@router.get(
    "/api/v1/cases/{case_id}/custody/checkpoints",
    response_model=list[CustodyCheckpointResponse],
)
def list_custody_checkpoints(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[CustodyCheckpointResponse]:
    return [
        _checkpoint_response(item)
        for item in CustodyCheckpointService().list(database, authenticated.principal, case_id)
    ]


@router.post(
    "/api/v1/cases/{case_id}/custody/checkpoints",
    response_model=CustodyCheckpointResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_custody_checkpoint(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CustodyCheckpointResponse:
    return _checkpoint_response(
        CustodyCheckpointService().create(database, authenticated.principal, case_id)
    )


@router.get("/api/v1/cases/{case_id}/custody/checkpoints/{checkpoint_id}/download")
def download_custody_checkpoint(
    case_id: str,
    checkpoint_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> FileResponse:
    content = CustodyCheckpointService().content(
        database, authenticated.principal, case_id, checkpoint_id
    )
    return FileResponse(
        content.path,
        media_type="application/json",
        filename=content.record.filename,
        headers={
            "Cache-Control": "no-store, private",
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
            "X-ForensiX-Checkpoint-SHA256": content.record.sha256,
            "X-ForensiX-External-Anchor": "not-anchored",
        },
    )


@router.get("/api/v1/audit-logs", response_model=list[AuditLogResponse])
def list_audit_logs(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    limit: Annotated[int, Query(ge=1, le=500)] = 500,
) -> list[AuditLogResponse]:
    with database.session() as session:
        records = AuditService().list(session, authenticated.principal, limit=limit)
        return [_audit_response(record) for record in records]


@router.get("/api/v1/audit-logs/verify", response_model=ChainVerificationResponse)
def verify_audit_logs(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ChainVerificationResponse:
    with database.session() as session:
        records = AuditService().list(session, authenticated.principal, limit=None)
        valid, broken = AuditService().verify(session, authenticated.principal)
        return ChainVerificationResponse(
            valid=valid,
            record_count=len(records),
            broken_sequence=broken,
            head_hash=records[-1].entry_hash if records else None,
        )


def _audit_response(record: AuditLogRecord) -> AuditLogResponse:
    return AuditLogResponse(
        id=record.id,
        sequence=record.sequence,
        case_id=record.case_id,
        actor_id=record.actor_id,
        event_type=record.event_type,
        object_type=record.object_type,
        object_id=record.object_id,
        detail=json.loads(record.detail_json),
        previous_hash=record.previous_hash,
        entry_hash=record.entry_hash,
        created_at=record.created_at,
    )


def _checkpoint_response(record: CustodyCheckpointRecord) -> CustodyCheckpointResponse:
    return CustodyCheckpointResponse(
        id=record.id,
        case_id=record.case_id,
        created_by=record.created_by,
        custody_record_count=record.custody_record_count,
        custody_head_hash=record.custody_head_hash,
        audit_sequence=record.audit_sequence,
        audit_head_hash=record.audit_head_hash,
        filename=record.filename,
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        schema_version=record.schema_version,
        anchor_status="not_externally_anchored",
        created_at=record.created_at,
    )
