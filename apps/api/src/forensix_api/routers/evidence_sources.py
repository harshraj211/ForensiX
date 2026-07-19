"""Authenticated streaming Evidence Twin import and integrity endpoints."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile, status

from forensix_api.dependencies import get_authenticated_session, get_database, require_csrf_session
from forensix_api.schemas import (
    EvidenceSourceResponse,
    EvidenceSourceVerificationResponse,
    EvidenceWorkingCopyResponse,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database, EvidenceSourceRecord
from forensix_server.evidence_twin import EvidenceTwinService

router = APIRouter(prefix="/api/v1/cases/{case_id}/evidence-sources", tags=["evidence-sources"])


@router.get("", response_model=list[EvidenceSourceResponse])
def list_evidence_sources(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceSourceResponse]:
    return [
        _source_response(item)
        for item in EvidenceTwinService().list_sources(database, authenticated.principal, case_id)
    ]


@router.post(
    "/import",
    response_model=EvidenceSourceResponse,
    status_code=status.HTTP_201_CREATED,
)
def import_evidence_source(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    source: Annotated[UploadFile, File(description="Evidence image, archive, or bundle")],
    display_name: Annotated[str | None, Form(max_length=255)] = None,
) -> EvidenceSourceResponse:
    try:
        record = EvidenceTwinService().import_stream(
            database,
            authenticated.principal,
            case_id,
            source.file,
            source_name=source.filename or "imported.evidence",
            display_name=display_name,
            declared_size_bytes=source.size,
        )
    finally:
        source.file.close()
    return _source_response(record)


@router.get("/{source_id}", response_model=EvidenceSourceResponse)
def get_evidence_source(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceSourceResponse:
    return _source_response(
        EvidenceTwinService().get_source(database, authenticated.principal, case_id, source_id)
    )


@router.post("/{source_id}/verify", response_model=EvidenceSourceVerificationResponse)
def verify_evidence_source(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceSourceVerificationResponse:
    return EvidenceSourceVerificationResponse.model_validate(
        EvidenceTwinService().verify_master(database, authenticated.principal, case_id, source_id)
    )


@router.get(
    "/{source_id}/verifications",
    response_model=list[EvidenceSourceVerificationResponse],
)
def list_evidence_source_verifications(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceSourceVerificationResponse]:
    return [
        EvidenceSourceVerificationResponse.model_validate(item)
        for item in EvidenceTwinService().list_verifications(
            database, authenticated.principal, case_id, source_id
        )
    ]


@router.post(
    "/{source_id}/working-copies",
    response_model=EvidenceWorkingCopyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_evidence_working_copy(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceWorkingCopyResponse:
    return EvidenceWorkingCopyResponse.model_validate(
        EvidenceTwinService().create_working_copy(
            database, authenticated.principal, case_id, source_id
        )
    )


@router.get("/{source_id}/working-copies", response_model=list[EvidenceWorkingCopyResponse])
def list_evidence_working_copies(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceWorkingCopyResponse]:
    return [
        EvidenceWorkingCopyResponse.model_validate(item)
        for item in EvidenceTwinService().list_working_copies(
            database, authenticated.principal, case_id, source_id
        )
    ]


def _source_response(record: EvidenceSourceRecord) -> EvidenceSourceResponse:
    limitations = json.loads(record.limitations_json)
    return EvidenceSourceResponse(
        id=record.id,
        case_id=record.case_id,
        device_id=record.device_id,
        created_by=record.created_by,
        source_type=record.source_type,  # type: ignore[arg-type]
        acquisition_level=record.acquisition_level,  # type: ignore[arg-type]
        status=record.status,  # type: ignore[arg-type]
        display_name=record.display_name,
        source_name=record.source_name,
        container_format=record.container_format,  # type: ignore[arg-type]
        size_bytes=record.size_bytes,
        sha256=record.sha256,
        chunks_sha256=record.chunks_sha256,
        manifest_sha256=record.manifest_sha256,
        chunk_size_bytes=record.chunk_size_bytes,
        chunk_count=record.chunk_count,
        read_only_applied=record.read_only_applied,
        validation_state=record.validation_state,
        limitations=limitations,
        tool_version=record.tool_version,
        error_code=record.error_code,
        error_message=record.error_message,
        sealed_at=record.sealed_at,
        created_at=record.created_at,
    )
