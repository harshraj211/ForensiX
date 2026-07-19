"""Authenticated streaming Evidence Twin import and integrity endpoints."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile, status

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    get_settings,
    require_csrf_session,
)
from forensix_api.schemas import (
    EvidenceInspectionResponse,
    EvidenceParserRunRequest,
    EvidenceParserRunResponse,
    EvidenceSourceArtifactResponse,
    EvidenceSourceResponse,
    EvidenceSourceVerificationResponse,
    EvidenceToolOutputResponse,
    EvidenceWorkingCopyResponse,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.db import (
    Database,
    EvidenceSourceArtifactRecord,
    EvidenceSourceInspectionRecord,
    EvidenceSourceRecord,
)
from forensix_server.evidence_twin import (
    AleappEvidenceService,
    EvidenceExaminationService,
    EvidenceInspectionService,
    EvidenceTwinError,
    EvidenceTwinService,
    inspection_signature,
    inspection_warnings,
)

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


@router.post(
    "/{source_id}/working-copies/{working_copy_id}/verify",
    response_model=EvidenceSourceVerificationResponse,
)
def verify_evidence_working_copy(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceSourceVerificationResponse:
    return EvidenceSourceVerificationResponse.model_validate(
        EvidenceTwinService().verify_working_copy(
            database, authenticated.principal, case_id, source_id, working_copy_id
        )
    )


@router.post(
    "/{source_id}/working-copies/{working_copy_id}/inspection",
    response_model=EvidenceInspectionResponse,
    status_code=status.HTTP_201_CREATED,
)
def inspect_evidence_working_copy(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceInspectionResponse:
    return _inspection_response(
        EvidenceInspectionService().inspect_working_copy(
            database, authenticated.principal, case_id, source_id, working_copy_id
        )
    )


@router.get(
    "/{source_id}/working-copies/{working_copy_id}/inspection",
    response_model=EvidenceInspectionResponse,
)
def get_evidence_working_copy_inspection(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceInspectionResponse:
    return _inspection_response(
        EvidenceInspectionService().get_for_working_copy(
            database, authenticated.principal, case_id, source_id, working_copy_id
        )
    )


@router.post(
    "/{source_id}/working-copies/{working_copy_id}/native-parsers",
    response_model=list[EvidenceParserRunResponse],
)
def run_native_evidence_parsers(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    request: EvidenceParserRunRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceParserRunResponse]:
    results = EvidenceExaminationService().run_native_parsers(
        database,
        authenticated.principal,
        case_id,
        source_id,
        working_copy_id,
        parser_ids=tuple(request.parser_ids) if request.parser_ids is not None else None,
    )
    return [EvidenceParserRunResponse.model_validate(item.run) for item in results]


@router.get("/{source_id}/parser-runs", response_model=list[EvidenceParserRunResponse])
def list_evidence_parser_runs(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceParserRunResponse]:
    return [
        EvidenceParserRunResponse.model_validate(item)
        for item in EvidenceExaminationService().list_runs(
            database, authenticated.principal, case_id, source_id
        )
    ]


@router.get("/{source_id}/artifacts", response_model=list[EvidenceSourceArtifactResponse])
def list_evidence_source_artifacts(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceSourceArtifactResponse]:
    return [
        _artifact_response(item)
        for item in EvidenceExaminationService().list_artifacts(
            database, authenticated.principal, case_id, source_id
        )
    ]


@router.post(
    "/{source_id}/working-copies/{working_copy_id}/aleapp",
    response_model=EvidenceParserRunResponse,
)
def run_aleapp(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> EvidenceParserRunResponse:
    runner = settings.aleapp_runner()
    if runner is None:
        raise EvidenceTwinError("ALEAPP is not configured on this workstation.")
    result = AleappEvidenceService().run(
        database,
        authenticated.principal,
        case_id,
        source_id,
        working_copy_id,
        runner,
    )
    return EvidenceParserRunResponse.model_validate(result.run)


@router.get("/{source_id}/tool-outputs", response_model=list[EvidenceToolOutputResponse])
def list_evidence_tool_outputs(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceToolOutputResponse]:
    return [
        EvidenceToolOutputResponse.model_validate(item)
        for item in AleappEvidenceService().list_outputs(
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


def _inspection_response(record: EvidenceSourceInspectionRecord) -> EvidenceInspectionResponse:
    return EvidenceInspectionResponse(
        id=record.id,
        evidence_source_id=record.evidence_source_id,
        working_copy_id=record.working_copy_id,
        case_id=record.case_id,
        inspected_by=record.inspected_by,
        detected_type=record.detected_type,  # type: ignore[arg-type]
        confidence=record.confidence,  # type: ignore[arg-type]
        encryption_state=record.encryption_state,  # type: ignore[arg-type]
        signature=inspection_signature(record),
        warnings=inspection_warnings(record),
        detector_version=record.detector_version,
        inspection_hash=record.inspection_hash,
        inspected_at=record.inspected_at,
    )


def _artifact_response(record: EvidenceSourceArtifactRecord) -> EvidenceSourceArtifactResponse:
    return EvidenceSourceArtifactResponse(
        id=record.id,
        parser_run_id=record.parser_run_id,
        evidence_source_id=record.evidence_source_id,
        working_copy_id=record.working_copy_id,
        case_id=record.case_id,
        category=record.category,  # type: ignore[arg-type]
        subtype=record.subtype,
        title=record.title,
        summary=record.summary,
        event_time=record.event_time,
        source_locator=record.source_locator,
        status=record.status,  # type: ignore[arg-type]
        confidence=record.confidence,  # type: ignore[arg-type]
        parser_id=record.parser_id,
        parser_version=record.parser_version,
        metadata=json.loads(record.metadata_json),
        provenance=json.loads(record.provenance_json),
        artifact_hash=record.artifact_hash,
        created_at=record.created_at,
    )
