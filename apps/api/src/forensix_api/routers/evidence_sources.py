"""Authenticated streaming Evidence Twin import and integrity endpoints."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile, status
from fastapi.responses import FileResponse

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
    RecoveryAssessmentResponse,
)
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.db import (
    Database,
    EvidenceRecoveryAssessmentRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceInspectionRecord,
    EvidenceSourceRecord,
)
from forensix_server.evidence_twin import (
    AleappEvidenceService,
    EvidenceExaminationService,
    EvidenceInspectionService,
    EvidenceRecoveryAssessmentService,
    EvidenceTwinError,
    EvidenceTwinIntegrityError,
    EvidenceTwinService,
    inspection_signature,
    inspection_warnings,
    recovery_assessment_result,
)

router = APIRouter(prefix="/api/v1/cases/{case_id}/evidence-sources", tags=["evidence-sources"])


@router.get("", response_model=list[EvidenceSourceResponse])
def list_evidence_sources(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceSourceResponse]:
    return [
        source_response(item)
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
    return source_response(record)


@router.get("/{source_id}", response_model=EvidenceSourceResponse)
def get_evidence_source(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceSourceResponse:
    return source_response(
        EvidenceTwinService().get_source(database, authenticated.principal, case_id, source_id)
    )


@router.get("/{source_id}/content", response_class=FileResponse)
def get_evidence_source_content(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    download: bool = False,
) -> FileResponse:
    """View or download a PNG screenshot without modifying the sealed master."""
    source = EvidenceTwinService().get_source(database, authenticated.principal, case_id, source_id)
    if (
        source.status != "sealed"
        or not source.sealed_storage_key
        or not source.sha256
        or not source.source_name.casefold().endswith(".png")
    ):
        raise EvidenceTwinError("Only a sealed PNG evidence source can be viewed directly.")
    path = EvidenceStore(database.data_dir / "evidence").resolve(
        source.sealed_storage_key, require_file=True
    )
    with path.open("rb") as stream:
        if stream.read(8) != b"\x89PNG\r\n\x1a\n":
            raise EvidenceTwinIntegrityError(
                "The evidence source does not contain the expected PNG signature."
            )
    return FileResponse(
        path,
        media_type="image/png",
        filename=source.source_name,
        content_disposition_type="attachment" if download else "inline",
        headers={
            "Cache-Control": "no-store, private",
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
            "X-ForensiX-Evidence-SHA256": source.sha256,
        },
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
    "/{source_id}/working-copies/{working_copy_id}/recovery-assessment",
    response_model=RecoveryAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def assess_evidence_recovery_candidates(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> RecoveryAssessmentResponse:
    return _recovery_response(
        EvidenceRecoveryAssessmentService().assess(
            database, authenticated.principal, case_id, source_id, working_copy_id
        )
    )


@router.get(
    "/{source_id}/working-copies/{working_copy_id}/recovery-assessment",
    response_model=RecoveryAssessmentResponse,
)
def get_evidence_recovery_assessment(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> RecoveryAssessmentResponse:
    return _recovery_response(
        EvidenceRecoveryAssessmentService().get(
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


def source_response(record: EvidenceSourceRecord) -> EvidenceSourceResponse:
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


def _recovery_response(
    record: EvidenceRecoveryAssessmentRecord,
) -> RecoveryAssessmentResponse:
    result = recovery_assessment_result(record)
    return RecoveryAssessmentResponse(
        id=record.id,
        evidence_source_id=record.evidence_source_id,
        working_copy_id=record.working_copy_id,
        inspection_id=record.inspection_id,
        case_id=record.case_id,
        assessed_by=record.assessed_by,
        maturity="experimental",
        status=record.status,  # type: ignore[arg-type]
        candidate_region_count=record.candidate_region_count,
        candidates=result.get("candidates", []),
        limitations=result.get("limitations", []),
        assessment_hash=record.assessment_hash,
        tool_version=record.tool_version,
        assessed_at=record.assessed_at,
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
