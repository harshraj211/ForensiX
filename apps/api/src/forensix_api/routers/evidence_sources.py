"""Authenticated streaming Evidence Twin import and integrity endpoints."""

import json
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Annotated
from zipfile import ZIP_STORED, ZipFile

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, StreamingResponse

from forensix_api.dependencies import (
    get_authenticated_session,
    get_database,
    get_settings,
    require_csrf_session,
)
from forensix_api.schemas import (
    AgentBundleImportResponse,
    BackupImportResponse,
    CloudExportImportResponse,
    EvidenceInspectionResponse,
    EvidenceParserRunRequest,
    EvidenceParserRunResponse,
    EvidenceSourceArtifactResponse,
    EvidenceSourceResponse,
    EvidenceSourceVerificationResponse,
    EvidenceToolOutputResponse,
    EvidenceWorkingCopyResponse,
    ExternalRecoveryResponse,
    ParserJobResponse,
    RecoveryAssessmentResponse,
    RecoveryCarvingResponse,
    SourceArtifactSearchResponse,
)
from forensix_forensic.evidence_io import ArchiveExtractionError, validate_archive_member_name
from forensix_forensic.extractors.agent_apk import InvalidAgentBundle, import_agent_bundle
from forensix_forensic.extractors.backup_import import (
    InvalidBackupImport,
    inspect_backup_import,
)
from forensix_forensic.extractors.cloud.exports import CloudExportError
from forensix_forensic.extractors.memory_card import (
    iter_active_file,
    iter_deleted_candidate,
    probe_fat32,
    verified_active_file,
    verified_deleted_candidate,
)
from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.db import (
    Database,
    EvidenceExternalRecoveryRunRecord,
    EvidenceRecoveryAssessmentRecord,
    EvidenceRecoveryCarvingRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceInspectionRecord,
    EvidenceSourceRecord,
    EvidenceWorkingCopyRecord,
    JobRecord,
)
from forensix_server.evidence_twin import (
    AleappEvidenceService,
    EvidenceExaminationService,
    EvidenceExternalRecoveryService,
    EvidenceInspectionService,
    EvidenceRecoveryAssessmentService,
    EvidenceRecoveryCarvingService,
    EvidenceTwinError,
    EvidenceTwinIntegrityError,
    EvidenceTwinService,
    external_recovery_result,
    inspection_signature,
    inspection_warnings,
    recovery_assessment_result,
    recovery_carving_result,
)
from forensix_server.evidence_twin.cloud_exports import CloudExportService
from forensix_server.jobs import JobState

router = APIRouter(prefix="/api/v1/cases/{case_id}/evidence-sources", tags=["evidence-sources"])

_MAX_AGENT_BUNDLE_BYTES = 256 * 1024 * 1024
_MAX_BACKUP_IMPORT_BYTES = 2 * 1024 * 1024 * 1024


@router.post("/import/cloud-export", response_model=CloudExportImportResponse, status_code=201)
def import_cloud_export(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    source: Annotated[UploadFile, File()],
    provider: Annotated[str, Form()],
    source_timezone: Annotated[str, Form(max_length=100)] = "UTC",
    date_order: Annotated[str, Form()] = "DMY",
) -> CloudExportImportResponse:
    try:
        record, run, summary = CloudExportService().import_stream(
            database, authenticated.principal, case_id, source.file,
            source_name=source.filename or "export.zip", provider=provider,
            source_timezone=source_timezone, date_order=date_order,
        )
    except CloudExportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        source.file.close()
    return CloudExportImportResponse(evidence_source=source_response(record),
                                    parser_run=EvidenceParserRunResponse.model_validate(run), summary=summary)


@router.get("/{source_id}/cloud-export-summary", response_model=CloudExportImportResponse)
def cloud_export_summary(
    case_id: str, source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CloudExportImportResponse:
    record, run, summary = CloudExportService().summary(database, authenticated.principal, case_id, source_id)
    return CloudExportImportResponse(evidence_source=source_response(record),
                                    parser_run=EvidenceParserRunResponse.model_validate(run) if run else None, summary=summary)


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


@router.post(
    "/import/agent-bundle",
    response_model=AgentBundleImportResponse,
    status_code=status.HTTP_201_CREATED,
)
def import_android_agent_bundle(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    source: Annotated[UploadFile, File(description="User-exported .fxz agent bundle")],
) -> AgentBundleImportResponse:
    """Validate a user-exported bundle, then seal its original bytes in the case vault."""
    if not (source.filename or "").lower().endswith(".fxz"):
        raise HTTPException(status_code=422, detail="Expected a .fxz agent bundle")
    work_parent = database.data_dir / "work"
    work_parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="agent-bundle-", dir=work_parent) as temp:
            bundle_path = Path(temp) / "collection.fxz"
            size = 0
            with bundle_path.open("wb") as destination:
                while chunk := source.file.read(1024 * 1024):
                    size += len(chunk)
                    if size > _MAX_AGENT_BUNDLE_BYTES:
                        raise HTTPException(status_code=413, detail="Agent bundle exceeds 256 MiB")
                    destination.write(chunk)
            try:
                result = import_agent_bundle(
                    bundle_path, case_id=case_id, output_dir=Path(temp) / "validated"
                )
            except (InvalidAgentBundle, ValueError) as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            manifest = json.loads((Path(result.output_dir) / "manifest.json").read_text())
            source_statuses = {
                name: entry.get("status", "ok")
                for name, entry in manifest["files"].items()
            }
            record_counts = {
                "contacts": len(result.contacts),
                "sms": len(result.sms_messages),
                "call_logs": len(result.call_logs),
                "installed_apps": len(result.installed_apps),
                "app_artifacts": len(result.app_artifacts),
                "wifi_states": len(result.wifi_states),
                "bluetooth_devices": len(result.bluetooth_devices),
                "sim_subscriptions": len(result.sim_subscriptions),
            }
            with bundle_path.open("rb") as stream:
                record = EvidenceTwinService().seal_agent_bundle_stream(
                    database,
                    authenticated.principal,
                    case_id,
                    stream,
                    source_name=source.filename or "collection.fxz",
                    declared_size_bytes=size,
                    collection_id=result.extraction_id,
                    complete=result.success,
                    source_statuses=source_statuses,
                    record_counts=record_counts,
                )
            return AgentBundleImportResponse(
                evidence_source=source_response(record),
                collection_id=result.extraction_id,
                collection_complete=result.success,
                source_statuses=source_statuses,
                record_counts=record_counts,
            )
    finally:
        source.file.close()


@router.post(
    "/import/device-backup",
    response_model=BackupImportResponse,
    status_code=status.HTTP_201_CREATED,
)
def import_android_device_backup(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    source: Annotated[UploadFile, File(description="User-supplied backup or card image")],
) -> BackupImportResponse:
    source_name = source.filename or "android-backup.bin"
    suffix = Path(source_name.replace("\\", "/")).suffix.casefold()
    if suffix not in {".ab", ".zip", ".sbu", ".img", ".dd", ".raw"}:
        raise HTTPException(status_code=422, detail="Expected a .ab, .zip, .sbu, .img, .dd, or .raw input")
    work_parent = database.data_dir / "work"
    work_parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="backup-import-", dir=work_parent) as temp:
            backup_path = Path(temp) / f"upload{suffix}"
            size = 0
            with backup_path.open("wb") as destination:
                while chunk := source.file.read(1024 * 1024):
                    size += len(chunk)
                    if size > _MAX_BACKUP_IMPORT_BYTES:
                        raise HTTPException(status_code=413, detail="Backup exceeds 2 GiB")
                    destination.write(chunk)
            return _seal_staged_backup(
                case_id, authenticated, database, backup_path, source_name=source_name,
            )
    finally:
        source.file.close()


@router.post(
    "/import/smart-switch-folder",
    response_model=BackupImportResponse,
    status_code=status.HTTP_201_CREATED,
)
def import_smart_switch_folder(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    files: Annotated[list[UploadFile], File(description="Files selected from one Smart Switch PC backup folder")],
    relative_paths: Annotated[list[str], Form(description="Matching browser relative paths")],
) -> BackupImportResponse:
    """Package a browser-selected PC backup folder without reading host paths."""
    if not files or len(files) != len(relative_paths) or len(files) > 10_000:
        raise HTTPException(status_code=422, detail="Provide matching files and relative paths (maximum 10,000)")
    work_parent = database.data_dir / "work"
    work_parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="smart-switch-folder-", dir=work_parent) as temp:
            archive_path = Path(temp) / "upload.zip"
            seen: set[str] = set()
            member_manifest: list[dict[str, str | int]] = []
            total_bytes = 0
            try:
                with ZipFile(archive_path, "w", compression=ZIP_STORED, allowZip64=True) as archive:
                    for source, relative_path in zip(files, relative_paths, strict=True):
                        normalized = validate_archive_member_name(relative_path, 20)
                        if normalized in seen:
                            raise HTTPException(status_code=422, detail="Duplicate folder member path")
                        seen.add(normalized)
                        digest = sha256()
                        size = 0
                        with archive.open(relative_path, "w", force_zip64=True) as destination:
                            while chunk := source.file.read(1024 * 1024):
                                size += len(chunk)
                                total_bytes += len(chunk)
                                if size > 512 * 1024 * 1024 or total_bytes > _MAX_BACKUP_IMPORT_BYTES:
                                    raise HTTPException(status_code=413, detail="Smart Switch folder exceeds the import limits")
                                digest.update(chunk)
                                destination.write(chunk)
                        member_manifest.append({"path": relative_path, "sha256": digest.hexdigest(), "size_bytes": size})
            except ArchiveExtractionError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if archive_path.stat().st_size > _MAX_BACKUP_IMPORT_BYTES:
                raise HTTPException(status_code=413, detail="Packaged Smart Switch folder exceeds 2 GiB")
            return _seal_staged_backup(
                case_id, authenticated, database, archive_path,
                source_name="SmartSwitch-PC-Folder.zip",
                source_assembly={"kind": "browser_selected_folder", "members": member_manifest},
            )
    finally:
        for source in files:
            source.file.close()


def _seal_staged_backup(
    case_id: str,
    authenticated: AuthenticatedSession,
    database: Database,
    backup_path: Path,
    *,
    source_name: str,
    source_assembly: dict[str, object] | None = None,
) -> BackupImportResponse:
    try:
        result = inspect_backup_import(backup_path, source_name=source_name)
    except (InvalidBackupImport, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    inspection = {
        "backup_kind": result.backup_kind,
        "format_version": result.format_version,
        "compression": result.compression,
        "encrypted": result.encrypted,
        "member_count": result.member_count,
        "member_bytes": result.member_bytes,
        "package_hints": list(result.package_hints),
        "warnings": list(result.warnings),
        "filesystem_type": result.filesystem_type,
        "filesystem_block_size": result.filesystem_block_size,
    }
    if source_assembly is not None:
        inspection["source_assembly"] = source_assembly
    with backup_path.open("rb") as stream:
        record = EvidenceTwinService().seal_backup_import_stream(
            database, authenticated.principal, case_id, stream,
            source_name=source_name, declared_size_bytes=backup_path.stat().st_size,
            inspection=inspection,
        )
    parser_run_id = None
    parsed_artifact_count = None
    parser_status = None
    parser_error = None
    parse_card = result.backup_kind == "memory_card_image" and result.filesystem_type == "fat32"
    if (result.backup_kind in {"samsung_smart_switch_archive", "legacy_android_backup"} or parse_card) and not result.encrypted:
        twin = EvidenceTwinService()
        copy = twin.create_working_copy(database, authenticated.principal, case_id, record.id)
        runs = EvidenceExaminationService().run_native_parsers(
            database, authenticated.principal, case_id, record.id, copy.id
        )
        if runs:
            parser_run_id = runs[0].run.id
            parsed_artifact_count = len(runs[0].artifacts)
            parser_status = runs[0].run.status
            parser_error = runs[0].run.error_message
    return BackupImportResponse(
        evidence_source=source_response(record), parser_run_id=parser_run_id,
        parsed_artifact_count=parsed_artifact_count, parser_status=parser_status,
        parser_error=parser_error, **{key: value for key, value in inspection.items() if key != "source_assembly"},
    )


@router.get("/{source_id}/agent-bundle-summary", response_model=AgentBundleImportResponse)
def get_android_agent_bundle_summary(
    case_id: str,
    source_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> AgentBundleImportResponse:
    """Read persistent collection status from the sealed case manifest."""
    record = EvidenceTwinService().get_source(
        database, authenticated.principal, case_id, source_id
    )
    if record.status != "sealed" or not record.manifest_storage_key:
        raise EvidenceTwinError("The agent bundle source is not sealed.")
    path = EvidenceStore(database.data_dir / "evidence").resolve(
        record.manifest_storage_key, require_file=True
    )
    manifest_bytes = path.read_bytes()
    if sha256(manifest_bytes).hexdigest() != record.manifest_sha256:
        raise EvidenceTwinIntegrityError("The evidence manifest hash does not match.")
    metadata = json.loads(manifest_bytes).get("acquisition_metadata", {})
    if metadata.get("operation") != "android_agent_user_export":
        raise EvidenceTwinError("This source is not an Android agent bundle.")
    return AgentBundleImportResponse(
        evidence_source=source_response(record),
        collection_id=metadata["collection_id"],
        collection_complete=metadata["collection_complete"],
        source_statuses=metadata["source_statuses"],
        record_counts=metadata["record_counts"],
    )


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
    "/{source_id}/working-copies/{working_copy_id}/recovery-carving",
    response_model=RecoveryCarvingResponse,
    status_code=status.HTTP_201_CREATED,
)
def carve_evidence_recovery_candidates(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> RecoveryCarvingResponse:
    return _recovery_carving_response(
        EvidenceRecoveryCarvingService().carve(
            database, authenticated.principal, case_id, source_id, working_copy_id
        )
    )


@router.get(
    "/{source_id}/working-copies/{working_copy_id}/recovery-carving",
    response_model=RecoveryCarvingResponse,
)
def get_evidence_recovery_carving(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> RecoveryCarvingResponse:
    return _recovery_carving_response(
        EvidenceRecoveryCarvingService().get(
            database, authenticated.principal, case_id, source_id, working_copy_id
        )
    )


@router.post(
    "/{source_id}/working-copies/{working_copy_id}/external-recovery",
    response_model=ExternalRecoveryResponse,
    status_code=status.HTTP_201_CREATED,
)
def run_external_recovery(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ExternalRecoveryResponse:
    return _external_recovery_response(
        EvidenceExternalRecoveryService().run(
            database,
            authenticated.principal,
            case_id,
            source_id,
            working_copy_id,
            settings.photorec_controller(),
        )
    )


@router.get(
    "/{source_id}/working-copies/{working_copy_id}/external-recovery",
    response_model=ExternalRecoveryResponse,
)
def get_external_recovery(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ExternalRecoveryResponse:
    return _external_recovery_response(
        EvidenceExternalRecoveryService().get(
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


@router.post(
    "/{source_id}/working-copies/{working_copy_id}/parser-jobs",
    response_model=ParserJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_parser_job(
    case_id: str,
    source_id: str,
    working_copy_id: str,
    request: EvidenceParserRunRequest,
    background_tasks: BackgroundTasks,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ParserJobResponse:
    job = EvidenceExaminationService().prepare_parser_job(
        database,
        authenticated.principal,
        case_id,
        source_id,
        working_copy_id,
        parser_ids=tuple(request.parser_ids) if request.parser_ids is not None else None,
    )
    background_tasks.add_task(
        EvidenceExaminationService().execute_parser_job,
        database,
        authenticated.principal,
        job.id,
    )
    return _parser_job_response(job)


@router.get("/parser-jobs/{job_id}", response_model=ParserJobResponse)
def get_parser_job(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ParserJobResponse:
    job = EvidenceExaminationService().get_parser_job(
        database, authenticated.principal, case_id, job_id
    )
    return _parser_job_response(job)


@router.post("/parser-jobs/{job_id}/cancel", response_model=ParserJobResponse)
def cancel_parser_job(
    case_id: str,
    job_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> ParserJobResponse:
    job = EvidenceExaminationService().cancel_parser_job(
        database, authenticated.principal, case_id, job_id
    )
    return _parser_job_response(job)


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


@router.get("/artifacts/search", response_model=SourceArtifactSearchResponse)
def search_source_artifacts(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
    q: str | None = None,
    category: str | None = None,
    status: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> SourceArtifactSearchResponse:
    result = EvidenceExaminationService().search_source_artifacts(
        database,
        authenticated.principal,
        case_id,
        query=q,
        category=category,
        status=status,
        offset=offset,
        limit=limit,
    )
    return SourceArtifactSearchResponse(
        items=[_artifact_response(item) for item in result.items],
        total=result.total,
        offset=result.offset,
        limit=result.limit,
        category_facets=result.category_facets,
    )


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


@router.get("/{source_id}/artifacts/{artifact_id}/candidate-content")
def download_deleted_card_candidate(
    case_id: str,
    source_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> StreamingResponse:
    """Export a reverified FAT32 deleted-entry candidate, never the sealed master."""
    EvidenceTwinService().get_source(database, authenticated.principal, case_id, source_id)
    with database.session() as session:
        artifact = session.get(EvidenceSourceArtifactRecord, artifact_id)
        if (
            artifact is None or artifact.case_id != case_id
            or artifact.evidence_source_id != source_id
            or artifact.parser_id != "memory_card.fat32.image"
            or artifact.subtype != "memory_card_deleted_candidate"
        ):
            raise HTTPException(status_code=404, detail="Card recovery candidate not found")
        working_copy = session.get(EvidenceWorkingCopyRecord, artifact.working_copy_id)
        if working_copy is None or working_copy.case_id != case_id:
            raise HTTPException(status_code=404, detail="Verified working copy not found")
        metadata = json.loads(artifact.metadata_json)
        storage_key = working_copy.storage_key
        copy_id = working_copy.id
    if metadata.get("recovery_status") != "contiguous_unallocated_candidate":
        raise HTTPException(status_code=409, detail="This deleted entry has no extractable candidate content")
    cluster = metadata.get("first_cluster")
    size = metadata.get("candidate_byte_count")
    digest = metadata.get("candidate_sha256")
    if type(cluster) is not int or type(size) is not int or not isinstance(digest, str):
        raise EvidenceTwinIntegrityError("The candidate provenance is incomplete.")
    verification = EvidenceTwinService().verify_working_copy(
        database, authenticated.principal, case_id, source_id, copy_id
    )
    if verification.status != "verified":
        raise EvidenceTwinIntegrityError("The candidate working copy failed integrity verification.")
    image = EvidenceStore(database.data_dir / "evidence").resolve(storage_key, require_file=True)
    try:
        verified_deleted_candidate(
            image, first_cluster=cluster, size_bytes=size, expected_sha256=digest
        )
    except ValueError as exc:
        raise EvidenceTwinIntegrityError(str(exc)) from exc
    volume = probe_fat32(image)
    if volume is None:
        raise EvidenceTwinIntegrityError("The candidate FAT32 volume disappeared.")
    return StreamingResponse(
        iter_deleted_candidate(image, volume, cluster, size),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(size),
            "Content-Disposition": f'attachment; filename="candidate-{artifact_id}.bin"',
            "Cache-Control": "no-store, private",
            "X-Content-Type-Options": "nosniff",
            "X-ForensiX-Candidate-SHA256": digest,
        },
    )


@router.get("/{source_id}/artifacts/{artifact_id}/file-content")
def download_active_card_file(
    case_id: str,
    source_id: str,
    artifact_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> StreamingResponse:
    """Export an indexed FAT32 file from its verified working copy."""
    EvidenceTwinService().get_source(database, authenticated.principal, case_id, source_id)
    with database.session() as session:
        artifact = session.get(EvidenceSourceArtifactRecord, artifact_id)
        if (
            artifact is None or artifact.case_id != case_id
            or artifact.evidence_source_id != source_id
            or artifact.parser_id != "memory_card.fat32.image"
            or artifact.subtype != "memory_card_file"
        ):
            raise HTTPException(status_code=404, detail="Card file artifact not found")
        working_copy = session.get(EvidenceWorkingCopyRecord, artifact.working_copy_id)
        if working_copy is None or working_copy.case_id != case_id:
            raise HTTPException(status_code=404, detail="Verified working copy not found")
        metadata = json.loads(artifact.metadata_json)
        storage_key = working_copy.storage_key
        copy_id = working_copy.id
    if metadata.get("hash_status") != "complete":
        raise HTTPException(status_code=409, detail="This card file has no verified content hash")
    cluster = metadata.get("first_cluster")
    size = metadata.get("size_bytes")
    digest = metadata.get("sha256")
    if type(cluster) is not int or type(size) is not int or not isinstance(digest, str):
        raise EvidenceTwinIntegrityError("The card file provenance is incomplete.")
    verification = EvidenceTwinService().verify_working_copy(
        database, authenticated.principal, case_id, source_id, copy_id
    )
    if verification.status != "verified":
        raise EvidenceTwinIntegrityError("The card working copy failed integrity verification.")
    image = EvidenceStore(database.data_dir / "evidence").resolve(storage_key, require_file=True)
    try:
        volume = verified_active_file(
            image, first_cluster=cluster, size_bytes=size, expected_sha256=digest
        )
    except ValueError as exc:
        raise EvidenceTwinIntegrityError(str(exc)) from exc
    return StreamingResponse(
        iter_active_file(image, volume, cluster, size),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(size),
            "Content-Disposition": f'attachment; filename="card-file-{artifact_id}.bin"',
            "Cache-Control": "no-store, private",
            "X-Content-Type-Options": "nosniff",
            "X-ForensiX-File-SHA256": digest,
        },
    )


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


def _recovery_carving_response(
    record: EvidenceRecoveryCarvingRecord,
) -> RecoveryCarvingResponse:
    result = recovery_carving_result(record)
    return RecoveryCarvingResponse(
        id=record.id,
        evidence_source_id=record.evidence_source_id,
        working_copy_id=record.working_copy_id,
        inspection_id=record.inspection_id,
        case_id=record.case_id,
        executed_by=record.executed_by,
        maturity="experimental",
        status=record.status,  # type: ignore[arg-type]
        fragment_count=record.fragment_count,
        fragments=result.get("fragments", []),
        input_locators=result.get("input_locators", []),
        skipped_locators=result.get("skipped_locators", []),
        source_file_count=result.get("source_file_count", 0),
        source_total_bytes=result.get("source_total_bytes", 0),
        wal_fragments_found=result.get("wal_fragments_found", 0),
        freelist_fragments_found=result.get("freelist_fragments_found", 0),
        unallocated_fragments_found=result.get("unallocated_fragments_found", 0),
        duration_seconds=result.get("duration_seconds", 0.0),
        limitations=result.get("limitations", []),
        run_hash=record.run_hash,
        tool_version=record.tool_version,
        executed_at=record.executed_at,
    )


def _external_recovery_response(
    record: EvidenceExternalRecoveryRunRecord,
) -> ExternalRecoveryResponse:
    result = external_recovery_result(record)
    return ExternalRecoveryResponse(
        id=record.id,
        evidence_source_id=record.evidence_source_id,
        working_copy_id=record.working_copy_id,
        inspection_id=record.inspection_id,
        case_id=record.case_id,
        executed_by=record.executed_by,
        tool_id=record.tool_id,
        maturity="experimental",
        status=record.status,  # type: ignore[arg-type]
        recovered_file_count=record.recovered_file_count,
        output_storage_key=record.output_storage_key,
        command=result.get("command", []),
        console_summary=result.get("console_summary", ""),
        executable_sha256=result.get("executable_sha256"),
        exit_code=result.get("exit_code"),
        output_files=result.get("output_files", []),
        output_total_bytes=result.get("output_total_bytes", 0),
        version=result.get("version", "unreported"),
        limitations=result.get("limitations", []),
        run_hash=record.run_hash,
        tool_version=record.tool_version,
        executed_at=record.executed_at,
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


def _parser_job_response(job: JobRecord) -> ParserJobResponse:
    checkpoint = None
    if job.checkpoint_json:
        try:
            checkpoint = json.loads(job.checkpoint_json)
        except Exception:
            checkpoint = None
    return ParserJobResponse(
        id=job.id,
        case_id=job.case_id,
        owner_id=job.owner_id,
        state=JobState(job.state),
        progress_percent=job.progress_percent,
        current_step=job.current_step,
        current_module=job.current_module,
        cancellation_requested=job.cancellation_requested,
        checkpoint=checkpoint,
        error_code=job.error_code,
        error_message=job.error_message,
        result_reference=job.result_reference,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )
