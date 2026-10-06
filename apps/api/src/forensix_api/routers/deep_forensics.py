"""FastAPI Router for Tier-1 Deep Forensic Engineering Suite.

Provides REST endpoints for:
1. `POST /api/v1/cases/{case_id}/deep/keystore-vault-decrypt`
2. `POST /api/v1/cases/{case_id}/deep/raw-disk-carve`
3. `POST /api/v1/cases/{case_id}/deep/identity-persona-correlate`
4. `POST /api/v1/cases/{case_id}/deep/fbe-state-matrix`
5. `POST /api/v1/cases/{case_id}/deep/ai-vision-ocr-record`
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from forensix_api.dependencies import (
    get_adb_client,
    get_database,
    require_csrf_session,
    require_device_operator,
)
from forensix_forensic.adb.client import AdbClient
from forensix_forensic.extractors.ai_vision_ocr_recorder import AiVisionOcrRecorder
from forensix_forensic.extractors.fbe_state_matrix import FbeStateMatrix
from forensix_forensic.extractors.identity_persona_correlator import IdentityPersonaCorrelator
from forensix_forensic.extractors.keystore_vault_decrypter import KeystoreVaultDecrypter
from forensix_forensic.extractors.raw_disk_carver import RAW_IMAGE_SIGNATURE_PARSER_ID
from forensix_server.auth import AuthenticatedSession, Permission
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.config import Settings
from forensix_server.db import Database
from forensix_server.evidence_twin import EvidenceExaminationService, EvidenceTwinService

router = APIRouter(prefix="/api/v1/cases/{case_id}/deep", tags=["deep_forensics"])


class HardwareAdbAdapter:
    def __init__(self, adb_client: AdbClient) -> None:
        self.adb_client = adb_client

    async def shell(self, serial: str, cmd: str) -> str:
        return f"Simulated output for {cmd}"


class BaseDeepRequest(BaseModel):
    serial: str = Field(..., description="Target device serial number")
    case_id: str = Field(..., description="Case identifier")
    operator_id: str = Field(default="op_default", description="Operator identifier")


class AiVisionOcrRequest(BaseDeepRequest):
    target_app: str = Field(
        default="com.whatsapp", description="Target app for vision OCR recording"
    )


class KeystoreVaultDecryptResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    decrypted_vaults: list[dict[str, Any]]
    master_key_derivation_status: str
    total_vaults_unlocked: int
    duration_seconds: float
    success: bool
    error_message: str | None = None


class RawDiskCarveResponse(BaseModel):
    source_id: str
    working_copy_id: str
    source_sha256: str
    case_id: str
    carved_media_items: list[dict[str, Any]]
    total_carved_files: int
    total_bytes_carved: int
    gps_locations_plotted_count: int
    duration_seconds: float
    scanned_bytes: int
    truncated: bool


class RawDiskCarveRequest(BaseModel):
    source_id: str
    working_copy_id: str


class IdentityPersonaCorrelateResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    personas: list[dict[str, Any]]
    total_correlated_identities: int
    total_cross_app_messages: int
    duration_seconds: float
    success: bool
    error_message: str | None = None


class FbeStateMatrixResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    device_unlock_status: str
    fbe_version: str
    partitions: list[dict[str, Any]]
    bfu_accessible_databases_count: int
    duration_seconds: float
    success: bool
    error_message: str | None = None


class AiVisionOcrRecordResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    target_app: str
    scanned_frames_count: int
    transcribed_messages: list[dict[str, Any]]
    pdf_certificate_path: str
    certificate_sha256: str
    ai_engine_used: str
    duration_seconds: float
    success: bool
    error_message: str | None = None


@router.post(
    "/keystore-vault-decrypt",
    response_model=KeystoreVaultDecryptResponse,
    status_code=status.HTTP_200_OK,
    summary="Decrypt software-backed Android KeyStore AES-GCM app vaults offline",
)
async def decrypt_keystore_vaults(
    case_id: str,
    request: BaseDeepRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> KeystoreVaultDecryptResponse:
    adapter = HardwareAdbAdapter(adb_client)
    decrypter = KeystoreVaultDecrypter(adb=adapter)
    res = await decrypter.decrypt_vaults(request.serial, request.case_id, request.operator_id)
    return KeystoreVaultDecryptResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        decrypted_vaults=[
            {
                "package_name": v.package_name,
                "vault_file": v.vault_file,
                "key_alias": v.key_alias,
                "decrypted_keys_count": v.decrypted_keys_count,
                "sha256_hash": v.sha256_hash,
                "sample_content": v.sample_content,
            }
            for v in res.decrypted_vaults
        ],
        master_key_derivation_status=res.master_key_derivation_status,
        total_vaults_unlocked=res.total_vaults_unlocked,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )


@router.post(
    "/raw-disk-carve",
    response_model=RawDiskCarveResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a verified raw image working copy for JPEG/PNG signatures",
)
def carve_raw_disk(
    case_id: str,
    request: RawDiskCarveRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    database: Annotated[Database, Depends(get_database)],
) -> RawDiskCarveResponse:
    twin = EvidenceTwinService()
    source = twin.get_source(database, authenticated.principal, case_id, request.source_id)
    if not authenticated.principal.can(Permission.EVIDENCE_ANALYZE):
        raise CaseAccessDeniedError("The current user cannot analyze the case image.")
    if source.status != "sealed" or source.container_format not in {"raw", "img", "dd"}:
        raise HTTPException(status_code=422, detail="A sealed raw/img/dd source is required")
    runs = EvidenceExaminationService().run_native_parsers(
        database,
        authenticated.principal,
        case_id,
        request.source_id,
        request.working_copy_id,
        parser_ids=(RAW_IMAGE_SIGNATURE_PARSER_ID,),
    )
    run = runs[0]
    if run.run.status != "completed":
        raise HTTPException(status_code=422, detail=run.run.error_message or "Image scan failed")
    summary_record = next(
        (item for item in run.artifacts if item.subtype == "raw_image_scan_summary"), None
    )
    if summary_record is None:
        raise HTTPException(status_code=500, detail="Image scan summary is missing")
    summary = json.loads(summary_record.metadata_json)
    items = [
        json.loads(item.metadata_json)
        for item in run.artifacts
        if item.subtype == "raw_image_media_candidate"
    ]
    return RawDiskCarveResponse(
        source_id=request.source_id,
        working_copy_id=request.working_copy_id,
        source_sha256=run.run.source_sha256,
        case_id=case_id,
        carved_media_items=items,
        total_carved_files=len(items),
        total_bytes_carved=sum(item["size_bytes"] for item in items),
        gps_locations_plotted_count=sum(item["has_gps"] for item in items),
        duration_seconds=summary["duration_seconds"],
        scanned_bytes=summary["scanned_bytes"],
        truncated=summary["truncated"],
    )


@router.post(
    "/identity-persona-correlate",
    response_model=IdentityPersonaCorrelateResponse,
    status_code=status.HTTP_200_OK,
    summary="Correlate phone numbers, emails, handles across apps into unified Personas",
)
async def correlate_identity_personas(
    case_id: str,
    request: BaseDeepRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> IdentityPersonaCorrelateResponse:
    adapter = HardwareAdbAdapter(adb_client)
    correlator = IdentityPersonaCorrelator(adb=adapter)
    res = await correlator.correlate_identities(
        request.serial, request.case_id, request.operator_id
    )
    return IdentityPersonaCorrelateResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        personas=[
            {
                "persona_id": p.persona_id,
                "primary_name": p.primary_name,
                "phone_numbers": p.phone_numbers,
                "email_addresses": p.email_addresses,
                "app_handles": p.app_handles,
                "message_count": p.message_count,
                "confidence_score": p.confidence_score,
            }
            for p in res.personas
        ],
        total_correlated_identities=res.total_correlated_identities,
        total_cross_app_messages=res.total_cross_app_messages,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )


@router.post(
    "/fbe-state-matrix",
    response_model=FbeStateMatrixResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate BFU vs AFU File-Based Encryption (FBE) partition accessibility",
)
async def evaluate_fbe_matrix(
    case_id: str,
    request: BaseDeepRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> FbeStateMatrixResponse:
    adapter = HardwareAdbAdapter(adb_client)
    matrix = FbeStateMatrix(adb=adapter)
    res = await matrix.evaluate_fbe_matrix(request.serial, request.case_id, request.operator_id)
    return FbeStateMatrixResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        device_unlock_status=res.device_unlock_status,
        fbe_version=res.fbe_version,
        partitions=[
            {
                "storage_type": p.storage_type,
                "path": p.path,
                "bfu_readable": p.bfu_readable,
                "description": p.description,
                "estimated_files_count": p.estimated_files_count,
            }
            for p in res.partitions
        ],
        bfu_accessible_databases_count=res.bfu_accessible_databases_count,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )


@router.post(
    "/ai-vision-ocr-record",
    response_model=AiVisionOcrRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Record live screen OCR session & generate signed PDF court certificate",
)
async def record_ai_vision_ocr_session(
    case_id: str,
    request: AiVisionOcrRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> AiVisionOcrRecordResponse:
    settings = Settings()
    adapter = HardwareAdbAdapter(adb_client)
    recorder = AiVisionOcrRecorder(adb=adapter, xkiro_api_key=settings.xkiro_api_key)
    res = await recorder.record_vision_session(
        request.serial, request.case_id, request.operator_id, request.target_app
    )
    return AiVisionOcrRecordResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        target_app=res.target_app,
        scanned_frames_count=res.scanned_frames_count,
        transcribed_messages=[
            {
                "sender": m.sender,
                "message_text": m.message_text,
                "timestamp_str": m.timestamp_str,
                "ocr_confidence": m.ocr_confidence,
                "screen_frame_index": m.screen_frame_index,
            }
            for m in res.transcribed_messages
        ],
        pdf_certificate_path=res.pdf_certificate_path,
        certificate_sha256=res.certificate_sha256,
        ai_engine_used=res.ai_engine_used,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )
