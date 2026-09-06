"""FastAPI router for Next-Gen Non-Rooted Forensic Suite endpoints."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from forensix_api.dependencies import (
    get_adb_client,
    get_authenticated_session,
    require_device_operator,
)
from forensix_forensic.adb import AdbClient
from forensix_forensic.extractors.android15_private_space import Android15PrivateSpaceExtractor
from forensix_forensic.extractors.ephemeral_ram_analyzer import EphemeralRamKeyAnalyzer
from forensix_forensic.extractors.whatsapp_crypt16_17 import WhatsAppCrypt16_17Extractor
from forensix_server.auth import AuthenticatedSession

router = APIRouter(prefix="/api/v1/cases/{case_id}/nextgen", tags=["nextgen-forensics"])


class NextGenRequest(BaseModel):
    serial: str
    case_id: str
    operator_id: str | None = None
    backup_file_name: str | None = None


@router.post("/android15-private-space-scan")
async def scan_android15_private_space(
    case_id: str,
    payload: NextGenRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    adb: Annotated[AdbClient, Depends(get_adb_client)],
    _operator_permission: Annotated[None, Depends(require_device_operator)] = None,
) -> dict[str, Any]:
    """Detects & triages Android 15 Private Space hidden user profiles over ADB."""
    extractor = Android15PrivateSpaceExtractor(adb)
    res = await extractor.triage_private_space(
        serial=payload.serial,
        case_id=case_id,
        operator_id=payload.operator_id or authenticated.principal.user_id,
    )
    return {
        "extraction_id": res.extraction_id,
        "serial": res.serial,
        "case_id": res.case_id,
        "operator_id": res.operator_id,
        "timestamp": res.timestamp,
        "profiles_found": [
            {
                "user_id": p.user_id,
                "user_name": p.user_name,
                "user_type": p.user_type,
                "is_unlocked": p.is_unlocked,
                "is_quiet_mode_enabled": p.is_quiet_mode_enabled,
                "installed_target_packages": p.installed_target_packages,
                "extracted_database_count": p.extracted_database_count,
            }
            for p in res.profiles_found
        ],
        "total_private_apps_detected": res.total_private_apps_detected,
        "duration_seconds": res.duration_seconds,
        "success": res.success,
        "error_message": res.error_message,
    }


@router.post("/whatsapp-crypt16-17-decrypt")
async def decrypt_whatsapp_crypt16_17(
    case_id: str,
    payload: NextGenRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    adb: Annotated[AdbClient, Depends(get_adb_client)],
    _operator_permission: Annotated[None, Depends(require_device_operator)] = None,
) -> dict[str, Any]:
    """Decrypts WhatsApp Crypt16 & Crypt17 backups offline via HKDF key derivation."""
    extractor = WhatsAppCrypt16_17Extractor(adb)
    res = await extractor.decrypt_crypt16_17(
        serial=payload.serial,
        case_id=case_id,
        backup_file_name=payload.backup_file_name,
        operator_id=payload.operator_id or authenticated.principal.user_id,
    )
    return {
        "extraction_id": res.extraction_id,
        "serial": res.serial,
        "case_id": res.case_id,
        "operator_id": res.operator_id,
        "timestamp": res.timestamp,
        "backup_format": res.backup_format,
        "cipher_algorithm": res.cipher_algorithm,
        "hkdf_key_derived": res.hkdf_key_derived,
        "total_messages_unlocked": res.total_messages_unlocked,
        "total_chat_threads": res.total_chat_threads,
        "sha256_hash": res.sha256_hash,
        "duration_seconds": res.duration_seconds,
        "success": res.success,
        "error_message": res.error_message,
    }


@router.post("/ephemeral-ram-key-scan")
async def scan_ephemeral_ram_keys(
    case_id: str,
    payload: NextGenRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    adb: Annotated[AdbClient, Depends(get_adb_client)],
    _operator_permission: Annotated[None, Depends(require_device_operator)] = None,
) -> dict[str, Any]:
    """Scans running process memory maps over ADB for active encryption keys."""
    extractor = EphemeralRamKeyAnalyzer(adb)
    res = await extractor.scan_ram_keys(
        serial=payload.serial,
        case_id=case_id,
        operator_id=payload.operator_id or authenticated.principal.user_id,
    )
    return {
        "extraction_id": res.extraction_id,
        "serial": res.serial,
        "case_id": res.case_id,
        "operator_id": res.operator_id,
        "timestamp": res.timestamp,
        "keys_extracted": [
            {
                "package_name": k.package_name,
                "pid": k.pid,
                "memory_region": k.memory_region,
                "key_type": k.key_type,
                "entropy_score": k.entropy_score,
                "key_sha256": k.key_sha256,
            }
            for k in res.keys_extracted
        ],
        "total_processes_scanned": res.total_processes_scanned,
        "duration_seconds": res.duration_seconds,
        "success": res.success,
        "error_message": res.error_message,
    }
