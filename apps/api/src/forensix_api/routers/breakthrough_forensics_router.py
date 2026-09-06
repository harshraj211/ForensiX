"""FastAPI router for Breakthrough Forensic Suite endpoints."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from forensix_api.dependencies import (
    get_adb_client,
    get_authenticated_session,
    require_device_operator,
)
from forensix_forensic.adb import AdbClient
from forensix_forensic.extractors.cloud_token_replay import CloudTokenReplayEngine
from forensix_forensic.extractors.live_touch_mapper import LiveTouchMapper
from forensix_forensic.extractors.physical_image_mounter import PhysicalImageMounter
from forensix_forensic.extractors.timeline_anomaly_detector import TimelineAnomalyDetector
from forensix_server.auth import AuthenticatedSession

router = APIRouter(prefix="/api/v1/cases/{case_id}/breakthrough", tags=["breakthrough-forensics"])


class BreakthroughRequest(BaseModel):
    serial: str
    case_id: str
    operator_id: str | None = None
    duration_sec: int | None = 15
    image_path: str | None = None


@router.post("/cloud-token-replay")
async def replay_cloud_tokens(
    case_id: str,
    payload: BreakthroughRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    adb: Annotated[AdbClient, Depends(get_adb_client)],
    _operator_permission: Annotated[None, Depends(require_device_operator)] = None,
) -> dict[str, Any]:
    """Uses harvested session tokens to synchronize cloud backups & Google timeline."""
    engine = CloudTokenReplayEngine(adb)
    res = await engine.replay_tokens_and_sync(
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
        "synced_services": [
            {
                "service_name": s.service_name,
                "target_account": s.target_account,
                "token_type": s.token_type,
                "synced_artifacts_count": s.synced_artifacts_count,
                "data_size_bytes": s.data_size_bytes,
                "sha256_hash": s.sha256_hash,
            }
            for s in res.synced_services
        ],
        "total_artifacts_synced": res.total_artifacts_synced,
        "total_bytes_downloaded": res.total_bytes_downloaded,
        "duration_seconds": res.duration_seconds,
        "success": res.success,
        "error_message": res.error_message,
    }


@router.post("/live-touch-record")
async def record_live_touch(
    case_id: str,
    payload: BreakthroughRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    adb: Annotated[AdbClient, Depends(get_adb_client)],
    _operator_permission: Annotated[None, Depends(require_device_operator)] = None,
) -> dict[str, Any]:
    """Records 60fps MP4 video with raw ADB touch gesture overlays."""
    mapper = LiveTouchMapper(adb)
    res = await mapper.record_live_touch_session(
        serial=payload.serial,
        case_id=case_id,
        duration_sec=payload.duration_sec or 15,
        operator_id=payload.operator_id or authenticated.principal.user_id,
    )
    return {
        "session_id": res.session_id,
        "serial": res.serial,
        "case_id": res.case_id,
        "operator_id": res.operator_id,
        "timestamp": res.timestamp,
        "video_output_path": res.video_output_path,
        "duration_seconds": res.duration_seconds,
        "fps": res.fps,
        "total_touch_events_mapped": res.total_touch_events_mapped,
        "sha256_seal": res.sha256_seal,
        "success": res.success,
        "error_message": res.error_message,
    }


@router.post("/timeline-anomaly-scan")
async def scan_timeline_anomalies(
    case_id: str,
    payload: BreakthroughRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    _operator_permission: Annotated[None, Depends(require_device_operator)] = None,
) -> dict[str, Any]:
    """Scans case timeline events for communication gaps, clock rollbacks, and EXIF spoofing."""
    detector = TimelineAnomalyDetector()
    res = await detector.detect_anomalies(
        case_id=case_id,
        operator_id=payload.operator_id or authenticated.principal.user_id,
    )
    return {
        "scan_id": res.scan_id,
        "case_id": res.case_id,
        "operator_id": res.operator_id,
        "timestamp": res.timestamp,
        "anomalies_detected": [
            {
                "anomaly_id": a.anomaly_id,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "affected_artifact": a.affected_artifact,
                "timestamp_range": a.timestamp_range,
                "confidence_score": a.confidence_score,
            }
            for a in res.anomalies_detected
        ],
        "total_events_analyzed": res.total_events_analyzed,
        "alibi_verification_score": res.alibi_verification_score,
        "duration_seconds": res.duration_seconds,
        "success": res.success,
        "error_message": res.error_message,
    }


@router.post("/physical-image-mount")
async def mount_physical_image(
    case_id: str,
    payload: BreakthroughRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    _operator_permission: Annotated[None, Depends(require_device_operator)] = None,
) -> dict[str, Any]:
    """Parses raw EXT4/F2FS block images to carve deleted inodes."""
    mounter = PhysicalImageMounter()
    res = await mounter.mount_and_carve_image(
        case_id=case_id,
        image_path=payload.image_path or "data/userdata.img",
        operator_id=payload.operator_id or authenticated.principal.user_id,
    )
    return {
        "mount_id": res.mount_id,
        "image_path": res.image_path,
        "case_id": res.case_id,
        "operator_id": res.operator_id,
        "timestamp": res.timestamp,
        "filesystem_type": res.filesystem_type,
        "block_size_bytes": res.block_size_bytes,
        "total_inodes_scanned": res.total_inodes_scanned,
        "carved_inodes": [
            {
                "inode_number": i.inode_number,
                "file_name": i.file_name,
                "file_type": i.file_type,
                "size_bytes": i.size_bytes,
                "unallocated_block_range": i.unallocated_block_range,
                "sha256_hash": i.sha256_hash,
            }
            for i in res.carved_inodes
        ],
        "duration_seconds": res.duration_seconds,
        "success": res.success,
        "error_message": res.error_message,
    }
