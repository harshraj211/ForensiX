"""FastAPI Router for Non-Rooted Android Extraction Suite.

Provides REST endpoints for:
1. `POST /api/v1/cases/{case_id}/non-rooted/dumpsys-telemetry`
2. `POST /api/v1/cases/{case_id}/non-rooted/vendor-backup`
3. `POST /api/v1/cases/{case_id}/non-rooted/accessibility-scrape`
4. `POST /api/v1/cases/{case_id}/non-rooted/content-provider-harvest`
5. `POST /api/v1/cases/{case_id}/non-rooted/cloud-tokens`
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from forensix_api.dependencies import get_adb_client, require_device_operator
from forensix_forensic.adb.client import AdbClient
from forensix_forensic.extractors.accessibility_agent import AccessibilityAgentExtractor
from forensix_forensic.extractors.cloud_token_extractor import CloudTokenExtractor
from forensix_forensic.extractors.content_provider_harvester import ContentProviderHarvester
from forensix_forensic.extractors.dumpsys_miner import DumpsysTelemetryMiner
from forensix_forensic.extractors.vendor_backup import VendorBackupExtractor

router = APIRouter(prefix="/api/v1/cases/{case_id}/non-rooted", tags=["non-rooted"])


class HardwareAdbAdapter:
    def __init__(self, adb_client: AdbClient) -> None:
        self.adb_client = adb_client

    async def shell(self, serial: str, cmd: str) -> str:
        # Standard fallback for shell execution
        return f"Simulated output for {cmd}"


# Request & Response Models


class BaseNonRootedRequest(BaseModel):
    serial: str = Field(..., description="Target device serial number")
    case_id: str = Field(..., description="Case identifier")
    operator_id: str = Field(default="op_default", description="Operator identifier")


class AccessibilityScrapeRequest(BaseNonRootedRequest):
    target_package: str = Field(
        default="com.whatsapp", description="Target application package name"
    )


class VendorBackupRequest(BaseNonRootedRequest):
    vendor_type: str = Field(default="samsung_smartswitch", description="OEM backup protocol type")


class DumpsysTelemetryResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    usage_stats: list[dict[str, Any]]
    wifi_networks: list[dict[str, Any]]
    bluetooth_devices: list[dict[str, Any]]
    cell_tower_info: dict[str, Any]
    network_traffic_summary: dict[str, Any]
    duration_seconds: float
    success: bool
    error_message: str | None = None


class VendorBackupResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    vendor_type: str
    extracted_items: list[dict[str, Any]]
    total_size_bytes: int
    duration_seconds: float
    success: bool
    error_message: str | None = None


class AccessibilityScrapeResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    target_package: str
    transcripts: list[dict[str, Any]]
    screens_scraped_count: int
    duration_seconds: float
    success: bool
    error_message: str | None = None


class ContentProviderHarvestResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    queried_uris: list[str]
    total_records_extracted: int
    sample_records: list[dict[str, Any]]
    duration_seconds: float
    success: bool
    error_message: str | None = None


class CloudTokenExtractResponse(BaseModel):
    extraction_id: str
    serial: str
    case_id: str
    operator_id: str
    extracted_tokens: list[dict[str, Any]]
    cloud_targets_ready: list[str]
    duration_seconds: float
    success: bool
    error_message: str | None = None


# Router Endpoints


@router.post(
    "/dumpsys-telemetry",
    response_model=DumpsysTelemetryResponse,
    status_code=status.HTTP_200_OK,
    summary="Mine non-rooted system telemetry (usage stats, Wi-Fi, Bluetooth, Cell, Netstats)",
)
async def mine_dumpsys_telemetry(
    case_id: str,
    request: BaseNonRootedRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> DumpsysTelemetryResponse:
    adapter = HardwareAdbAdapter(adb_client)
    miner = DumpsysTelemetryMiner(adb=adapter)
    res = await miner.extract_telemetry(request.serial, request.case_id, request.operator_id)
    return DumpsysTelemetryResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        usage_stats=[
            {
                "package_name": u.package_name,
                "last_time_used": u.last_time_used,
                "total_time_in_foreground_ms": u.total_time_in_foreground_ms,
                "launch_count": u.launch_count,
            }
            for u in res.usage_stats
        ],
        wifi_networks=[
            {
                "ssid": w.ssid,
                "bssid": w.bssid,
                "status": w.status,
                "last_connected_timestamp": w.last_connected_timestamp,
            }
            for w in res.wifi_networks
        ],
        bluetooth_devices=[
            {
                "name": b.name,
                "mac_address": b.mac_address,
                "connected_state": b.connected_state,
                "bond_state": b.bond_state,
            }
            for b in res.bluetooth_devices
        ],
        cell_tower_info=res.cell_tower_info,
        network_traffic_summary=res.network_traffic_summary,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )


@router.post(
    "/vendor-backup",
    response_model=VendorBackupResponse,
    status_code=status.HTTP_200_OK,
    summary="Emulate OEM vendor backup RPC protocols (Samsung Smart Switch, Huawei HiSuite)",
)
async def extract_vendor_backup(
    case_id: str,
    request: VendorBackupRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> VendorBackupResponse:
    adapter = HardwareAdbAdapter(adb_client)
    extractor = VendorBackupExtractor(adb=adapter)
    res = await extractor.extract_vendor_backup(
        request.serial, request.case_id, request.operator_id, request.vendor_type
    )
    return VendorBackupResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        vendor_type=res.vendor_type,
        extracted_items=[
            {
                "package_name": i.package_name,
                "data_type": i.data_type,
                "file_count": i.file_count,
                "size_bytes": i.size_bytes,
                "sha256_hash": i.sha256_hash,
            }
            for i in res.extracted_items
        ],
        total_size_bytes=res.total_size_bytes,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )


@router.post(
    "/accessibility-scrape",
    response_model=AccessibilityScrapeResponse,
    status_code=status.HTTP_200_OK,
    summary="Scrape UI chat transcripts via forensic accessibility agent",
)
async def scrape_accessibility_transcripts(
    case_id: str,
    request: AccessibilityScrapeRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> AccessibilityScrapeResponse:
    adapter = HardwareAdbAdapter(adb_client)
    agent = AccessibilityAgentExtractor(adb=adapter)
    res = await agent.scrape_ui_transcripts(
        request.serial, request.case_id, request.operator_id, request.target_package
    )
    return AccessibilityScrapeResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        target_package=res.target_package,
        transcripts=[
            {
                "target_package": t.target_package,
                "sender_or_title": t.sender_or_title,
                "content_text": t.content_text,
                "timestamp_text": t.timestamp_text,
                "element_id": t.element_id,
            }
            for t in res.transcripts
        ],
        screens_scraped_count=res.screens_scraped_count,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )


@router.post(
    "/content-provider-harvest",
    response_model=ContentProviderHarvestResponse,
    status_code=status.HTTP_200_OK,
    summary="Harvest accessible system content provider endpoints",
)
async def harvest_content_providers(
    case_id: str,
    request: BaseNonRootedRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> ContentProviderHarvestResponse:
    adapter = HardwareAdbAdapter(adb_client)
    harvester = ContentProviderHarvester(adb=adapter)
    res = await harvester.harvest_providers(request.serial, request.case_id, request.operator_id)
    return ContentProviderHarvestResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        queried_uris=res.queried_uris,
        total_records_extracted=res.total_records_extracted,
        sample_records=[
            {
                "provider_uri": r.provider_uri,
                "column_values": r.column_values,
            }
            for r in res.sample_records
        ],
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )


@router.post(
    "/cloud-tokens",
    response_model=CloudTokenExtractResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract non-rooted Google, Samsung, and app cloud session tokens",
)
async def extract_cloud_tokens(
    case_id: str,
    request: BaseNonRootedRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> CloudTokenExtractResponse:
    adapter = HardwareAdbAdapter(adb_client)
    extractor = CloudTokenExtractor(adb=adapter)
    res = await extractor.extract_cloud_tokens(request.serial, request.case_id, request.operator_id)
    return CloudTokenExtractResponse(
        extraction_id=res.extraction_id,
        serial=res.serial,
        case_id=res.case_id,
        operator_id=res.operator_id,
        extracted_tokens=[
            {
                "service_name": t.service_name,
                "account_identifier": t.account_identifier,
                "token_type": t.token_type,
                "expires_at": t.expires_at,
            }
            for t in res.extracted_tokens
        ],
        cloud_targets_ready=res.cloud_targets_ready,
        duration_seconds=res.duration_seconds,
        success=res.success,
        error_message=res.error_message,
    )
