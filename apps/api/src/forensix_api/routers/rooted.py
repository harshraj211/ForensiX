"""Explicitly acknowledged rooted-device capability endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from forensix_api.dependencies import (
    get_adb_client,
    get_authenticated_session,
    get_database,
    get_settings,
    require_device_operator,
)
from forensix_api.routers.evidence_sources import source_response
from forensix_api.schemas import (
    EvidenceSourceResponse,
    PhysicalBlockCaptureRequest,
    PhysicalBlockProbeRequest,
    PhysicalBlockProbeResponse,
    RootAccessProbeRequest,
    RootAccessProbeResponse,
    RootedCaptureRequest,
)
from forensix_forensic.adb import (
    AdbClient,
    PhysicalBlockProfile,
    RootedCollectionProfile,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.db import Database
from forensix_server.rooted import RootedDeviceService

router = APIRouter(
    prefix="/api/v1/cases/{case_id}/devices/{device_id}/root-probes",
    tags=["rooted-device"],
)

capture_router = APIRouter(
    prefix="/api/v1/cases/{case_id}/devices/{device_id}/rooted-captures",
    tags=["rooted-device"],
)

physical_probe_router = APIRouter(
    prefix="/api/v1/cases/{case_id}/devices/{device_id}/physical-block-probes",
    tags=["rooted-device"],
)

physical_capture_router = APIRouter(
    prefix="/api/v1/cases/{case_id}/devices/{device_id}/physical-captures",
    tags=["rooted-device"],
)


@router.post("", response_model=RootAccessProbeResponse, status_code=status.HTTP_201_CREATED)
async def probe_root_access(
    case_id: str,
    device_id: str,
    request: RootAccessProbeRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
) -> RootAccessProbeResponse:
    record = await RootedDeviceService().probe_access(
        database,
        adb_client,
        authenticated.principal,
        case_id,
        device_id,
        serial=request.serial,
    )
    return RootAccessProbeResponse.model_validate(record)


@router.get("", response_model=list[RootAccessProbeResponse])
def list_root_access_probes(
    case_id: str,
    device_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> list[RootAccessProbeResponse]:
    records = RootedDeviceService().list_probes(
        database, authenticated.principal, case_id, device_id
    )
    return [RootAccessProbeResponse.model_validate(item) for item in records]


@capture_router.post("", response_model=EvidenceSourceResponse, status_code=status.HTTP_201_CREATED)
async def capture_rooted_provider_bundle(
    case_id: str,
    device_id: str,
    request: RootedCaptureRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceSourceResponse:
    record = await RootedDeviceService().capture_provider_bundle(
        database,
        adb_client,
        authenticated.principal,
        case_id,
        device_id,
        serial=request.serial,
        probe_id=request.root_probe_id,
        profile=RootedCollectionProfile(request.profile),
        side_effects_acknowledged=request.side_effects_acknowledged,
    )
    return source_response(record)


@physical_probe_router.post(
    "", response_model=PhysicalBlockProbeResponse, status_code=status.HTTP_201_CREATED
)
async def probe_physical_block(
    case_id: str,
    device_id: str,
    request: PhysicalBlockProbeRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> PhysicalBlockProbeResponse:
    record = await RootedDeviceService().probe_physical_block(
        database,
        adb_client,
        settings,
        authenticated.principal,
        case_id,
        device_id,
        serial=request.serial,
        root_probe_id=request.root_probe_id,
        profile=PhysicalBlockProfile(request.profile),
        risk_acknowledged=request.risk_acknowledged,
    )
    return PhysicalBlockProbeResponse.model_validate(record)


@physical_capture_router.post(
    "", response_model=EvidenceSourceResponse, status_code=status.HTTP_201_CREATED
)
async def capture_physical_block(
    case_id: str,
    device_id: str,
    request: PhysicalBlockCaptureRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> EvidenceSourceResponse:
    record = await RootedDeviceService().capture_physical_block(
        database,
        adb_client,
        settings,
        authenticated.principal,
        case_id,
        device_id,
        serial=request.serial,
        physical_probe_id=request.physical_probe_id,
        acquisition_acknowledged=request.acquisition_acknowledged,
        encryption_acknowledged=request.encryption_acknowledged,
        non_resumable_acknowledged=request.non_resumable_acknowledged,
    )
    return source_response(record)
