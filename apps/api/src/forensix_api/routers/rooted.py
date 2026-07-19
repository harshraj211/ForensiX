"""Explicitly acknowledged rooted-device capability endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from forensix_api.dependencies import (
    get_adb_client,
    get_authenticated_session,
    get_database,
    require_device_operator,
)
from forensix_api.schemas import RootAccessProbeRequest, RootAccessProbeResponse
from forensix_forensic.adb import AdbClient
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database
from forensix_server.rooted import RootedDeviceService

router = APIRouter(
    prefix="/api/v1/cases/{case_id}/devices/{device_id}/root-probes",
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
