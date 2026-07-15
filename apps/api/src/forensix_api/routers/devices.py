from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, status

from forensix_api.dependencies import get_adb_client, get_database
from forensix_api.schemas import (
    AdbInfoResponse,
    ApiErrorResponse,
    DeviceDetectionResponse,
    DeviceTransportResponse,
)
from forensix_forensic.adb import AdbClient
from forensix_server.db import Database, DeviceDetectionRun

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


@router.post(
    "/detect",
    response_model=DeviceDetectionResponse,
    status_code=status.HTTP_200_OK,
    responses={
        502: {"model": ApiErrorResponse},
        503: {"model": ApiErrorResponse},
        504: {"model": ApiErrorResponse},
    },
)
async def detect_devices(
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
) -> DeviceDetectionResponse:
    observed_at = datetime.now(UTC)
    adb_info = await adb_client.server_info()
    transports = await adb_client.list_transports()
    result: Literal["no_devices", "single_device", "multiple_devices"] = (
        "no_devices"
        if not transports
        else "single_device"
        if len(transports) == 1
        else "multiple_devices"
    )
    detection = DeviceDetectionRun(
        observed_at=observed_at,
        adb_version=adb_info.version,
        device_count=len(transports),
        result=result,
    )
    with database.session() as session:
        session.add(detection)
        session.flush()
        detection_id = detection.id
    return DeviceDetectionResponse(
        detection_id=detection_id,
        observed_at=observed_at,
        result=result,
        adb=AdbInfoResponse(
            version=adb_info.version,
            executable_path=adb_info.executable_path,
        ),
        devices=[DeviceTransportResponse.model_validate(item) for item in transports],
    )
