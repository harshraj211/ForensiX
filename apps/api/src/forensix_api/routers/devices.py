from datetime import UTC, datetime
from hashlib import sha256
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from forensix_api.dependencies import get_adb_client, get_database, require_device_operator
from forensix_api.schemas import (
    AdbInfoResponse,
    ApiErrorResponse,
    DeviceAssessmentRequest,
    DeviceCapabilityAssessmentResponse,
    DeviceDetectionResponse,
    DeviceTransportResponse,
)
from forensix_forensic.adb import AdbClient
from forensix_forensic.capabilities import DeviceCapabilityAssessor
from forensix_server.auth import AuthenticatedSession
from forensix_server.case_devices import CaseDeviceService
from forensix_server.db import Database, DeviceCapabilityRun, DeviceDetectionRun

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
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
    case_id: Annotated[str | None, Query(min_length=36, max_length=36)] = None,
) -> DeviceDetectionResponse:
    if case_id is not None:
        with database.session() as session:
            CaseDeviceService().ensure_operable(session, authenticated.principal, case_id)
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
    with database.session() as session:
        if case_id is None:
            detection = DeviceDetectionRun(
                observed_at=observed_at,
                adb_version=adb_info.version,
                device_count=len(transports),
                result=result,
            )
            session.add(detection)
            session.flush()
            detection_id = detection.id
        else:
            case_detection = CaseDeviceService().record_detection(
                session,
                authenticated.principal,
                case_id,
                observed_at=observed_at,
                adb_version=adb_info.version,
                device_count=len(transports),
                result=result,
            )
            detection_id = case_detection.id
    return DeviceDetectionResponse(
        detection_id=detection_id,
        case_id=case_id,
        observed_at=observed_at,
        result=result,
        adb=AdbInfoResponse(
            version=adb_info.version,
            executable_path=adb_info.executable_path,
        ),
        devices=[DeviceTransportResponse.model_validate(item) for item in transports],
    )


@router.post(
    "/assess",
    response_model=DeviceCapabilityAssessmentResponse,
    responses={
        404: {"model": ApiErrorResponse},
        409: {"model": ApiErrorResponse},
        502: {"model": ApiErrorResponse},
        503: {"model": ApiErrorResponse},
        504: {"model": ApiErrorResponse},
    },
)
async def assess_device(
    request: DeviceAssessmentRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
) -> DeviceCapabilityAssessmentResponse:
    if request.case_id is not None:
        with database.session() as session:
            CaseDeviceService().ensure_operable(session, authenticated.principal, request.case_id)
    snapshot = await DeviceCapabilityAssessor(adb_client).assess(request.serial)
    with database.session() as session:
        if request.case_id is None:
            capability_run = DeviceCapabilityRun(
                assessed_at=snapshot.assessed_at,
                serial_hash=sha256(snapshot.serial.encode("utf-8")).hexdigest(),
                manufacturer=snapshot.manufacturer,
                model=snapshot.model,
                android_version=snapshot.android_version,
                sdk_level=snapshot.sdk_level,
                snapshot_json=snapshot.model_dump_json(exclude={"serial"}),
            )
            session.add(capability_run)
            session.flush()
            assessment_id = capability_run.id
            case_device_id = None
        else:
            device, assessment = CaseDeviceService().register_assessment(
                session,
                authenticated.principal,
                request.case_id,
                snapshot,
            )
            assessment_id = assessment.id
            case_device_id = device.id
    return DeviceCapabilityAssessmentResponse(
        assessment_id=assessment_id,
        case_id=request.case_id,
        case_device_id=case_device_id,
        **snapshot.model_dump(),
    )
