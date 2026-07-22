import asyncio
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from forensix_api.dependencies import (
    get_adb_client,
    get_database,
    get_settings,
    require_device_operator,
)
from forensix_api.schemas import (
    AdbInfoResponse,
    ApiErrorResponse,
    DeviceAssessmentRequest,
    DeviceCapabilityAssessmentResponse,
    DeviceDetectionResponse,
    DeviceTransportResponse,
    EvidenceSourceResponse,
    ProviderCollectionRequest,
    ProviderCollectionResponse,
    ScrcpyLaunchRequest,
    ScrcpyLaunchResponse,
)
from forensix_forensic.adb import (
    AdbClient,
    ContentProviderAccessStatus,
    ContentProviderProfile,
)
from forensix_forensic.capabilities import DeviceCapabilityAssessor
from forensix_server.auth import AuthenticatedSession
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseInvalidStateError
from forensix_server.config import Settings
from forensix_server.db import (
    CaseEventRecord,
    Database,
    DeviceCapabilityRun,
    DeviceDetectionRun,
)
from forensix_server.evidence_twin import EvidenceTwinService

from .evidence_sources import source_response

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


@router.post(
    "/providers/collect",
    response_model=ProviderCollectionResponse,
    responses={409: {"model": ApiErrorResponse}},
)
async def collect_provider_records(
    request: ProviderCollectionRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
) -> ProviderCollectionResponse:
    profile = ContentProviderProfile(request.profile)
    with database.session() as session:
        device = CaseDeviceService().get_device(
            session,
            authenticated.principal,
            request.case_id,
            request.case_device_id,
        )
        CaseDeviceService().ensure_operable(
            session, authenticated.principal, request.case_id
        )
        if sha256(request.serial.encode("utf-8")).hexdigest() != device.serial_hash:
            raise CaseInvalidStateError(
                "The connected Android serial does not match the case-linked device."
            )

    probe = await adb_client.probe_content_provider(request.serial, profile)
    if probe.status is not ContentProviderAccessStatus.AVAILABLE:
        raise CaseInvalidStateError(
            f"Android did not permit {profile.value} provider access: {probe.reason_code}."
        )
    result = await adb_client.query_content_provider(request.serial, profile)
    with database.session() as session:
        session.add(
            CaseEventRecord(
                case_id=request.case_id,
                actor_id=authenticated.principal.user_id,
                event_type="provider_records_collected",
                safe_detail=(
                    f"device_id={request.case_device_id};profile={profile.value};"
                    f"record_count={len(result.records)};truncated={result.truncated}"
                ),
            )
        )
    return ProviderCollectionResponse(
        case_id=request.case_id,
        case_device_id=request.case_device_id,
        profile=request.profile,
        records=[record.values for record in result.records],
        discovered_count=result.discovered_count,
        truncated=result.truncated,
        max_records=result.max_records,
        limitation=(
            "This is a live logical provider preview. It is audit-recorded but is not yet a "
            "sealed evidence source; export or rooted acquisition is required for offline parsing."
        ),
    )


@router.post(
    "/{case_id}/case-devices/{device_id}/screenshots",
    response_model=EvidenceSourceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def capture_device_screenshot(
    case_id: str,
    device_id: str,
    serial: Annotated[str, Query(min_length=1, max_length=255)],
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
) -> EvidenceSourceResponse:
    with database.session() as session:
        device = CaseDeviceService().get_device(
            session, authenticated.principal, case_id, device_id
        )
        CaseDeviceService().ensure_operable(session, authenticated.principal, case_id)
        if sha256(serial.encode("utf-8")).hexdigest() != device.serial_hash:
            raise CaseInvalidStateError(
                "The connected Android serial does not match the case-linked device."
            )

    temp_root = database.data_dir / "tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="screenshot-", dir=temp_root) as temporary:
        screenshot_path = Path(temporary) / "screen.png"
        capture = await adb_client.capture_screenshot(serial, screenshot_path)
        with screenshot_path.open("rb") as stream:
            source = EvidenceTwinService().seal_logical_stream(
                database,
                authenticated.principal,
                case_id,
                device_id,
                stream,
                source_name="android-screen.png",
                display_name="Android screen capture",
                declared_size_bytes=capture.size_bytes,
                operation="adb_exec_out_screencap_png",
                limitations=(
                    "The image represents the displayed screen at capture time only.",
                    (
                        "ADB is not hardware write blocking and the device may record transport "
                        "activity."
                    ),
                    "No screenshot file was intentionally created on the Android device.",
                ),
            )
    return source_response(source)


@router.post(
    "/live-screen/launch",
    response_model=ScrcpyLaunchResponse,
    status_code=status.HTTP_201_CREATED,
)
async def launch_live_screen(
    request: ScrcpyLaunchRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScrcpyLaunchResponse:
    with database.session() as session:
        device = CaseDeviceService().get_device(
            session,
            authenticated.principal,
            request.case_id,
            request.case_device_id,
        )
        CaseDeviceService().ensure_operable(
            session, authenticated.principal, request.case_id
        )
        if sha256(request.serial.encode("utf-8")).hexdigest() != device.serial_hash:
            raise CaseInvalidStateError(
                "The connected Android serial does not match the case-linked device."
            )
    controller = settings.scrcpy_controller()
    diagnostic = await asyncio.to_thread(controller.diagnose)
    if not diagnostic.available:
        raise CaseInvalidStateError(
            "scrcpy is not ready. Configure the official executable and review diagnostics."
        )
    result = await asyncio.to_thread(
        controller.launch, request.serial, control=request.mode == "control"
    )
    with database.session() as session:
        session.add(
            CaseEventRecord(
                case_id=request.case_id,
                actor_id=authenticated.principal.user_id,
                event_type="live_screen_launched",
                safe_detail=(
                    f"device_id={request.case_device_id};mode={result.mode};"
                    f"scrcpy_version={result.version};process_id={result.process_id}"
                ),
            )
        )
    return ScrcpyLaunchResponse.model_validate(result, from_attributes=True)
