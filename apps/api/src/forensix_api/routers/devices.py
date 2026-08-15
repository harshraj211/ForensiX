import asyncio
import json
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response, status

from forensix_api.dependencies import (
    get_adb_client,
    get_authenticated_session,
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
    LockedDeviceAssessmentRequest,
    LockedDeviceAssessmentResponse,
    LockedDeviceResearchProfileResponse,
    ProviderCollectionRequest,
    ProviderCollectionResponse,
    ScrcpyLaunchRequest,
    ScrcpyLaunchResponse,
    ScreenRecordingSessionResponse,
    ScreenRecordingStartRequest,
    ScreenRecordingStopRequest,
    WebsiteLivePreviewRequest,
    WebsiteLivePreviewResponse,
)
from forensix_forensic.adb import (
    AdbClient,
    ContentProviderAccessStatus,
    ContentProviderProfile,
)
from forensix_forensic.capabilities import (
    LOCKED_DEVICE_RESEARCH_PROFILES,
    DeviceCapabilityAssessor,
    assess_locked_device,
)
from forensix_server.auth import AuthenticatedSession, Permission
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError
from forensix_server.config import Settings
from forensix_server.db import (
    CaseEventRecord,
    Database,
    DeviceCapabilityRun,
    DeviceDetectionRun,
)
from forensix_server.evidence_twin import EvidenceTwinService
from forensix_server.screen_recordings import ScreenRecordingService

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
    "/locked-device/assess",
    response_model=LockedDeviceAssessmentResponse,
    summary="Classify a locked Android device without attempting its passcode",
)
def assess_locked_android_device(
    request: LockedDeviceAssessmentRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    database: Annotated[Database, Depends(get_database)],
) -> LockedDeviceAssessmentResponse:
    with database.session() as session:
        CaseDeviceService().ensure_operable(session, authenticated.principal, request.case_id)
        readiness = assess_locked_device(
            android_api=request.android_api,
            android_release=request.android_release,
            manufacturer=request.manufacturer,
            model=request.model,
            chipset_family=request.chipset_family,
            chipset_model=request.chipset_model,
            encryption_type=request.encryption_type,
            security_patch=request.security_patch,
            credential_known=request.credential_known,
        )
        session.add(
            CaseEventRecord(
                case_id=request.case_id,
                actor_id=authenticated.principal.user_id,
                event_type="locked_device_assessed",
                safe_detail=(
                    f"android_api={request.android_api};chipset={request.chipset_family};"
                    f"mode={readiness.operating_mode};status={readiness.support_status};"
                    "passcode_attempted=false"
                ),
            )
        )
    return LockedDeviceAssessmentResponse(
        case_id=request.case_id,
        assessed_at=datetime.now(UTC),
        readiness=readiness,
    )


@router.get(
    "/locked-device/research-profiles",
    response_model=list[LockedDeviceResearchProfileResponse],
    summary="List non-operational locked-device research coverage",
)
def list_locked_device_research_profiles(
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
) -> list[LockedDeviceResearchProfileResponse]:
    del authenticated
    return [
        LockedDeviceResearchProfileResponse.model_validate(profile, from_attributes=True)
        for profile in LOCKED_DEVICE_RESEARCH_PROFILES
    ]


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
    profile = ContentProviderProfile(request.profile) if request.profile != "device_info" else None
    with database.session() as session:
        device = CaseDeviceService().get_device(
            session,
            authenticated.principal,
            request.case_id,
            request.case_device_id,
        )
        CaseDeviceService().ensure_operable(session, authenticated.principal, request.case_id)
        if sha256(request.serial.encode("utf-8")).hexdigest() != device.serial_hash:
            raise CaseInvalidStateError(
                "The connected Android serial does not match the case-linked device."
            )

    if profile is None:
        properties = await adb_client.get_properties(request.serial)
        allowlist = (
            "ro.product.manufacturer",
            "ro.product.model",
            "ro.product.device",
            "ro.build.version.release",
            "ro.build.version.sdk",
            "ro.build.version.security_patch",
            "ro.build.fingerprint",
            "ro.boot.hardware",
            "ro.boot.serialno",
        )
        records = [{"_id": "device-info", **{key: properties.get(key) for key in allowlist}}]
        discovered_count = 1
        truncated = False
        max_records = 1
    else:
        probe = await adb_client.probe_content_provider(request.serial, profile)
        if probe.status is not ContentProviderAccessStatus.AVAILABLE:
            raise CaseInvalidStateError(
                f"Android did not permit {profile.value} provider access: {probe.reason_code}."
            )
        result = await adb_client.query_content_provider(request.serial, profile)
        records = [record.values for record in result.records]
        discovered_count = result.discovered_count
        truncated = result.truncated
        max_records = result.max_records

    source = None
    if request.seal_selected:
        requested_ids = set(request.selected_record_ids)
        if not requested_ids:
            raise CaseInvalidStateError("Select at least one record before acquisition.")
        if len(requested_ids) != len(request.selected_record_ids) or any(
            not record_id or len(record_id) > 128 for record_id in requested_ids
        ):
            raise CaseInvalidStateError("Selected record identifiers are invalid or duplicated.")
        available_by_id = {
            str(record.get("_id")): record for record in records if record.get("_id") is not None
        }
        if not requested_ids.issubset(available_by_id):
            raise CaseInvalidStateError(
                "The selected records no longer match the current device preview; preview again."
            )
        selected = [available_by_id[record_id] for record_id in request.selected_record_ids]
        payload = json.dumps(
            {
                "schema_version": "1.0.0",
                "profile": request.profile,
                "device_id": request.case_device_id,
                "record_count": len(selected),
                "records": selected,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        source = EvidenceTwinService().seal_logical_stream(
            database,
            authenticated.principal,
            request.case_id,
            request.case_device_id,
            BytesIO(payload),
            source_name=f"android-{request.profile}.json",
            display_name=f"Selected Android {request.profile.replace('_', ' ')}",
            declared_size_bytes=len(payload),
            operation=f"adb_logical_{request.profile}_selected",
            limitations=(
                "Only analyst-selected rows from the fixed logical projection are included.",
                "ADB is not a hardware write blocker and Android may record transport activity.",
                "This selective logical artifact is not a full filesystem acquisition.",
            ),
        )
        records = selected
    with database.session() as session:
        session.add(
            CaseEventRecord(
                case_id=request.case_id,
                actor_id=authenticated.principal.user_id,
                event_type=(
                    "provider_records_acquired"
                    if request.seal_selected
                    else "provider_records_previewed"
                ),
                safe_detail=(
                    f"device_id={request.case_device_id};profile={request.profile};"
                    f"record_count={len(records)};truncated={truncated};"
                    f"sealed={request.seal_selected}"
                ),
            )
        )
    return ProviderCollectionResponse(
        case_id=request.case_id,
        case_device_id=request.case_device_id,
        profile=request.profile,
        records=records,
        discovered_count=discovered_count,
        truncated=truncated,
        max_records=max_records,
        limitation=(
            "Selected records are sealed as a hashed logical evidence source."
            if source is not None
            else "This is an audit-recorded live preview; select rows to seal them as evidence."
        ),
        evidence_source_id=source.id if source is not None else None,
        evidence_sha256=source.sha256 if source is not None else None,
        evidence_storage_key=source.sealed_storage_key if source is not None else None,
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
    "/live-screen/preview/start",
    response_model=WebsiteLivePreviewResponse,
    status_code=status.HTTP_201_CREATED,
)
def start_website_live_preview(
    request: WebsiteLivePreviewRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    database: Annotated[Database, Depends(get_database)],
) -> WebsiteLivePreviewResponse:
    _validate_case_device_serial(
        database,
        authenticated,
        request.case_id,
        request.case_device_id,
        request.serial,
    )
    with database.session() as session:
        session.add(
            CaseEventRecord(
                case_id=request.case_id,
                actor_id=authenticated.principal.user_id,
                event_type="website_live_preview_started",
                safe_detail=f"device_id={request.case_device_id};transport=adb_screencap_polling",
            )
        )
    return WebsiteLivePreviewResponse(
        case_id=request.case_id,
        case_device_id=request.case_device_id,
        status="started",
        limitation=(
            "Website preview frames are temporary and are not evidence until the operator "
            "explicitly seals a screenshot."
        ),
    )


@router.post(
    "/live-screen/preview/stop",
    response_model=WebsiteLivePreviewResponse,
)
def stop_website_live_preview(
    request: WebsiteLivePreviewRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    database: Annotated[Database, Depends(get_database)],
) -> WebsiteLivePreviewResponse:
    _validate_case_device_serial(
        database,
        authenticated,
        request.case_id,
        request.case_device_id,
        request.serial,
    )
    with database.session() as session:
        session.add(
            CaseEventRecord(
                case_id=request.case_id,
                actor_id=authenticated.principal.user_id,
                event_type="website_live_preview_stopped",
                safe_detail=f"device_id={request.case_device_id};transport=adb_screencap_polling",
            )
        )
    return WebsiteLivePreviewResponse(
        case_id=request.case_id,
        case_device_id=request.case_device_id,
        status="stopped",
        limitation="No preview process remains active on the ForensiX server.",
    )


@router.get("/live-screen/preview/frame", response_class=Response)
async def get_website_live_preview_frame(
    case_id: Annotated[str, Query(min_length=36, max_length=36)],
    case_device_id: Annotated[str, Query(min_length=36, max_length=36)],
    serial: Annotated[str, Query(min_length=1, max_length=255)],
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    database: Annotated[Database, Depends(get_database)],
) -> Response:
    if not authenticated.principal.can(Permission.DEVICES_OPERATE):
        raise CaseAccessDeniedError("The current user cannot operate Android devices.")
    _validate_case_device_serial(database, authenticated, case_id, case_device_id, serial)
    temp_root = database.data_dir / "tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="live-frame-", dir=temp_root) as temporary:
        frame_path = Path(temporary) / "frame.png"
        await adb_client.capture_screenshot(serial, frame_path)
        frame = frame_path.read_bytes()
    return Response(
        content=frame,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store, private",
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
            "X-ForensiX-Ephemeral-Preview": "true",
        },
    )


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
        CaseDeviceService().ensure_operable(session, authenticated.principal, request.case_id)
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


@router.get(
    "/live-screen/recordings",
    response_model=list[ScreenRecordingSessionResponse],
)
def list_screen_recordings(
    case_id: Annotated[str, Query(min_length=36, max_length=36)],
    case_device_id: Annotated[str, Query(min_length=36, max_length=36)],
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    database: Annotated[Database, Depends(get_database)],
) -> list[ScreenRecordingSessionResponse]:
    records = ScreenRecordingService().list(
        database,
        authenticated.principal,
        case_id,
        case_device_id,
    )
    return [ScreenRecordingSessionResponse.model_validate(record) for record in records]


@router.post(
    "/live-screen/recordings",
    response_model=ScreenRecordingSessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def start_screen_recording(
    request: ScreenRecordingStartRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScreenRecordingSessionResponse:
    record = await asyncio.to_thread(
        ScreenRecordingService().start,
        database,
        authenticated.principal,
        settings.scrcpy_controller(),
        request.case_id,
        request.case_device_id,
        request.serial,
    )
    return ScreenRecordingSessionResponse.model_validate(record)


@router.post(
    "/live-screen/recordings/{recording_id}/stop",
    response_model=ScreenRecordingSessionResponse,
)
async def stop_screen_recording(
    recording_id: str,
    request: ScreenRecordingStopRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(require_device_operator)],
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScreenRecordingSessionResponse:
    record = await asyncio.to_thread(
        ScreenRecordingService().stop_and_seal,
        database,
        authenticated.principal,
        settings.scrcpy_controller(),
        recording_id,
        request.case_id,
        request.case_device_id,
        request.serial,
    )
    return ScreenRecordingSessionResponse.model_validate(record)


def _validate_case_device_serial(
    database: Database,
    authenticated: AuthenticatedSession,
    case_id: str,
    case_device_id: str,
    serial: str,
) -> None:
    with database.session() as session:
        device = CaseDeviceService().get_device(
            session, authenticated.principal, case_id, case_device_id
        )
        CaseDeviceService().ensure_operable(session, authenticated.principal, case_id)
        if sha256(serial.encode("utf-8")).hexdigest() != device.serial_hash:
            raise CaseInvalidStateError(
                "The connected Android serial does not match the case-linked device."
            )
