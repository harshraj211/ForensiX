"""Authenticated diagnostics for optional external forensic integrations."""

from typing import Annotated

from fastapi import APIRouter, Depends

from forensix_api.dependencies import get_authenticated_session, get_settings
from forensix_api.schemas import (
    AdbDiagnosticResponse,
    AleappDiagnosticResponse,
    ApplicationArtifactSupportResponse,
    CloudServiceCapabilityResponse,
    PhotoRecDiagnosticResponse,
    PhysicalAcquisitionDiagnosticResponse,
    ScrcpyDiagnosticResponse,
)
from forensix_forensic.adb import diagnose_adb
from forensix_forensic.android_artifacts import application_artifact_support
from forensix_forensic.extractors.cloud import cloud_service_catalog
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.evidence_twin import AleappEvidenceService

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("/adb", response_model=AdbDiagnosticResponse)
async def adb_diagnostic(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AdbDiagnosticResponse:
    del authenticated
    return AdbDiagnosticResponse.model_validate(
        await diagnose_adb(settings.adb_mode, settings.adb_path), from_attributes=True
    )


@router.get("/aleapp", response_model=AleappDiagnosticResponse)
def aleapp_diagnostic(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AleappDiagnosticResponse:
    del authenticated
    return AleappDiagnosticResponse.model_validate(
        AleappEvidenceService().diagnose(settings.aleapp_runner()), from_attributes=True
    )


@router.get("/photorec", response_model=PhotoRecDiagnosticResponse)
def photorec_diagnostic(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> PhotoRecDiagnosticResponse:
    del authenticated
    diagnostic = settings.photorec_controller().diagnose()
    return PhotoRecDiagnosticResponse(
        available=diagnostic.available,
        status=diagnostic.status,
        executable_path=diagnostic.executable_path,
        version=diagnostic.version,
        sha256=diagnostic.sha256,
        guidance=list(diagnostic.guidance),
    )


@router.get("/physical-acquisition", response_model=PhysicalAcquisitionDiagnosticResponse)
def physical_acquisition_diagnostic(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> PhysicalAcquisitionDiagnosticResponse:
    del authenticated
    return PhysicalAcquisitionDiagnosticResponse(
        enabled=settings.enable_experimental_physical_acquisition,
        max_size_bytes=settings.max_physical_acquisition_bytes,
        warning=(
            "Experimental raw userdata acquisition does not bypass device encryption, is not "
            "hardware write blocking, and is not resumable in the current release."
        ),
    )


@router.get("/scrcpy", response_model=ScrcpyDiagnosticResponse)
def scrcpy_diagnostic(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScrcpyDiagnosticResponse:
    del authenticated
    return ScrcpyDiagnosticResponse.model_validate(
        settings.scrcpy_controller().diagnose(), from_attributes=True
    )


@router.get("/application-artifacts", response_model=list[ApplicationArtifactSupportResponse])
def application_artifact_support_matrix(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
) -> list[ApplicationArtifactSupportResponse]:
    del authenticated
    return [
        ApplicationArtifactSupportResponse.model_validate(item, from_attributes=True)
        for item in application_artifact_support()
    ]


@router.get("/cloud-services", response_model=list[CloudServiceCapabilityResponse])
def cloud_service_support_matrix(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
) -> list[CloudServiceCapabilityResponse]:
    del authenticated
    return [
        CloudServiceCapabilityResponse(
            service_id=item.service_id,
            display_name=item.display_name,
            category=item.category,
            depth=item.depth,
            auth_methods=list(item.auth_methods),
            artifact_types=list(item.artifact_types),
            blocker_class=item.blocker_class,
            implementation_note=item.implementation_note,
        )
        for item in cloud_service_catalog()
    ]
