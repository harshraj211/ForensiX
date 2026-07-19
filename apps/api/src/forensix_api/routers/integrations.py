"""Authenticated diagnostics for optional external forensic integrations."""

from typing import Annotated

from fastapi import APIRouter, Depends

from forensix_api.dependencies import get_authenticated_session, get_settings
from forensix_api.schemas import (
    AdbDiagnosticResponse,
    AleappDiagnosticResponse,
    ApplicationArtifactSupportResponse,
    PhysicalAcquisitionDiagnosticResponse,
)
from forensix_forensic.adb import diagnose_adb
from forensix_forensic.android_artifacts import application_artifact_support
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


@router.get("/application-artifacts", response_model=list[ApplicationArtifactSupportResponse])
def application_artifact_support_matrix(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
) -> list[ApplicationArtifactSupportResponse]:
    del authenticated
    return [
        ApplicationArtifactSupportResponse.model_validate(item, from_attributes=True)
        for item in application_artifact_support()
    ]
