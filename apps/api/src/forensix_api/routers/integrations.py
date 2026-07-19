"""Authenticated diagnostics for optional external forensic integrations."""

from typing import Annotated

from fastapi import APIRouter, Depends

from forensix_api.dependencies import get_authenticated_session, get_settings
from forensix_api.schemas import (
    AleappDiagnosticResponse,
    PhysicalAcquisitionDiagnosticResponse,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.evidence_twin import AleappEvidenceService

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("/aleapp", response_model=AleappDiagnosticResponse)
def aleapp_diagnostic(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AleappDiagnosticResponse:
    del authenticated
    return AleappDiagnosticResponse.model_validate(
        AleappEvidenceService().diagnose(settings.aleapp_runner()), from_attributes=True
    )


@router.get(
    "/physical-acquisition", response_model=PhysicalAcquisitionDiagnosticResponse
)
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
