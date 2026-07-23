"""Administrator-controlled, synthetic known-answer validation endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from forensix_api.dependencies import (
    get_authenticated_session,
    get_settings,
    require_csrf_session,
)
from forensix_api.errors import ApiSecurityError
from forensix_server.auth import AuthenticatedSession, Permission
from forensix_server.config import Settings
from forensix_server.validation import (
    EvidenceTwinValidationIntegrityError,
    SealedEvidenceTwinValidationReport,
    load_latest_evidence_twin_validation,
    run_and_store_evidence_twin_validation,
)

router = APIRouter(prefix="/api/v1/validation", tags=["validation"])


@router.get(
    "/evidence-twin/latest",
    response_model=SealedEvidenceTwinValidationReport | None,
)
def latest_evidence_twin_validation(
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SealedEvidenceTwinValidationReport | None:
    _require_validation_access(authenticated)
    try:
        return load_latest_evidence_twin_validation(settings.resolved_data_dir)
    except EvidenceTwinValidationIntegrityError as error:
        raise ApiSecurityError(
            status.HTTP_409_CONFLICT,
            "VALIDATION_REPORT_INTEGRITY_FAILED",
            str(error),
        ) from error


@router.post(
    "/evidence-twin/runs",
    response_model=SealedEvidenceTwinValidationReport,
    status_code=status.HTTP_201_CREATED,
)
def run_evidence_twin_known_answer(
    authenticated: Annotated[AuthenticatedSession, Depends(require_csrf_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SealedEvidenceTwinValidationReport:
    _require_validation_access(authenticated)
    return run_and_store_evidence_twin_validation(settings.resolved_data_dir)


def _require_validation_access(authenticated: AuthenticatedSession) -> None:
    if not authenticated.principal.can(Permission.SETTINGS_MANAGE):
        raise ApiSecurityError(
            status.HTTP_403_FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an administrator can run or inspect workstation validation.",
        )
