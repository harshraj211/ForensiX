"""Safe API error mapping for controlled ADB and security failures."""

from fastapi import Request
from fastapi.responses import JSONResponse

from forensix_forensic.adb import (
    AdbBinaryNotFoundError,
    AdbCommandError,
    AdbDeviceNotAuthorizedError,
    AdbDeviceNotFoundError,
    AdbError,
    AdbOutputLimitError,
    AdbTimeoutError,
    AdbTransferLimitError,
)
from forensix_server.cases import (
    CaseAccessDeniedError,
    CaseError,
    CaseInvalidStateError,
    CaseMemberError,
    CaseNotFoundError,
    CaseVersionConflictError,
)
from forensix_server.evidence import ArtifactQueryError


class ApiSecurityError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


async def security_error_handler(request: Request, error: ApiSecurityError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={
            "error": {
                "code": error.code,
                "message": str(error),
                "details": {},
                "request_id": request.state.request_id,
            }
        },
        headers={"X-Request-ID": request.state.request_id},
    )


async def case_error_handler(request: Request, error: CaseError) -> JSONResponse:
    status_code = 400
    if isinstance(error, CaseNotFoundError):
        status_code = 404
    elif isinstance(error, CaseAccessDeniedError):
        status_code = 403
    elif isinstance(error, ArtifactQueryError):
        status_code = 422
    elif isinstance(error, (CaseInvalidStateError, CaseVersionConflictError)):
        status_code = 409
    elif isinstance(error, CaseMemberError):
        status_code = 400
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": error.code,
                "message": str(error),
                "details": {},
                "request_id": request.state.request_id,
            }
        },
        headers={"X-Request-ID": request.state.request_id},
    )


async def adb_error_handler(request: Request, error: AdbError) -> JSONResponse:
    status_code = 503
    if isinstance(error, AdbTimeoutError):
        status_code = 504
    elif isinstance(error, AdbTransferLimitError):
        status_code = 413
    elif isinstance(error, AdbDeviceNotFoundError):
        status_code = 404
    elif isinstance(error, AdbDeviceNotAuthorizedError):
        status_code = 409
    elif isinstance(error, (AdbCommandError, AdbOutputLimitError)):
        status_code = 502
    elif isinstance(error, AdbBinaryNotFoundError):
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": error.code,
                "message": str(error),
                "details": {},
                "request_id": request.state.request_id,
            }
        },
        headers={"X-Request-ID": request.state.request_id},
    )
