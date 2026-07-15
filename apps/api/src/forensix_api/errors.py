"""Safe API error mapping for controlled ADB failures."""

from fastapi import Request
from fastapi.responses import JSONResponse

from forensix_forensic.adb import (
    AdbBinaryNotFoundError,
    AdbCommandError,
    AdbError,
    AdbOutputLimitError,
    AdbTimeoutError,
)


async def adb_error_handler(request: Request, error: AdbError) -> JSONResponse:
    status_code = 503
    if isinstance(error, AdbTimeoutError):
        status_code = 504
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
