from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from forensix_api import __version__
from forensix_api.dependencies import get_database
from forensix_api.schemas import HealthResponse
from forensix_server.db import Database

router = APIRouter(tags=["health"])


@router.get("/health/live", response_model=HealthResponse)
async def live() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@router.get("/health/ready", response_model=HealthResponse)
async def ready(
    response: Response,
    database: Annotated[Database, Depends(get_database)],
) -> HealthResponse:
    if not database.ready():
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthResponse(status="not_ready", version=__version__, database="unavailable")
    return HealthResponse(status="ready", version=__version__, database="ready")
