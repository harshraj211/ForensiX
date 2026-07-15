"""ForensiX local API composition root."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from forensix_api import __version__
from forensix_api.errors import adb_error_handler
from forensix_api.middleware import request_id_middleware
from forensix_api.routers import devices, health
from forensix_forensic.adb import AdbClient, AdbError
from forensix_server.config import Settings
from forensix_server.db import Database


def create_app(
    settings: Settings | None = None,
    *,
    adb_client: AdbClient | None = None,
) -> FastAPI:
    effective_settings = settings or Settings()
    database = Database(
        effective_settings.resolved_database_url,
        effective_settings.resolved_data_dir,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        database.initialize()
        yield
        database.dispose()

    app = FastAPI(
        title="ForensiX Local API",
        version=__version__,
        description=(
            "Controlled logical Android triage API. No arbitrary ADB shell endpoint exists."
        ),
        lifespan=lifespan,
    )
    app.state.settings = effective_settings
    app.state.database = database
    app.state.adb_client = adb_client
    app.middleware("http")(request_id_middleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(effective_settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Request-ID"],
    )
    app.add_exception_handler(AdbError, adb_error_handler)  # type: ignore[arg-type]
    app.include_router(health.router)
    app.include_router(devices.router)
    return app


app = create_app()
