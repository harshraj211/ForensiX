"""ForensiX local API composition root."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from forensix_api import __version__
from forensix_api.errors import (
    ApiSecurityError,
    adb_error_handler,
    case_error_handler,
    security_error_handler,
)
from forensix_api.middleware import request_id_middleware
from forensix_api.routers import acquisitions, auth, cases, custody, devices, health
from forensix_forensic.adb import AdbClient, AdbError
from forensix_server.acquisitions import AcquisitionRecoveryService
from forensix_server.auth import AuthService
from forensix_server.cases import CaseError
from forensix_server.config import Settings
from forensix_server.db import Database
from forensix_server.jobs import JobService


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
    auth_service = AuthService(effective_settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if effective_settings.environment == "test":
            database.initialize()
        else:
            database.migrate()
        with database.session() as session:
            auth_service.ensure_roles(session)
            JobService().recover_after_restart(session)
        AcquisitionRecoveryService().recover_after_restart(database)
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
    app.state.auth_service = auth_service
    app.state.adb_client = adb_client
    app.middleware("http")(request_id_middleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(effective_settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["DELETE", "GET", "PATCH", "POST"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
    )
    app.add_exception_handler(AdbError, adb_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ApiSecurityError, security_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(CaseError, case_error_handler)  # type: ignore[arg-type]
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(cases.router)
    app.include_router(custody.router)
    app.include_router(acquisitions.router)
    app.include_router(devices.router)
    return app


app = create_app()
