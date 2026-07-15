"""Composition helpers for API dependencies."""

from typing import cast

from fastapi import Request

from forensix_forensic.adb import (
    AdbBinaryResolver,
    AdbClient,
    MockAdbClient,
    MockAdbScenario,
    SubprocessAdbRunner,
    SystemAdbClient,
)
from forensix_server.config import Settings
from forensix_server.db import Database


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def get_adb_client(request: Request) -> AdbClient:
    injected = cast(AdbClient | None, request.app.state.adb_client)
    if injected is not None:
        return injected
    settings: Settings = request.app.state.settings
    if settings.adb_mode == "mock":
        return MockAdbClient(MockAdbScenario(settings.mock_adb_scenario))
    adb_path = AdbBinaryResolver(settings.adb_path).resolve()
    return SystemAdbClient(SubprocessAdbRunner(adb_path))
