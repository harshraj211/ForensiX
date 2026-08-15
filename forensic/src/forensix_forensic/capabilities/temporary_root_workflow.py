"""Temporary-root lifecycle with mandatory cleanup and post-cleanup verification."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar, cast

from forensix_forensic.adb import AdbClient, RootAccessStatus

from .temporary_root import find_temporary_root_profile
from .temporary_root_provider import (
    HashPinnedTemporaryRootProvider,
    TemporaryRootProviderError,
)

T = TypeVar("T")
_UNSET = object()


@dataclass(frozen=True, slots=True)
class TemporaryRootWorkflowResult[T]:
    profile_id: str
    provider_sha256: str
    acquisition_result: T
    cleanup_verified: bool
    kernel_build_id: str | None = None


class TemporaryRootProfileMismatchError(TemporaryRootProviderError):
    """Raised when the live device no longer matches the validated provider profile."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class TemporaryRootWorkflow:
    def __init__(
        self,
        *,
        cleanup_verification_attempts: int = 45,
        cleanup_verification_interval_seconds: float = 2.0,
    ) -> None:
        if cleanup_verification_attempts < 1:
            raise ValueError("Cleanup verification requires at least one attempt.")
        if cleanup_verification_interval_seconds < 0:
            raise ValueError("Cleanup verification interval cannot be negative.")
        self._cleanup_verification_attempts = cleanup_verification_attempts
        self._cleanup_verification_interval_seconds = cleanup_verification_interval_seconds

    async def run(
        self,
        adb_client: AdbClient,
        provider: HashPinnedTemporaryRootProvider,
        serial: str,
        acquire: Callable[[], Awaitable[T]],
    ) -> TemporaryRootWorkflowResult[T]:
        properties = await adb_client.get_properties(serial)
        kernel_build_id = await adb_client.get_kernel_version(serial)
        base_matched = find_temporary_root_profile(properties)
        matched = find_temporary_root_profile(properties, kernel_build_id=kernel_build_id)
        if base_matched is not None and matched is None:
            raise TemporaryRootProfileMismatchError(
                "The connected device kernel does not match the validated provider profile.",
                reason="kernel_build_id",
            )
        if matched is None or matched != provider.profile:
            raise TemporaryRootProfileMismatchError(
                "The connected device does not exactly match the validated provider profile.",
                reason="device_profile",
            )

        activation_attempted = False
        acquisition_result: T | object = _UNSET
        activation = None
        primary_error: BaseException | None = None
        try:
            await asyncio.to_thread(provider.verify)
            activation_attempted = True
            activation = await asyncio.to_thread(provider.activate, serial)
            root_probe = await adb_client.probe_root_access(serial)
            if root_probe.status is not RootAccessStatus.AVAILABLE or root_probe.uid != 0:
                raise TemporaryRootProviderError(
                    "The provider completed but root UID confirmation failed."
                )
            acquisition_result = await acquire()
        except BaseException as error:
            primary_error = error
        finally:
            if activation_attempted:
                cleanup_error: BaseException | None = None
                try:
                    await asyncio.to_thread(provider.cleanup, serial)
                except BaseException as error:
                    cleanup_error = error
                try:
                    await self._verify_cleanup(adb_client, serial)
                except BaseException as verification_error:
                    raise TemporaryRootProviderError(
                        "Temporary-root cleanup or post-cleanup verification failed."
                    ) from verification_error
                if cleanup_error is not None:
                    raise TemporaryRootProviderError(
                        "The provider cleanup command failed, although root is no longer available."
                    ) from cleanup_error

        if primary_error is not None:
            raise primary_error
        if activation is None:
            raise TemporaryRootProviderError("Temporary root was not activated.")
        if acquisition_result is _UNSET:
            raise TemporaryRootProviderError("The temporary-root acquisition did not complete.")
        return TemporaryRootWorkflowResult(
            profile_id=provider.profile.profile_id,
            provider_sha256=activation.executable_sha256,
            acquisition_result=cast(T, acquisition_result),
            cleanup_verified=True,
            kernel_build_id=kernel_build_id,
        )

    async def _verify_cleanup(self, adb_client: AdbClient, serial: str) -> None:
        last_error: Exception | None = None
        for attempt in range(self._cleanup_verification_attempts):
            try:
                probe = await adb_client.probe_root_access(serial)
            except Exception as error:
                last_error = error
            else:
                if not (probe.status is RootAccessStatus.AVAILABLE and probe.uid == 0):
                    return
            if attempt + 1 < self._cleanup_verification_attempts:
                await asyncio.sleep(self._cleanup_verification_interval_seconds)
        if last_error is not None:
            raise TemporaryRootProviderError(
                "The device did not reconnect for post-cleanup root verification."
            ) from last_error
        raise TemporaryRootProviderError(
            "Temporary-root cleanup completed, but root access is still available."
        )
