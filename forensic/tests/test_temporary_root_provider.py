from collections.abc import Awaitable, Callable
from hashlib import sha256
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any, cast

import pytest

from forensix_forensic.adb import AdbClient, RootAccessProbe, RootAccessStatus
from forensix_forensic.capabilities import temporary_root_workflow
from forensix_forensic.capabilities.temporary_root import TemporaryRootProfile
from forensix_forensic.capabilities.temporary_root_provider import (
    HashPinnedTemporaryRootProvider,
    TemporaryRootProviderError,
    TemporaryRootProviderPackage,
    TemporaryRootProviderResult,
)
from forensix_forensic.capabilities.temporary_root_workflow import (
    TemporaryRootProfileMismatchError,
    TemporaryRootWorkflow,
)


def _profile() -> TemporaryRootProfile:
    return TemporaryRootProfile(
        profile_id="controlled-profile",
        provider_id="validated-provider",
        manufacturer="Example",
        model="Controlled Device",
        build_fingerprint="example/device/build:10/TEST/1:user/release-keys",
        security_patch="2019-10-01",
        validation_record_sha256="a" * 64,
        kernel_build_id="4.4.0-controlled",
    )


def test_hash_pinned_provider_uses_fixed_shell_free_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"controlled provider fixture")
    digest = sha256(executable.read_bytes()).hexdigest()
    package = TemporaryRootProviderPackage(_profile(), executable, digest)
    provider = HashPinnedTemporaryRootProvider(package, tmp_path)
    observed_command: tuple[str, ...] | None = None

    def fake_run(command: tuple[str, ...], **_: Any) -> CompletedProcess[bytes]:
        nonlocal observed_command
        observed_command = command
        return CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = provider.activate("SERIAL-123")

    assert result.executable_sha256 == digest
    assert observed_command == (
        str(executable.resolve()),
        "activate",
        "--protocol-version",
        "1",
        "--serial",
        "SERIAL-123",
        "--profile",
        "controlled-profile",
    )


def test_hash_pinned_provider_rejects_digest_mismatch(tmp_path: Path) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"unexpected provider")
    package = TemporaryRootProviderPackage(_profile(), executable, "0" * 64)

    with pytest.raises(TemporaryRootProviderError, match="SHA-256 does not match"):
        HashPinnedTemporaryRootProvider(package, tmp_path).verify()


class _FakeAdbClient:
    def __init__(self) -> None:
        self.probe_count = 0
        self._probes = iter(
            (
                _root_probe(RootAccessStatus.AVAILABLE, 0),
                _root_probe(RootAccessStatus.UNAVAILABLE, None),
            )
        )

    async def get_properties(self, serial: str) -> dict[str, str]:
        assert serial == "SERIAL-123"
        return {"ro.build.fingerprint": _profile().build_fingerprint}

    async def get_kernel_version(self, serial: str) -> str:
        assert serial == "SERIAL-123"
        return _profile().kernel_build_id

    async def probe_root_access(self, serial: str) -> RootAccessProbe:
        assert serial == "SERIAL-123"
        self.probe_count += 1
        return next(self._probes)


class _FakeProvider:
    def __init__(self) -> None:
        self.profile = _profile()
        self.operations: list[str] = []

    def verify(self) -> str:
        return "b" * 64

    def activate(self, serial: str) -> TemporaryRootProviderResult:
        self.operations.append(f"activate:{serial}")
        return TemporaryRootProviderResult("activate", "b" * 64, 0)

    def cleanup(self, serial: str) -> TemporaryRootProviderResult:
        self.operations.append(f"cleanup:{serial}")
        return TemporaryRootProviderResult("cleanup", "b" * 64, 0)


@pytest.mark.asyncio
async def test_workflow_activates_acquires_cleans_and_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider()
    monkeypatch.setattr(
        temporary_root_workflow,
        "find_temporary_root_profile",
        lambda _, **__: provider.profile,
    )

    async def acquire() -> str:
        return "sealed-evidence-id"

    result = await TemporaryRootWorkflow().run(
        cast(AdbClient, _FakeAdbClient()),
        cast(HashPinnedTemporaryRootProvider, provider),
        "SERIAL-123",
        acquire,
    )

    assert result.acquisition_result == "sealed-evidence-id"
    assert result.cleanup_verified is True
    assert result.kernel_build_id == "4.4.0-controlled"
    assert provider.operations == ["activate:SERIAL-123", "cleanup:SERIAL-123"]


@pytest.mark.asyncio
async def test_workflow_cleans_up_when_acquisition_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider()
    monkeypatch.setattr(
        temporary_root_workflow,
        "find_temporary_root_profile",
        lambda _, **__: provider.profile,
    )

    async def acquire() -> str:
        raise RuntimeError("controlled acquisition failure")

    adb_client = _FakeAdbClient()
    with pytest.raises(RuntimeError, match="controlled acquisition failure"):
        await TemporaryRootWorkflow().run(
            cast(AdbClient, adb_client),
            cast(HashPinnedTemporaryRootProvider, provider),
            "SERIAL-123",
            cast(Callable[[], Awaitable[str]], acquire),
        )

    assert provider.operations == ["activate:SERIAL-123", "cleanup:SERIAL-123"]
    assert adb_client.probe_count == 2


@pytest.mark.asyncio
async def test_workflow_rejects_kernel_mismatch_before_provider_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider()

    def match_profile(_: dict[str, str], *, kernel_build_id: str | None = None):
        return provider.profile if kernel_build_id is None else None

    monkeypatch.setattr(temporary_root_workflow, "find_temporary_root_profile", match_profile)

    with pytest.raises(TemporaryRootProfileMismatchError) as caught:
        await TemporaryRootWorkflow().run(
            cast(AdbClient, _FakeAdbClient()),
            cast(HashPinnedTemporaryRootProvider, provider),
            "SERIAL-123",
            cast(Callable[[], Awaitable[str]], _unreachable_acquire),
        )

    assert caught.value.reason == "kernel_build_id"
    assert provider.operations == []


async def _unreachable_acquire() -> str:
    raise AssertionError("Acquisition must not run after profile mismatch.")


def _root_probe(status: RootAccessStatus, uid: int | None) -> RootAccessProbe:
    return RootAccessProbe(
        status=status,
        uid=uid,
        identity="uid=0(root)" if uid == 0 else None,
        reason_code="ROOT_UID_CONFIRMED" if uid == 0 else "ROOT_UID_NOT_AVAILABLE",
        potential_side_effect="Controlled test probe.",
    )
