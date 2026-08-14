from __future__ import annotations

import asyncio
from hashlib import sha256
from pathlib import Path

import pytest

from forensix_forensic.adb.models import BackupResult, PulledFileResult
from forensix_forensic.extractors.apk_downgrade import (
    APK_DOWNGRADE_PROFILES,
    ApkDowngradeExtractor,
)


class FakeAdbClient:
    def __init__(self, *, api: int, fail_backup: bool = False) -> None:
        self.api = api
        self.fail_backup = fail_backup
        self.version_dumps = [
            "versionCode=100 minSdk=21 targetSdk=33\nversionName=10.0",
            "versionCode=50 minSdk=21 targetSdk=27\nversionName=5.0",
            "versionCode=100 minSdk=21 targetSdk=33\nversionName=10.0",
        ]
        self.installs: list[tuple[str, ...]] = []

    async def get_properties(self, serial: str) -> dict[str, str]:
        return {
            "ro.build.version.sdk": str(self.api),
            "ro.build.version.release": "5.0" if self.api == 21 else "13",
        }

    async def dump_package(self, serial: str, package_name: str) -> str:
        return self.version_dumps.pop(0)

    async def list_package_apks(self, serial: str, package_name: str) -> tuple[str, ...]:
        return (
            "/data/app/~~token/com.whatsapp-token/base.apk",
            "/data/app/~~token/com.whatsapp-token/split_config.en.apk",
        )

    async def pull_package_apk(
        self, serial: str, remote_path: str, destination: Path
    ) -> PulledFileResult:
        content = f"original:{remote_path}".encode()
        await asyncio.to_thread(destination.write_bytes, content)
        return PulledFileResult(
            root_id="installed_package",
            relative_path=remote_path,
            size_bytes=len(content),
        )

    async def install_package(self, serial: str, apk_path: str) -> bool:
        self.installs.append((apk_path,))
        return True

    async def install_packages(self, serial: str, apk_paths: tuple[str, ...]) -> bool:
        self.installs.append(apk_paths)
        return True

    async def backup_package(
        self, serial: str, package_name: str, destination: Path
    ) -> BackupResult:
        if self.fail_backup:
            raise RuntimeError("simulated backup failure")
        content = b"ANDROID BACKUP\nfixture"
        await asyncio.to_thread(destination.write_bytes, content)
        return BackupResult(
            backup_file_size_bytes=len(content),
            destination_path=str(destination),
            package_name=package_name,
            success=True,
        )


def _staged_apk(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "approved-old.apk"
    path.write_bytes(b"signed downgrade fixture")
    return path, sha256(path.read_bytes()).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize("api", [21, 33])
async def test_downgrade_supports_android_5_through_13_and_restores_splits(
    tmp_path: Path, api: int
) -> None:
    apk_path, apk_hash = _staged_apk(tmp_path)
    adb = FakeAdbClient(api=api)

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=(apk_hash,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is True
    assert result.restored is True
    assert result.android_api == api
    assert result.original_version == "10.0 (100)"
    assert result.downgrade_version == "5.0 (50)"
    assert len(result.preserved_apks) == 2
    assert len(adb.installs) == 2
    assert adb.installs[0] == (str(apk_path.resolve()),)
    assert len(adb.installs[1]) == 2
    journal = await asyncio.to_thread(lambda: next(tmp_path.glob("apk_downgrade_*/recovery.json")))
    journal_text = await asyncio.to_thread(journal.read_text, encoding="utf-8")
    assert '"state": "restored"' in journal_text


@pytest.mark.asyncio
async def test_backup_failure_still_restores_original_package(tmp_path: Path) -> None:
    apk_path, apk_hash = _staged_apk(tmp_path)
    adb = FakeAdbClient(api=33, fail_backup=True)

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=(apk_hash,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is False
    assert result.restored is True
    assert result.error_message == "simulated backup failure"
    assert len(adb.installs) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("api", [20, 34])
async def test_versions_outside_android_5_through_13_are_rejected_before_mutation(
    tmp_path: Path, api: int
) -> None:
    apk_path, apk_hash = _staged_apk(tmp_path)
    adb = FakeAdbClient(api=api)

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=(apk_hash,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is False
    assert result.restored is True
    assert "API 21-33" in (result.error_message or "")
    assert adb.installs == []


@pytest.mark.asyncio
async def test_hash_mismatch_is_rejected_before_original_apks_are_changed(tmp_path: Path) -> None:
    apk_path, _ = _staged_apk(tmp_path)
    adb = FakeAdbClient(api=33)

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=("0" * 64,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is False
    assert "SHA-256 mismatch" in (result.error_message or "")
    assert adb.installs == []


def test_profiles_are_closed_to_known_android_app_packages() -> None:
    assert APK_DOWNGRADE_PROFILES["whatsapp"].package_name == "com.whatsapp"
    assert APK_DOWNGRADE_PROFILES["signal"].package_name == "org.thoughtcrime.securesms"
    assert all(profile.min_api == 21 for profile in APK_DOWNGRADE_PROFILES.values())
    assert all(profile.max_api == 33 for profile in APK_DOWNGRADE_PROFILES.values())
