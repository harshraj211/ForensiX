from __future__ import annotations

import asyncio
from hashlib import sha256
from pathlib import Path

import pytest

from forensix_forensic.adb.models import BackupResult, PulledFileResult
from forensix_forensic.extractors.apk_downgrade import (
    APK_DOWNGRADE_PROFILES,
    ApkDowngradeExtractor,
    DowngradeCapabilityStatus,
    get_apk_downgrade_profile,
)


class FakeAdbClient:
    def __init__(
        self,
        *,
        api: int | None = 28,
        raw_api_prop: str | None = None,
        fail_backup: bool = False,
        missing_package: bool = False,
    ) -> None:
        self.api = api
        self.raw_api_prop = raw_api_prop
        self.fail_backup = fail_backup
        self.missing_package = missing_package
        self.version_dumps = [
            "versionCode=100 minSdk=21 targetSdk=30\nversionName=10.0",
            "versionCode=50 minSdk=21 targetSdk=27\nversionName=5.0",
            "versionCode=100 minSdk=21 targetSdk=30\nversionName=10.0",
        ]
        self.installs: list[tuple[str, ...]] = []
        self.backups: list[str] = []

    async def get_properties(self, serial: str) -> dict[str, str]:
        if self.raw_api_prop is not None:
            return {
                "ro.build.version.sdk": self.raw_api_prop,
                "ro.build.version.release": "unknown",
            }
        if self.api is None:
            return {}
        release = "5.0" if self.api == 21 else "11" if self.api == 30 else "12"
        return {
            "ro.build.version.sdk": str(self.api),
            "ro.build.version.release": release,
        }

    async def dump_package(self, serial: str, package_name: str) -> str:
        if self.missing_package:
            return ""
        if self.version_dumps:
            return self.version_dumps.pop(0)
        return "versionCode=100 minSdk=21 targetSdk=30\nversionName=10.0"

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
        self.backups.append(package_name)
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
@pytest.mark.parametrize("api", [21, 28, 30])
async def test_downgrade_supports_legacy_android_5_through_11_and_restores_splits(
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
    assert result.capability_status == DowngradeCapabilityStatus.LEGACY_SUPPORTED
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
@pytest.mark.parametrize("api", [31, 33, 34])
async def test_modern_android_12_plus_is_rejected_without_adb_mutation(
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
    assert result.capability_status == DowngradeCapabilityStatus.UNSUPPORTED
    assert result.restored is True
    assert "Android 12+" in (result.capability_reason or "")
    assert adb.installs == []
    assert adb.backups == []


@pytest.mark.asyncio
async def test_unknown_api_level_fails_closed_without_adb_mutation(tmp_path: Path) -> None:
    apk_path, apk_hash = _staged_apk(tmp_path)
    adb = FakeAdbClient(raw_api_prop="invalid")

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=(apk_hash,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is False
    assert result.capability_status == DowngradeCapabilityStatus.UNKNOWN
    assert result.restored is True
    assert "valid Android API level" in (result.capability_reason or "")
    assert adb.installs == []
    assert adb.backups == []


@pytest.mark.asyncio
async def test_hash_mismatch_is_classified_as_unsafe_without_adb_mutation(
    tmp_path: Path,
) -> None:
    apk_path, _ = _staged_apk(tmp_path)
    adb = FakeAdbClient(api=28)

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=("0" * 64,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is False
    assert result.capability_status == DowngradeCapabilityStatus.UNSAFE
    assert "SHA-256 mismatch" in (result.capability_reason or "")
    assert adb.installs == []
    assert adb.backups == []


@pytest.mark.asyncio
async def test_missing_package_is_classified_as_unsafe_without_adb_mutation(
    tmp_path: Path,
) -> None:
    apk_path, apk_hash = _staged_apk(tmp_path)
    adb = FakeAdbClient(api=28, missing_package=True)

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=(apk_hash,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is False
    assert result.capability_status == DowngradeCapabilityStatus.UNSAFE
    assert "not installed" in (result.capability_reason or "")
    assert adb.installs == []
    assert adb.backups == []


@pytest.mark.asyncio
async def test_backup_failure_on_supported_device_still_restores_original_package(
    tmp_path: Path,
) -> None:
    apk_path, apk_hash = _staged_apk(tmp_path)
    adb = FakeAdbClient(api=28, fail_backup=True)

    result = await ApkDowngradeExtractor(adb, tmp_path).extract(
        "FX-DEMO-001",
        profile_id="whatsapp",
        downgrade_apk_paths=(apk_path,),
        expected_sha256=(apk_hash,),
        case_id="CASE-001",
        operator_id="operator",
    )

    assert result.success is False
    assert result.capability_status == DowngradeCapabilityStatus.LEGACY_SUPPORTED
    assert result.restored is True
    assert result.error_message == "simulated backup failure"
    assert len(adb.installs) == 2


@pytest.mark.asyncio
async def test_assess_capability_direct_evaluation(tmp_path: Path) -> None:
    apk_path, apk_hash = _staged_apk(tmp_path)
    profile = get_apk_downgrade_profile("whatsapp")

    # API 28 -> LEGACY_SUPPORTED
    adb = FakeAdbClient(api=28)
    status, reason, api, release, version = await ApkDowngradeExtractor(
        adb, tmp_path
    ).assess_capability(
        "FX-DEMO-001", profile, downgrade_apk_paths=(apk_path,), expected_sha256=(apk_hash,)
    )
    assert status == DowngradeCapabilityStatus.LEGACY_SUPPORTED
    assert api == 28
    assert version == "10.0 (100)"

    # API 31 -> UNSUPPORTED
    adb = FakeAdbClient(api=31)
    status, reason, api, release, version = await ApkDowngradeExtractor(
        adb, tmp_path
    ).assess_capability("FX-DEMO-001", profile)
    assert status == DowngradeCapabilityStatus.UNSUPPORTED

    # Unknown property -> UNKNOWN
    adb = FakeAdbClient(raw_api_prop="invalid")
    status, reason, api, release, version = await ApkDowngradeExtractor(
        adb, tmp_path
    ).assess_capability("FX-DEMO-001", profile)
    assert status == DowngradeCapabilityStatus.UNKNOWN

    # Missing package -> UNSAFE
    adb = FakeAdbClient(api=28, missing_package=True)
    status, reason, api, release, version = await ApkDowngradeExtractor(
        adb, tmp_path
    ).assess_capability("FX-DEMO-001", profile)
    assert status == DowngradeCapabilityStatus.UNSAFE


def test_profiles_max_api_is_capped_at_30() -> None:
    assert APK_DOWNGRADE_PROFILES["whatsapp"].package_name == "com.whatsapp"
    assert APK_DOWNGRADE_PROFILES["signal"].package_name == "org.thoughtcrime.securesms"
    assert all(profile.min_api == 21 for profile in APK_DOWNGRADE_PROFILES.values())
    assert all(profile.max_api == 30 for profile in APK_DOWNGRADE_PROFILES.values())
