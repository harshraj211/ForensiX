"""Failure-safe Android APK downgrade acquisition for closed application profiles."""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient

MIN_ANDROID_API = 21
MAX_ANDROID_API = 33


@dataclass(frozen=True, slots=True)
class ApkDowngradeProfile:
    profile_id: str
    display_name: str
    package_name: str
    min_api: int = MIN_ANDROID_API
    max_api: int = MAX_ANDROID_API


APK_DOWNGRADE_PROFILES: dict[str, ApkDowngradeProfile] = {
    profile.profile_id: profile
    for profile in (
        ApkDowngradeProfile("facebook", "Facebook", "com.facebook.katana"),
        ApkDowngradeProfile("messenger", "Facebook Messenger", "com.facebook.orca"),
        ApkDowngradeProfile("instagram", "Instagram", "com.instagram.android"),
        ApkDowngradeProfile("kakaotalk", "KakaoTalk", "com.kakao.talk"),
        ApkDowngradeProfile("opera", "Opera", "com.opera.browser"),
        ApkDowngradeProfile("signal", "Signal", "org.thoughtcrime.securesms"),
        ApkDowngradeProfile("skype", "Skype", "com.skype.raider"),
        ApkDowngradeProfile("telegram", "Telegram", "org.telegram.messenger"),
        ApkDowngradeProfile("x", "X (Twitter)", "com.twitter.android"),
        ApkDowngradeProfile("viber", "Viber", "com.viber.voip"),
        ApkDowngradeProfile("wechat", "WeChat", "com.tencent.mm"),
        ApkDowngradeProfile("whatsapp", "WhatsApp", "com.whatsapp"),
        ApkDowngradeProfile("zello", "Zello", "com.loudtalks"),
    )
}


@dataclass(frozen=True, slots=True)
class PreservedApk:
    source_path: str
    local_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ApkDowngradeResult:
    extraction_id: str
    profile_id: str
    package_name: str
    android_release: str
    android_api: int
    original_version: str | None
    downgrade_version: str | None
    backup_path: str | None
    backup_file_size_bytes: int
    backup_sha256: str
    preserved_apks: tuple[PreservedApk, ...]
    restored: bool
    timeline: tuple[dict[str, str], ...]
    duration_seconds: float
    success: bool
    error_message: str | None


class ApkDowngradeExtractor:
    """Temporarily replace one approved app, acquire its backup, then restore it."""

    def __init__(self, adb_client: AdbClient, work_dir: Path) -> None:
        self._adb = adb_client
        self._work_dir = work_dir.resolve()

    async def extract(
        self,
        serial: str,
        *,
        profile_id: str,
        downgrade_apk_paths: tuple[Path, ...],
        expected_sha256: tuple[str, ...],
        case_id: str,
        operator_id: str,
    ) -> ApkDowngradeResult:
        extraction_id = str(uuid4())
        started = time.monotonic()
        timeline: list[dict[str, str]] = []
        profile = get_apk_downgrade_profile(profile_id)
        run_dir = self._work_dir / f"apk_downgrade_{extraction_id}"
        originals_dir = run_dir / "original_apks"
        backup_path = run_dir / f"{profile.profile_id}.ab"
        journal_path = run_dir / "recovery.json"
        preserved: tuple[PreservedApk, ...] = ()
        original_version: str | None = None
        downgrade_version: str | None = None
        android_release = "unknown"
        android_api = 0
        backup_hash = ""
        backup_size = 0
        mutated = False
        restored = False
        success = False
        error_message: str | None = None

        run_dir.mkdir(parents=True, exist_ok=False)
        originals_dir.mkdir()
        try:
            properties = await self._adb.get_properties(serial)
            android_release = properties.get("ro.build.version.release", "unknown")
            android_api = _parse_android_api(properties)
            if not profile.min_api <= android_api <= profile.max_api:
                raise RuntimeError(
                    f"{profile.display_name} downgrade is limited to Android 5-13 "
                    f"(API 21-33); device reports API {android_api}."
                )
            _log(timeline, "STEP", f"Android {android_release} (API {android_api}) accepted")

            package_dump = await self._adb.dump_package(serial, profile.package_name)
            original_version = _parse_version(package_dump)
            if original_version is None:
                raise RuntimeError(
                    f"{profile.display_name} is not installed or has no version metadata."
                )
            _log(timeline, "STEP", f"Installed version: {original_version}")

            staged_apks = await asyncio.to_thread(
                _verify_staged_apks, downgrade_apk_paths, expected_sha256
            )
            _log(timeline, "STEP", f"Verified {len(staged_apks)} staged downgrade APK(s)")

            installed_paths = await self._adb.list_package_apks(serial, profile.package_name)
            preserved_items: list[PreservedApk] = []
            for index, remote_path in enumerate(installed_paths):
                local_path = originals_dir / f"{index:02d}_{Path(remote_path).name}"
                pulled = await self._adb.pull_package_apk(serial, remote_path, local_path)
                preserved_items.append(
                    PreservedApk(
                        source_path=remote_path,
                        local_path=str(local_path),
                        sha256=await asyncio.to_thread(_hash_file, local_path),
                        size_bytes=pulled.size_bytes,
                    )
                )
            preserved = tuple(preserved_items)
            _write_journal(
                journal_path,
                extraction_id=extraction_id,
                case_id=case_id,
                operator_id=operator_id,
                serial=serial,
                profile=profile,
                original_version=original_version,
                preserved=preserved,
                state="prepared",
            )
            _log(timeline, "STEP", f"Preserved {len(preserved)} original APK(s)")

            installed = await _install_apks(self._adb, serial, staged_apks)
            if not installed:
                raise RuntimeError("Android package manager rejected the downgrade APK set.")
            mutated = True
            _update_journal_state(journal_path, "downgraded")
            downgrade_version = _parse_version(
                await self._adb.dump_package(serial, profile.package_name)
            )
            if downgrade_version is None or downgrade_version == original_version:
                raise RuntimeError("Downgrade installation could not be verified on the device.")
            _log(timeline, "STEP", f"Temporary version installed: {downgrade_version}")

            backup = await self._adb.backup_package(serial, profile.package_name, backup_path)
            backup_size = backup.backup_file_size_bytes
            backup_hash = await asyncio.to_thread(_hash_file, backup_path)
            _update_journal_state(journal_path, "backup_captured")
            _log(timeline, "STEP", f"ADB backup captured: {backup_size} bytes")
            success = True
        except Exception as error:
            error_message = str(error)
            _log(timeline, "ERROR", error_message)
        finally:
            if mutated:
                try:
                    restore_paths = tuple(item.local_path for item in preserved)
                    if not await _install_apks(self._adb, serial, restore_paths):
                        raise RuntimeError("Android package manager rejected the original APK set.")
                    restored_version = _parse_version(
                        await self._adb.dump_package(serial, profile.package_name)
                    )
                    if restored_version != original_version:
                        raise RuntimeError(
                            "Restored version mismatch: "
                            f"expected {original_version}, got {restored_version}."
                        )
                    restored = True
                    _update_journal_state(journal_path, "restored")
                    _log(timeline, "STEP", f"Original version restored: {restored_version}")
                except Exception as restore_error:
                    success = False
                    restore_message = f"CRITICAL RESTORE FAILURE: {restore_error}"
                    error_message = (
                        f"{error_message}; {restore_message}" if error_message else restore_message
                    )
                    _update_journal_state(journal_path, "restore_failed", restore_message)
                    _log(timeline, "ERROR", restore_message)
            else:
                restored = True

        return ApkDowngradeResult(
            extraction_id=extraction_id,
            profile_id=profile.profile_id,
            package_name=profile.package_name,
            android_release=android_release,
            android_api=android_api,
            original_version=original_version,
            downgrade_version=downgrade_version,
            backup_path=str(backup_path) if backup_size else None,
            backup_file_size_bytes=backup_size,
            backup_sha256=backup_hash,
            preserved_apks=preserved,
            restored=restored,
            timeline=tuple(timeline),
            duration_seconds=time.monotonic() - started,
            success=success and restored,
            error_message=error_message,
        )


def get_apk_downgrade_profile(profile_id: str) -> ApkDowngradeProfile:
    try:
        return APK_DOWNGRADE_PROFILES[profile_id]
    except KeyError as error:
        raise ValueError(f"Unknown APK downgrade profile: {profile_id}") from error


def _parse_android_api(properties: dict[str, str]) -> int:
    raw = properties.get("ro.build.version.sdk", "")
    if not raw.isdigit():
        raise RuntimeError("Device did not report a valid Android API level.")
    return int(raw)


def _parse_version(package_dump: str) -> str | None:
    name = re.search(r"\bversionName=([^\s]+)", package_dump)
    code = re.search(r"\bversionCode=(\d+)", package_dump)
    if name and code:
        return f"{name.group(1)} ({code.group(1)})"
    if name:
        return name.group(1)
    if code:
        return code.group(1)
    return None


def _verify_staged_apks(paths: tuple[Path, ...], hashes: tuple[str, ...]) -> tuple[str, ...]:
    if not paths or len(paths) > 64 or len(paths) != len(hashes):
        raise ValueError("Provide one SHA-256 value for each of 1-64 downgrade APKs.")
    verified: list[str] = []
    for path, expected in zip(paths, hashes, strict=True):
        resolved = path.resolve(strict=True)
        normalized_hash = expected.lower()
        if resolved.suffix.lower() != ".apk" or not re.fullmatch(r"[0-9a-f]{64}", normalized_hash):
            raise ValueError("Every downgrade APK needs a valid .apk path and SHA-256 value.")
        actual = _hash_file(resolved)
        if actual != normalized_hash:
            raise ValueError(f"SHA-256 mismatch for staged APK: {resolved.name}")
        verified.append(str(resolved))
    return tuple(verified)


async def _install_apks(adb: AdbClient, serial: str, paths: tuple[str, ...]) -> bool:
    if len(paths) == 1:
        return await adb.install_package(serial, paths[0])
    return await adb.install_packages(serial, paths)


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _log(timeline: list[dict[str, str]], level: str, message: str) -> None:
    timeline.append(
        {"timestamp": datetime.now(UTC).isoformat(), "level": level, "message": message}
    )


def _write_journal(
    path: Path,
    *,
    extraction_id: str,
    case_id: str,
    operator_id: str,
    serial: str,
    profile: ApkDowngradeProfile,
    original_version: str,
    preserved: tuple[PreservedApk, ...],
    state: str,
) -> None:
    payload = {
        "extraction_id": extraction_id,
        "case_id": case_id,
        "operator_id": operator_id,
        "serial": serial,
        "profile": asdict(profile),
        "original_version": original_version,
        "preserved_apks": [asdict(item) for item in preserved],
        "state": state,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    _atomic_json_write(path, payload)


def _update_journal_state(path: Path, state: str, error: str | None = None) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["state"] = state
    payload["updated_at"] = datetime.now(UTC).isoformat()
    if error:
        payload["error"] = error
    _atomic_json_write(path, payload)


def _atomic_json_write(path: Path, payload: Mapping[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)
