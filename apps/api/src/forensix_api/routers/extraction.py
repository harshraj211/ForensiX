"""Application-specific extraction endpoints (WhatsApp downgrade, Signal, Telegram).

These endpoints expose the downgrade-attack and rooted-application extractors
through a controlled, operator-acknowledged API.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from forensix_api.dependencies import (
    get_adb_client,
    require_device_operator,
)
from forensix_forensic.adb import AdbClient
from forensix_forensic.extractors.hardware import (
    HashcatConfig,
    HashcatLauncher,
    HashcatMode,
    LockBypassConfig,
    OfflineHashExtractor,
    ScreenLockAssessmentService,
    ScreenLockBypassEngine,
)

router = APIRouter(
    prefix="/api/v1/cases/{case_id}/extractions",
    tags=["extraction"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class WhatsAppDowngradeRequest(BaseModel):
    """Request body for the WhatsApp downgrade-attack extraction."""

    serial: str = Field(min_length=1, max_length=255)
    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    downgrade_acknowledged: bool = Field(
        description="Operator must explicitly acknowledge the downgrade risk.",
    )


class ExtractionTimelineEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: str
    level: str
    message: str


class WhatsAppDowngradeResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    extraction_id: str
    package_name: str
    original_version: str | None
    downgrade_version: str
    backup_file_size_bytes: int
    backup_sha256: str
    encryption_key_found: bool
    encrypted_database_found: bool
    decrypted_database_path: str | None
    key_file_path: str | None
    database_file_path: str | None
    timeline: list[ExtractionTimelineEntry]
    duration_seconds: float
    success: bool
    error_message: str | None


class ApkDowngradeRequest(BaseModel):
    """Request a failure-safe downgrade acquisition for one approved app profile."""

    serial: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    profile_id: str = Field(min_length=1, max_length=64)
    downgrade_apk_paths: list[str] = Field(min_length=1, max_length=64)
    expected_sha256: list[str] = Field(min_length=1, max_length=64)
    downgrade_acknowledged: bool = Field(
        description="Operator explicitly authorizes temporary package replacement.",
    )


class PreservedApkResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_path: str
    local_path: str
    sha256: str
    size_bytes: int


class ApkDowngradeResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

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
    preserved_apks: list[PreservedApkResponse]
    restored: bool
    timeline: list[ExtractionTimelineEntry]
    duration_seconds: float
    success: bool
    error_message: str | None


class SignalExtractionRequest(BaseModel):
    """Request body for the rooted Signal extraction."""

    serial: str = Field(min_length=1, max_length=255)
    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    root_acknowledged: bool = Field(
        description="Operator must explicitly acknowledge rooted extraction side effects.",
    )


class SignalExtractionResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    extraction_id: str
    package_name: str
    passphrase_found: bool
    passphrase_sha256: str
    encrypted_database_size_bytes: int
    encrypted_database_sha256: str
    decrypted_database_path: str | None
    preferences_file_path: str
    database_file_path: str
    timeline: list[ExtractionTimelineEntry]
    duration_seconds: float
    success: bool
    error_message: str | None


class TelegramExtractionRequest(BaseModel):
    """Request body for the rooted Telegram extraction."""

    serial: str = Field(min_length=1, max_length=255)
    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    package_name: str = Field(
        default="",
        min_length=0,
        max_length=255,
        description="Telegram package name (auto-detected if empty).",
    )
    root_acknowledged: bool = Field(
        description="Operator must explicitly acknowledge rooted extraction side effects.",
    )


class TelegramExtractionResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    extraction_id: str
    package_name: str
    package_display_name: str
    database_files_copied: int
    database_total_size_bytes: int
    database_sha256: str
    database_path: str
    timeline: list[ExtractionTimelineEntry]
    duration_seconds: float
    success: bool
    error_message: str | None


class SQLiteCarvingRequest(BaseModel):
    """Request body for SQLite carving on previously extracted database files."""

    source_paths: list[str] = Field(
        min_length=1,
        max_length=20,
        description="Local file paths to scan for deleted message fragments.",
    )
    case_id: str = Field(min_length=1, max_length=255)
    max_fragments: int = Field(default=10_000, ge=1, le=100_000)


class CarvedFragmentResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_file: str
    offset_bytes: int
    length_bytes: int
    fragment_type: str
    confidence: str
    content_preview: str
    content_sha256: str
    metadata: dict[str, str | int | bool | None]


class SQLiteCarvingResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    carving_id: str
    source_files: list[str]
    source_total_bytes: int
    fragments_found: int
    fragments: list[CarvedFragmentResponse]
    wal_fragments_found: int
    freelist_fragments_found: int
    unallocated_fragments_found: int
    duration_seconds: float
    limitations: list[str]


class ExtractionManifestResponse(BaseModel):
    """Verify the integrity of all extracted artefacts."""

    model_config = ConfigDict(frozen=True)

    extraction_id: str
    total_entries: int
    verified: bool
    error: str | None


class ScreenLockAssessRequest(BaseModel):
    """Request lock screen security assessment for an ADB connected device."""

    serial: str = Field(min_length=1, max_length=255)
    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)


class ScreenLockAssessResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    lock_type: str
    pin_length: int | None
    pattern_complexity: str | None
    max_failed_attempts: int | None
    wipe_risk: str
    biometric_enrolled: bool
    search_space_estimate: int
    gatekeeper_present: bool
    spblob_present: bool
    raw_settings: dict[str, str]
    duration_seconds: float
    success: bool
    error_message: str | None


class ScreenLockExtractHashesRequest(BaseModel):
    """Request offline credential hash extraction from a rooted device."""

    serial: str = Field(min_length=1, max_length=255)
    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    root_acknowledged: bool = Field(
        description="Operator explicitly acknowledges root privilege requirement.",
    )


class ScreenLockExtractHashesResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    dump_id: str
    device_serial: str
    lock_type: str
    gatekeeper_blobs_count: int
    spblob_files_count: int
    has_pattern_hash: bool
    has_password_salt: bool
    password_salt: str | None
    pattern_hash_hex: str | None
    aggregate_sha256: str
    saved_files: list[str]
    timeline: list[ExtractionTimelineEntry]
    duration_seconds: float
    success: bool
    error_message: str | None


class ScreenLockCrackRequest(BaseModel):
    """Request a password or PIN brute-force or dictionary cracking job."""

    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    mode: int = Field(
        default=13800,
        description="Hashcat mode: 10=Pattern, 13800=Android Gatekeeper, 18800=Android FDE",
    )
    attack_type: str = Field(
        default="mask",
        description="Attack type: 'mask' (PIN brute-force), 'wordlist', or 'pattern_solve'",
    )
    mask: str = Field(default="?d?d?d?d", max_length=128)
    wordlist_path: str = Field(default="", max_length=512)
    rules_path: str = Field(default="", max_length=512)
    raw_hash: str = Field(default="", max_length=1024)
    hash_file_path: str = Field(default="", max_length=512)
    hashcat_binary_path: str = Field(default="", max_length=512)


class ScreenLockCrackResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    job_id: str
    mode: int
    attack_type: str
    cracked_credentials: list[str]
    recovered_credential: str | None
    duration_seconds: float
    success: bool
    stdout_tail: str
    error_message: str | None


class ScreenLockBypassRequest(BaseModel):
    """Request rooted screen lock bypass (locksettings.db patch)."""

    serial: str = Field(min_length=1, max_length=255)
    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    dry_run: bool = Field(default=False)
    root_acknowledged: bool = Field(
        description="Operator explicitly acknowledges root requirement for lock bypass.",
    )


class ScreenLockBypassResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    bypass_id: str
    vector_used: str
    previous_lock_type: str
    android_api_level: int
    lock_disabled_success: bool
    db_patched: bool
    pre_patch_hash: str
    post_patch_hash: str
    dry_run: bool
    duration_seconds: float
    timeline: list[ExtractionTimelineEntry]
    success: bool
    error_message: str | None


class AuthorisedEntryRequest(BaseModel):
    """Supervised authorised entry attempt with safety delays."""

    serial: str = Field(min_length=1, max_length=255)
    case_id: str = Field(min_length=1, max_length=255)
    operator_id: str = Field(min_length=1, max_length=255)
    credential: str = Field(min_length=1, max_length=128)
    credential_type: str = Field(default="pin", description="'pin' or 'password'")


class AuthorisedEntryResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    attempt_id: str
    credential_type: str
    unlock_success: bool
    attempts_made: int
    duration_seconds: float
    timeline: list[ExtractionTimelineEntry]
    error_message: str | None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/apk-downgrade",
    response_model=ApkDowngradeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Android 5-13 app extraction via failure-safe APK downgrade",
    description=(
        "Targets a closed application profile on Android API 21-33. The service verifies "
        "examiner-supplied APK hashes, preserves the installed base and split APKs, captures "
        "an ADB backup, and restores the exact original package set in failure-safe cleanup."
    ),
)
async def apk_downgrade_extract(
    case_id: str,
    request: ApkDowngradeRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> ApkDowngradeResponse:
    from fastapi import HTTPException

    if not request.downgrade_acknowledged:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator must acknowledge temporary package replacement risks.",
        )
    if len(request.downgrade_apk_paths) != len(request.expected_sha256):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Each downgrade APK must have one matching SHA-256 value.",
        )

    from forensix_forensic.extractors import ApkDowngradeExtractor

    work_dir = Path(tempfile.mkdtemp(prefix="forensix_apk_downgrade_"))
    extractor = ApkDowngradeExtractor(adb_client, work_dir)
    try:
        result = await extractor.extract(
            request.serial,
            profile_id=request.profile_id,
            downgrade_apk_paths=tuple(Path(path) for path in request.downgrade_apk_paths),
            expected_sha256=tuple(request.expected_sha256),
            case_id=case_id,
            operator_id=request.operator_id,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error

    return ApkDowngradeResponse(
        extraction_id=result.extraction_id,
        profile_id=result.profile_id,
        package_name=result.package_name,
        android_release=result.android_release,
        android_api=result.android_api,
        original_version=result.original_version,
        downgrade_version=result.downgrade_version,
        backup_path=result.backup_path,
        backup_file_size_bytes=result.backup_file_size_bytes,
        backup_sha256=result.backup_sha256,
        preserved_apks=[PreservedApkResponse(**asdict(item)) for item in result.preserved_apks],
        restored=result.restored,
        timeline=[ExtractionTimelineEntry(**entry) for entry in result.timeline],
        duration_seconds=result.duration_seconds,
        success=result.success,
        error_message=result.error_message,
    )


@router.post(
    "/whatsapp-downgrade",
    response_model=WhatsAppDowngradeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="WhatsApp extraction via downgrade attack (non-rooted devices)",
    description=(
        "Automates the downgrade-attack workflow: temporarily downgrades WhatsApp "
        "to a version that permits ADB backup, captures the backup, restores the "
        "current version, then unpacks and decrypts the database."
    ),
)
async def whatsapp_downgrade_extract(
    case_id: str,
    request: WhatsAppDowngradeRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> WhatsAppDowngradeResponse:
    if not request.downgrade_acknowledged:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator must acknowledge downgrade attack risks.",
        )

    from forensix_forensic.extractors import (
        StreamingManifestCollector,
        WhatsAppDowngradeExtractor,
    )

    work_dir = Path(tempfile.mkdtemp(prefix="forensix_wa_"))
    manifest = StreamingManifestCollector(work_dir)
    extractor = WhatsAppDowngradeExtractor(adb_client, work_dir, manifest=manifest)
    result = await extractor.extract(
        request.serial,
        case_id=request.case_id,
        operator_id=request.operator_id,
    )

    return WhatsAppDowngradeResponse(
        extraction_id=result.extraction_id,
        package_name=result.package_name,
        original_version=result.original_version,
        downgrade_version=result.downgrade_version,
        backup_file_size_bytes=result.backup_file_size_bytes,
        backup_sha256=result.backup_sha256,
        encryption_key_found=result.encryption_key_found,
        encrypted_database_found=result.encrypted_database_found,
        decrypted_database_path=result.decrypted_database_path,
        key_file_path=result.key_file_path,
        database_file_path=result.database_file_path,
        timeline=[ExtractionTimelineEntry(**e) for e in result.timeline],
        duration_seconds=result.duration_seconds,
        success=result.success,
        error_message=result.error_message,
    )


@router.post(
    "/signal-rooted",
    response_model=SignalExtractionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Signal extraction on rooted devices (SQLCipher key retrieval)",
    description=(
        "Copies the Signal shared-preferences and SQLCipher database from the "
        "application sandbox via root access, extracts the encryption passphrase, "
        "and attempts database decryption."
    ),
)
async def signal_rooted_extract(
    case_id: str,
    request: SignalExtractionRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> SignalExtractionResponse:
    if not request.root_acknowledged:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator must acknowledge rooted extraction side effects.",
        )

    from forensix_forensic.extractors import (
        SignalRootedExtractor,
        StreamingManifestCollector,
    )

    work_dir = Path(tempfile.mkdtemp(prefix="forensix_signal_"))
    manifest = StreamingManifestCollector(work_dir)
    extractor = SignalRootedExtractor(adb_client, work_dir, manifest=manifest)
    result = await extractor.extract(
        request.serial,
        case_id=request.case_id,
        operator_id=request.operator_id,
    )

    return SignalExtractionResponse(
        extraction_id=result.extraction_id,
        package_name=result.package_name,
        passphrase_found=result.passphrase_found,
        passphrase_sha256=result.passphrase_sha256,
        encrypted_database_size_bytes=result.encrypted_database_size_bytes,
        encrypted_database_sha256=result.encrypted_database_sha256,
        decrypted_database_path=result.decrypted_database_path,
        preferences_file_path=result.preferences_file_path,
        database_file_path=result.database_file_path,
        timeline=[ExtractionTimelineEntry(**e) for e in result.timeline],
        duration_seconds=result.duration_seconds,
        success=result.success,
        error_message=result.error_message,
    )


@router.post(
    "/telegram-rooted",
    response_model=TelegramExtractionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Telegram extraction on rooted devices (direct database copy)",
    description=(
        "Copies the Telegram cache4.db database from the application sandbox "
        "via root access, along with WAL and SHM files."
    ),
)
async def telegram_rooted_extract(
    case_id: str,
    request: TelegramExtractionRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> TelegramExtractionResponse:
    if not request.root_acknowledged:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator must acknowledge rooted extraction side effects.",
        )

    from forensix_forensic.extractors import (
        StreamingManifestCollector,
        TelegramRootedExtractor,
    )

    work_dir = Path(tempfile.mkdtemp(prefix="forensix_telegram_"))
    manifest = StreamingManifestCollector(work_dir)
    extractor = TelegramRootedExtractor(adb_client, work_dir, manifest=manifest)
    result = await extractor.extract(
        request.serial,
        case_id=request.case_id,
        operator_id=request.operator_id,
        package_name=request.package_name,
    )

    return TelegramExtractionResponse(
        extraction_id=result.extraction_id,
        package_name=result.package_name,
        package_display_name=result.package_display_name,
        database_files_copied=result.database_files_copied,
        database_total_size_bytes=result.database_total_size_bytes,
        database_sha256=result.database_sha256,
        database_path=result.database_path,
        timeline=[ExtractionTimelineEntry(**e) for e in result.timeline],
        duration_seconds=result.duration_seconds,
        success=result.success,
        error_message=result.error_message,
    )


@router.post(
    "/sqlite-carve",
    response_model=SQLiteCarvingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="SQLite carver for deleted message recovery",
    description=(
        "Scans raw SQLite database files for deleted message fragments in WAL "
        "frames, freelists, and unallocated regions."
    ),
)
async def sqlite_carve(
    case_id: str,
    request: SQLiteCarvingRequest,
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> SQLiteCarvingResponse:
    from forensix_forensic.extractors import SQLiteCarver

    source_paths = [Path(p) for p in request.source_paths]
    carver = SQLiteCarver()
    result = carver.carve(source_paths, max_fragments=request.max_fragments)

    return SQLiteCarvingResponse(
        carving_id=result.carving_id,
        source_files=result.source_files,
        source_total_bytes=result.source_total_bytes,
        fragments_found=result.fragments_found,
        fragments=[
            CarvedFragmentResponse(
                source_file=f.source_file,
                offset_bytes=f.offset_bytes,
                length_bytes=f.length_bytes,
                fragment_type=f.fragment_type,
                confidence=f.confidence,
                content_preview=f.content_preview,
                content_sha256=f.content_sha256,
                metadata=f.metadata,
            )
            for f in result.fragments
        ],
        wal_fragments_found=result.wal_fragments_found,
        freelist_fragments_found=result.freelist_fragments_found,
        unallocated_fragments_found=result.unallocated_fragments_found,
        duration_seconds=result.duration_seconds,
        limitations=list(result.limitations),
    )


# ---------------------------------------------------------------------------
# Hardware ADB Adapter & Lock Screen Cracking Helpers
# ---------------------------------------------------------------------------


class HardwareAdbAdapter:
    """Adapter wrapping AdbClient with methods expected by hardware modules."""

    def __init__(self, adb: Any) -> None:
        self._adb = adb

    async def shell(self, serial: str, command: str) -> str:
        if hasattr(self._adb, "_runner"):
            runner = self._adb._runner
            try:
                res = await runner.run(("-s", serial, "shell", command), timeout_seconds=30.0)
                return str(res.stdout)
            except Exception:  # noqa: BLE001, S110
                pass
        if hasattr(self._adb, "root_exec") and "su -c" in command:
            try:
                inner = command.replace("su -c", "").strip().strip("'").strip('"')
                return str(await self._adb.root_exec(serial, inner))
            except Exception:  # noqa: BLE001, S110
                pass
        return ""

    async def pull(self, serial: str, remote_path: str, local_path: str) -> bool:
        if hasattr(self._adb, "_runner"):
            runner = self._adb._runner
            try:
                cmd = ("-s", serial, "pull", remote_path, local_path)
                res = await runner.run(cmd, timeout_seconds=60.0)
                return bool(res.exit_code == 0)
            except Exception:  # noqa: BLE001, S110
                pass
        return False

    async def push(self, serial: str, local_path: str, remote_path: str) -> bool:
        if hasattr(self._adb, "_runner"):
            runner = self._adb._runner
            try:
                cmd = ("-s", serial, "push", local_path, remote_path)
                res = await runner.run(cmd, timeout_seconds=60.0)
                return bool(res.exit_code == 0)
            except Exception:  # noqa: BLE001, S110
                pass
        return False


def _solve_pattern_key(target_hash_hex: str) -> str | None:
    """Solve an Android pattern.key SHA-1 (20B) or MD5 (16B) hash in pure Python.

    Explores the 389,112 legal Android pattern paths on a 3x3 grid (nodes 0..8).
    """
    clean_hex = target_hash_hex.strip().lower()
    try:
        target_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        return None

    jumps: dict[tuple[int, int], int] = {
        (0, 2): 1, (2, 0): 1,
        (0, 6): 3, (6, 0): 3,
        (0, 8): 4, (8, 0): 4,
        (1, 7): 4, (7, 1): 4,
        (2, 6): 4, (6, 2): 4,
        (2, 8): 5, (8, 2): 5,
        (3, 5): 4, (5, 3): 4,
        (6, 8): 7, (8, 6): 7,
    }

    found: list[int] | None = None

    def dfs(current_path: list[int], visited: set[int]) -> bool:
        nonlocal found
        if len(current_path) >= 4:
            payload = bytes(current_path)
            h_sha1 = hashlib.sha1(payload).digest()  # noqa: S324
            h_md5 = hashlib.md5(payload).digest()  # noqa: S324
            if h_sha1 == target_bytes or h_md5 == target_bytes:
                found = list(current_path)
                return True
        if len(current_path) == 9:
            return False
        last = current_path[-1]
        for nxt in range(9):
            if nxt not in visited:
                jump_mid = jumps.get((last, nxt))
                if jump_mid is None or jump_mid in visited:
                    visited.add(nxt)
                    current_path.append(nxt)
                    if dfs(current_path, visited):
                        return True
                    current_path.pop()
                    visited.remove(nxt)
        return False

    for start_node in range(9):
        if dfs([start_node], {start_node}):
            break

    if found is not None:
        sequence_1based = "".join(str(n + 1) for n in found)
        return f"Pattern Grid: {sequence_1based}"
    return None


def _solve_pin_brute_force(target_hash_hex: str, length: int = 4) -> str | None:
    """Test standard numeric PINs (0000..9999 or 000000..999999) against unsalted hashes."""
    clean_hex = target_hash_hex.strip().lower()
    total = 10**length
    for n in range(total):
        candidate = f"{n:0{length}d}"
        cand_bytes = candidate.encode("utf-8")
        if (
            hashlib.md5(cand_bytes).hexdigest() == clean_hex  # noqa: S324
            or hashlib.sha1(cand_bytes).hexdigest() == clean_hex  # noqa: S324
            or hashlib.sha256(cand_bytes).hexdigest() == clean_hex
        ):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Screen Lock & Passcode Cracking Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/screen-lock/assess",
    response_model=ScreenLockAssessResponse,
    status_code=status.HTTP_200_OK,
    summary="Assess lock screen mechanism, search space, and wipe risk",
)
async def assess_screen_lock(
    case_id: str,
    request: ScreenLockAssessRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> ScreenLockAssessResponse:
    adapter = HardwareAdbAdapter(adb_client)
    service = ScreenLockAssessmentService(adb=adapter)
    t0 = time.monotonic()
    try:
        profile = await service.assess(request.serial, request.case_id)
        duration = time.monotonic() - t0
        return ScreenLockAssessResponse(
            lock_type=profile.lock_type,
            pin_length=profile.pin_length,
            pattern_complexity=profile.pattern_complexity,
            max_failed_attempts=profile.max_failed_attempts,
            wipe_risk=profile.wipe_risk,
            biometric_enrolled=profile.biometric_enrolled,
            search_space_estimate=profile.search_space_estimate,
            gatekeeper_present=profile.gatekeeper_present,
            spblob_present=profile.spblob_present,
            raw_settings=profile.raw_settings,
            duration_seconds=round(duration, 3),
            success=True,
            error_message=None,
        )
    except Exception as exc:
        duration = time.monotonic() - t0
        return ScreenLockAssessResponse(
            lock_type="unknown",
            pin_length=None,
            pattern_complexity=None,
            max_failed_attempts=None,
            wipe_risk="low",
            biometric_enrolled=False,
            search_space_estimate=0,
            gatekeeper_present=False,
            spblob_present=False,
            raw_settings={},
            duration_seconds=round(duration, 3),
            success=False,
            error_message=str(exc),
        )


@router.post(
    "/screen-lock/extract-hashes",
    response_model=ScreenLockExtractHashesResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Extract Gatekeeper, SPBlob, and pattern hashes for offline cracking",
)
async def extract_screen_lock_hashes(
    case_id: str,
    request: ScreenLockExtractHashesRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> ScreenLockExtractHashesResponse:
    if not request.root_acknowledged:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator must acknowledge root privilege requirement.",
        )

    clean_serial = request.serial.replace(":", "_")
    work_dir = Path(tempfile.gettempdir()) / f"forensix_hashes_{case_id}_{clean_serial}"
    work_dir.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240

    adapter = HardwareAdbAdapter(adb_client)
    extractor = OfflineHashExtractor(adb=adapter, output_dir=work_dir)  # type: ignore[arg-type]
    t0 = time.monotonic()

    dump = await extractor.extract(request.serial, request.case_id, request.operator_id)
    duration = time.monotonic() - t0

    saved_files = [str(f) for f in work_dir.glob("*") if f.is_file()]  # noqa: ASYNC240
    pattern_hex = dump.pattern_hash.hex() if dump.pattern_hash else None

    timeline_entries = [
        ExtractionTimelineEntry(
            timestamp=e.get("ts", ""),
            level="INFO",
            message=f"{e.get('event', '')}: {e}",
        )
        for e in dump.timeline
    ]

    return ScreenLockExtractHashesResponse(
        dump_id=dump.dump_id,
        device_serial=dump.device_serial,
        lock_type=dump.lock_type,
        gatekeeper_blobs_count=len(dump.gatekeeper_blobs),
        spblob_files_count=len(dump.spblob_files),
        has_pattern_hash=dump.pattern_hash is not None,
        has_password_salt=dump.password_salt is not None,
        password_salt=dump.password_salt,
        pattern_hash_hex=pattern_hex,
        aggregate_sha256=dump.aggregate_sha256,
        saved_files=saved_files,
        timeline=timeline_entries,
        duration_seconds=round(duration, 3),
        success=dump.success,
        error_message=dump.error_message,
    )


@router.post(
    "/screen-lock/crack",
    response_model=ScreenLockCrackResponse,
    status_code=status.HTTP_200_OK,
    summary="Launch password, PIN, or pattern brute-force/dictionary cracking job",
)
async def crack_screen_lock(
    case_id: str,
    request: ScreenLockCrackRequest,
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> ScreenLockCrackResponse:
    job_id = str(uuid4())
    t0 = time.monotonic()

    # 1. Check for pure-Python instant solve (Pattern lock or 4-digit PIN)
    if (request.attack_type == "pattern_solve" or request.mode == 10) and request.raw_hash:
        solved = _solve_pattern_key(request.raw_hash)
        duration = time.monotonic() - t0
        if solved:
            return ScreenLockCrackResponse(
                job_id=job_id,
                mode=request.mode,
                attack_type=request.attack_type,
                cracked_credentials=[solved],
                recovered_credential=solved,
                duration_seconds=round(duration, 3),
                success=True,
                stdout_tail="Pure-Python Android pattern solver verified permutations.",
                error_message=None,
            )
        return ScreenLockCrackResponse(
            job_id=job_id,
            mode=request.mode,
            attack_type=request.attack_type,
            cracked_credentials=[],
            recovered_credential=None,
            duration_seconds=round(duration, 3),
            success=False,
            stdout_tail="Exhausted all 389,112 legal Android patterns without match.",
            error_message="Hash did not match any legal Android 3x3 pattern sequence.",
        )

    # 2. Check for pure-Python 4-digit PIN brute force on raw unsalted hashes
    if request.attack_type == "mask" and request.mask == "?d?d?d?d" and request.raw_hash:
        solved_pin = _solve_pin_brute_force(request.raw_hash, length=4)
        if solved_pin:
            duration = time.monotonic() - t0
            return ScreenLockCrackResponse(
                job_id=job_id,
                mode=request.mode,
                attack_type=request.attack_type,
                cracked_credentials=[solved_pin],
                recovered_credential=solved_pin,
                duration_seconds=round(duration, 3),
                success=True,
                stdout_tail="Direct PIN search space (0000-9999) resolved successfully.",
                error_message=None,
            )

    # 3. Locate Hashcat binary
    hc_bin: Path | None = None
    if request.hashcat_binary_path and Path(request.hashcat_binary_path).exists():  # noqa: ASYNC240
        hc_bin = Path(request.hashcat_binary_path)
    else:
        which_hc = shutil.which("hashcat") or shutil.which("hashcat.exe")
        if which_hc:
            hc_bin = Path(which_hc)
        elif Path("tools/hashcat/hashcat.exe").exists():  # noqa: ASYNC240
            hc_bin = Path("tools/hashcat/hashcat.exe").resolve()  # noqa: ASYNC240

    if not hc_bin:
        duration = time.monotonic() - t0
        return ScreenLockCrackResponse(
            job_id=job_id,
            mode=request.mode,
            attack_type=request.attack_type,
            cracked_credentials=[],
            recovered_credential=None,
            duration_seconds=round(duration, 3),
            success=False,
            stdout_tail="",
            error_message=(
                "Hashcat executable not found. Install Hashcat or supply "
                "'hashcat_binary_path' to perform GPU Gatekeeper cracking."
            ),
        )

    # 4. Prepare target hash file
    work_dir = Path(tempfile.gettempdir()) / f"forensix_hc_{case_id}_{job_id}"
    work_dir.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240
    hash_file = work_dir / "target_hash.txt"

    if request.hash_file_path and Path(request.hash_file_path).exists():  # noqa: ASYNC240
        hash_file = Path(request.hash_file_path)
    elif request.raw_hash:
        hash_file.write_text(request.raw_hash.strip() + "\n")  # noqa: ASYNC240
    else:
        duration = time.monotonic() - t0
        return ScreenLockCrackResponse(
            job_id=job_id,
            mode=request.mode,
            attack_type=request.attack_type,
            cracked_credentials=[],
            recovered_credential=None,
            duration_seconds=round(duration, 3),
            success=False,
            stdout_tail="",
            error_message="Either 'raw_hash' or 'hash_file_path' must be provided.",
        )

    # 5. Launch Hashcat
    cfg = HashcatConfig(
        hashcat_binary=hc_bin,
        wordlist_path=Path(request.wordlist_path) if request.wordlist_path else None,
        rules_path=Path(request.rules_path) if request.rules_path else None,
        mask=request.mask if request.attack_type == "mask" else None,
        session_name=f"fx_{job_id[:8]}",
    )
    launcher = HashcatLauncher(cfg, work_dir)
    valid_modes = (10, 13800, 18800)
    mode_enum = (
        HashcatMode(request.mode)
        if request.mode in valid_modes
        else HashcatMode.ANDROID_GATEKEEPER
    )

    res = await launcher.run(hash_file, mode_enum, case_id)
    recovered = res.cracked_credentials[0] if res.cracked_credentials else None

    return ScreenLockCrackResponse(
        job_id=res.job_id,
        mode=res.mode,
        attack_type=request.attack_type,
        cracked_credentials=list(res.cracked_credentials),
        recovered_credential=recovered,
        duration_seconds=res.duration_seconds,
        success=res.success,
        stdout_tail=res.stdout_tail,
        error_message=res.error_message,
    )


@router.post(
    "/screen-lock/bypass",
    response_model=ScreenLockBypassResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute rooted screen lock bypass",
)
async def bypass_screen_lock(
    case_id: str,
    request: ScreenLockBypassRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> ScreenLockBypassResponse:
    if not request.root_acknowledged:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator must acknowledge root privilege requirement for lock bypass.",
        )

    clean_serial = request.serial.replace(":", "_")
    work_dir = Path(tempfile.gettempdir()) / f"forensix_bypass_{case_id}_{clean_serial}"
    work_dir.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240

    adapter = HardwareAdbAdapter(adb_client)
    engine = ScreenLockBypassEngine(
        adb=adapter,
        output_dir=work_dir,
        config=LockBypassConfig(dry_run=request.dry_run),
    )

    result = await engine.bypass_lock(
        serial=request.serial,
        case_id=request.case_id,
        operator_id=request.operator_id,
    )

    timeline_entries = [
        ExtractionTimelineEntry(
            timestamp=e.get("ts", ""),
            level="INFO",
            message=f"{e.get('event', '')}: {e}",
        )
        for e in result.timeline
    ]

    return ScreenLockBypassResponse(
        bypass_id=result.bypass_id,
        vector_used=result.vector_used,
        previous_lock_type=result.previous_lock_type,
        android_api_level=result.android_api_level,
        lock_disabled_success=result.lock_disabled_success,
        db_patched=result.db_patched,
        pre_patch_hash=result.pre_patch_hash,
        post_patch_hash=result.post_patch_hash,
        dry_run=result.dry_run,
        duration_seconds=result.duration_seconds,
        timeline=timeline_entries,
        success=result.success,
        error_message=result.error_message,
    )


@router.post(
    "/screen-lock/authorised-entry",
    response_model=AuthorisedEntryResponse,
    status_code=status.HTTP_200_OK,
    summary="Supervised authorised passcode entry with anti-wipe delays",
)
async def attempt_authorised_entry(
    case_id: str,
    request: AuthorisedEntryRequest,
    adb_client: Annotated[AdbClient, Depends(get_adb_client)],
    _authenticated: Annotated[object, Depends(require_device_operator)],
) -> AuthorisedEntryResponse:
    adapter = HardwareAdbAdapter(adb_client)
    service = ScreenLockAssessmentService(adb=adapter)

    res = await service.authorised_entry(
        serial=request.serial,
        credential=request.credential,
        credential_type=request.credential_type,
        case_id=request.case_id,
        operator_id=request.operator_id,
    )

    timeline_entries = [
        ExtractionTimelineEntry(
            timestamp=e.get("ts", ""),
            level="INFO",
            message=f"{e.get('event', '')}: {e}",
        )
        for e in res.timeline
    ]

    return AuthorisedEntryResponse(
        attempt_id=res.attempt_id,
        credential_type=res.credential_type,
        unlock_success=res.unlock_success,
        attempts_made=res.attempts_made,
        duration_seconds=res.duration_seconds,
        timeline=timeline_entries,
        error_message=res.error_message,
    )
