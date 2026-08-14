"""Application-specific extraction endpoints (WhatsApp downgrade, Signal, Telegram).

These endpoints expose the downgrade-attack and rooted-application extractors
through a controlled, operator-acknowledged API.
"""

from __future__ import annotations

import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field

from forensix_api.dependencies import (
    get_adb_client,
    require_device_operator,
)
from forensix_forensic.adb import AdbClient

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
