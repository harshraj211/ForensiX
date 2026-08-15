"""Frozen acquisition scope and module catalog."""

from enum import StrEnum


class AcquisitionScope(StrEnum):
    METADATA_ONLY = "metadata_only"
    QUICK_TRIAGE = "quick_triage"
    SHARED_STORAGE_INVENTORY = "shared_storage_inventory"
    IMAGE_FILES = "image_files"
    VIDEO_FILES = "video_files"
    AUDIO_FILES = "audio_files"
    MEDIA_FILES = "media_files"
    DOCUMENT_FILES = "document_files"
    DOWNLOADS_FILES = "downloads_files"
    CUSTOM = "custom"


class AcquisitionModule(StrEnum):
    DEVICE_METADATA = "device_metadata"
    PACKAGE_INVENTORY = "package_inventory"
    SHARED_STORAGE_INVENTORY = "shared_storage_inventory"


MODULE_CAPABILITIES: dict[AcquisitionModule, str] = {
    AcquisitionModule.DEVICE_METADATA: "device_metadata",
    AcquisitionModule.PACKAGE_INVENTORY: "package_inventory",
    AcquisitionModule.SHARED_STORAGE_INVENTORY: "shared_storage",
}

PRESET_MODULES: dict[AcquisitionScope, tuple[AcquisitionModule, ...]] = {
    AcquisitionScope.METADATA_ONLY: (
        AcquisitionModule.DEVICE_METADATA,
        AcquisitionModule.PACKAGE_INVENTORY,
    ),
    AcquisitionScope.QUICK_TRIAGE: (
        AcquisitionModule.DEVICE_METADATA,
        AcquisitionModule.PACKAGE_INVENTORY,
        AcquisitionModule.SHARED_STORAGE_INVENTORY,
    ),
    AcquisitionScope.SHARED_STORAGE_INVENTORY: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.IMAGE_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.VIDEO_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.AUDIO_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.MEDIA_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.DOCUMENT_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.DOWNLOADS_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.CUSTOM: (),
}

IMAGE_EXTENSIONS = frozenset(
    {
        "avif",
        "bmp",
        "dng",
        "gif",
        "heic",
        "heif",
        "jpeg",
        "jpg",
        "png",
        "svg",
        "tif",
        "tiff",
        "webp",
    }
)
VIDEO_EXTENSIONS = frozenset(
    {"3g2", "3gp", "avi", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "ts", "webm"}
)
AUDIO_EXTENSIONS = frozenset(
    {"3ga", "aac", "amr", "flac", "m4a", "mid", "midi", "mp3", "oga", "ogg", "opus", "wav"}
)
MEDIA_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS | AUDIO_EXTENSIONS
DOCUMENT_EXTENSIONS = frozenset(
    {
        "csv",
        "doc",
        "docx",
        "epub",
        "htm",
        "html",
        "json",
        "log",
        "md",
        "ods",
        "odt",
        "odp",
        "pdf",
        "ppt",
        "pptx",
        "rtf",
        "txt",
        "xls",
        "xlsx",
        "xml",
    }
)


def scope_allows_inventory_item(
    scope: AcquisitionScope, relative_path: str, extension: str | None
) -> bool:
    """Return whether a frozen scope authorizes acquiring one inventory item."""
    normalized_extension = (extension or "").casefold()
    normalized_path = relative_path.replace("\\", "/").casefold()
    if scope is AcquisitionScope.IMAGE_FILES:
        return normalized_extension in IMAGE_EXTENSIONS
    if scope is AcquisitionScope.VIDEO_FILES:
        return normalized_extension in VIDEO_EXTENSIONS
    if scope is AcquisitionScope.AUDIO_FILES:
        return normalized_extension in AUDIO_EXTENSIONS
    if scope is AcquisitionScope.MEDIA_FILES:
        return normalized_extension in MEDIA_EXTENSIONS
    if scope is AcquisitionScope.DOCUMENT_FILES:
        return normalized_extension in DOCUMENT_EXTENSIONS
    if scope is AcquisitionScope.DOWNLOADS_FILES:
        return normalized_path.startswith(("download/", "downloads/"))
    return scope is not AcquisitionScope.METADATA_ONLY


PLAN_SCHEMA_VERSION = "1.0.0"
READINESS_MAX_AGE_MINUTES = 30
