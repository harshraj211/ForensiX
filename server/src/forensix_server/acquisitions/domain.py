"""Frozen acquisition scope and module catalog."""

from enum import StrEnum


class AcquisitionScope(StrEnum):
    METADATA_ONLY = "metadata_only"
    QUICK_TRIAGE = "quick_triage"
    SHARED_STORAGE_INVENTORY = "shared_storage_inventory"
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
    AcquisitionScope.MEDIA_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.DOCUMENT_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.DOWNLOADS_FILES: (AcquisitionModule.SHARED_STORAGE_INVENTORY,),
    AcquisitionScope.CUSTOM: (),
}

MEDIA_EXTENSIONS = frozenset(
    {
        "3g2",
        "3ga",
        "3gp",
        "aac",
        "amr",
        "avif",
        "avi",
        "bmp",
        "dng",
        "flac",
        "gif",
        "heic",
        "heif",
        "jpeg",
        "jpg",
        "m4a",
        "m4v",
        "mid",
        "midi",
        "mkv",
        "mov",
        "mp3",
        "mp4",
        "mpeg",
        "mpg",
        "oga",
        "ogg",
        "opus",
        "png",
        "svg",
        "tif",
        "tiff",
        "ts",
        "wav",
        "webm",
        "webp",
    }
)
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
    if scope is AcquisitionScope.MEDIA_FILES:
        return normalized_extension in MEDIA_EXTENSIONS
    if scope is AcquisitionScope.DOCUMENT_FILES:
        return normalized_extension in DOCUMENT_EXTENSIONS
    if scope is AcquisitionScope.DOWNLOADS_FILES:
        return normalized_path.startswith(("download/", "downloads/"))
    return scope is not AcquisitionScope.METADATA_ONLY


PLAN_SCHEMA_VERSION = "1.0.0"
READINESS_MAX_AGE_MINUTES = 30
