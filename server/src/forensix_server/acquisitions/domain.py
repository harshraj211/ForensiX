"""Frozen acquisition scope and module catalog."""

from enum import StrEnum


class AcquisitionScope(StrEnum):
    METADATA_ONLY = "metadata_only"
    QUICK_TRIAGE = "quick_triage"
    SHARED_STORAGE_INVENTORY = "shared_storage_inventory"
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
    AcquisitionScope.CUSTOM: (),
}

PLAN_SCHEMA_VERSION = "1.0.0"
READINESS_MAX_AGE_MINUTES = 30
