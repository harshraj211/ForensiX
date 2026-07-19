"""Evidence Twin source classifications and integrity constants."""

from enum import StrEnum

DEFAULT_EVIDENCE_CHUNK_SIZE = 4 * 1024 * 1024
MIN_EVIDENCE_CHUNK_SIZE = 1024 * 1024
MAX_EVIDENCE_CHUNK_SIZE = 64 * 1024 * 1024
MINIMUM_FREE_BYTES = 256 * 1024 * 1024


class EvidenceSourceType(StrEnum):
    IMPORTED_FILE = "imported_file"
    LOGICAL_ADB = "logical_adb"
    ROOTED_FILESYSTEM = "rooted_filesystem"
    PHYSICAL_BLOCK = "physical_block"


class AcquisitionLevel(StrEnum):
    LOGICAL = "logical"
    SELECTIVE = "selective"
    FILESYSTEM = "filesystem"
    PHYSICAL = "physical"


class EvidenceContainerFormat(StrEnum):
    RAW = "raw"
    IMG = "img"
    DD = "dd"
    TAR = "tar"
    ZIP = "zip"
    DIRECTORY_BUNDLE = "directory_bundle"
    UNKNOWN = "unknown"


FORMAT_BY_SUFFIX = {
    ".dd": EvidenceContainerFormat.DD,
    ".img": EvidenceContainerFormat.IMG,
    ".raw": EvidenceContainerFormat.RAW,
    ".tar": EvidenceContainerFormat.TAR,
    ".zip": EvidenceContainerFormat.ZIP,
}
