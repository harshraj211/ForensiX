"""Hardware-level forensic acquisition modules for ForensiX.

Provides chipset-specific physical acquisition protocol handlers:

* :mod:`.chipset_detector` — USB VID/PID + ADB property-based chipset detection
* :mod:`.mtk_brom` — MediaTek BROM / SP Flash Tool protocol
* :mod:`.qualcomm_edl` — Qualcomm EDL / Sahara / Firehose protocol
* :mod:`.unisoc_fdl` — Unisoc / Spreadtrum FDL1/FDL2 protocol
* :mod:`.samsung_download` — Samsung Odin / LOKE Download Mode + PIT parser
* :mod:`.physical_acquisition` — Top-level auto-routing pipeline
* :mod:`.screen_lock_assessment` — Lock screen forensic assessment service
* :mod:`.keystore_reader` — Android Keystore key blob metadata inspector
"""

from .chipset_detector import (
    USB_CHIPSET_MAP,
    ChipsetFamily,
    ChipsetProbe,
    detect_chipset_from_adb,
    detect_chipset_from_usb,
)
from .hashcat_launcher import (
    HashcatConfig,
    HashcatJobResult,
    HashcatLauncher,
    HashcatMode,
)
from .keystore_reader import (
    KeyBlobMetadata,
    KeystoreExtractor,
    KeystoreInspectionResult,
    parse_keyblob_header,
)
from .kirin_hisi import (
    KirinAcquisitionResult,
    KirinChipset,
    KirinExtractor,
    KirinPartitionInfo,
    KirinState,
    build_erecovery_packet,
    parse_partition_table,
    verify_erecovery_handshake,
)
from .mtk_brom import (
    BromProtocolError,
    MtkBromAcquisitionResult,
    MtkBromExtractor,
    MtkBromState,
    MtkChipset,
    MtkPartitionInfo,
    build_read_command,
    parse_flash_id_response,
    verify_handshake_echo,
)
from .offline_hash_extractor import (
    GatekeeperBlob,
    HashDump,
    OfflineHashExtractor,
    SpblobFile,
)
from .physical_acquisition import (
    PhysicalAcquisitionRouter,
    PhysicalAcquisitionRouterResult,
    RouterConfig,
)
from .qualcomm_edl import (
    FirehosePartitionInfo,
    QualcommEdlAcquisitionResult,
    QualcommEdlExtractor,
    SaharaHello,
    build_firehose_configure,
    build_firehose_getpartitiontable,
    build_firehose_read,
    build_sahara_hello_response,
    decode_sahara_hello,
    parse_firehose_response,
)
from .rockchip_rkdfu import (
    RkChipset,
    RkPartitionEntry,
    RkState,
    RockchipAcquisitionResult,
    RockchipExtractor,
    build_rk_command,
    parse_rk_flash_id,
    parse_rk_partition_table,
)
from .samsung_download import (
    OdinState,
    PitRecord,
    SamsungDownloadModeExtractor,
    SamsungDownloadModeResult,
    build_odin_packet,
    parse_pit,
)
from .screen_lock_assessment import (
    AuthorisedEntryResult,
    LockScreenProfile,
    LockType,
    ScreenLockAssessmentService,
    WipeRisk,
    _estimate_search_space,
)
from .unisoc_fdl import (
    FdlPartitionEntry,
    FdlState,
    SpreadtrumBootromExtractor,
    UnisocFdlAcquisitionResult,
    build_fdl_packet,
    build_read_partition_cmd,
    hdlc_decode,
    hdlc_encode,
)

__all__ = [
    # Chipset detector
    "ChipsetFamily",
    "ChipsetProbe",
    "USB_CHIPSET_MAP",
    "detect_chipset_from_adb",
    "detect_chipset_from_usb",
    # Kirin & Rockchip
    "KirinAcquisitionResult",
    "KirinChipset",
    "KirinExtractor",
    "KirinPartitionInfo",
    "KirinState",
    "RkChipset",
    "RkPartitionEntry",
    "RkState",
    "RockchipAcquisitionResult",
    "RockchipExtractor",
    "build_erecovery_packet",
    "build_rk_command",
    "parse_partition_table",
    "parse_rk_flash_id",
    "parse_rk_partition_table",
    "verify_erecovery_handshake",
    # Offline Hash & Hashcat
    "GatekeeperBlob",
    "HashDump",
    "HashcatConfig",
    "HashcatJobResult",
    "HashcatLauncher",
    "HashcatMode",
    "OfflineHashExtractor",
    "SpblobFile",
    # Keystore reader
    "KeyBlobMetadata",
    "KeystoreExtractor",
    "KeystoreInspectionResult",
    "parse_keyblob_header",
    # MTK BROM
    "BromProtocolError",
    "MtkBromAcquisitionResult",
    "MtkBromExtractor",
    "MtkBromState",
    "MtkChipset",
    "MtkPartitionInfo",
    "build_read_command",
    "parse_flash_id_response",
    "verify_handshake_echo",
    # Physical acquisition router
    "PhysicalAcquisitionRouter",
    "PhysicalAcquisitionRouterResult",
    "RouterConfig",
    # Qualcomm EDL
    "FirehosePartitionInfo",
    "QualcommEdlAcquisitionResult",
    "QualcommEdlExtractor",
    "SaharaHello",
    "build_firehose_configure",
    "build_firehose_getpartitiontable",
    "build_firehose_read",
    "build_sahara_hello_response",
    "decode_sahara_hello",
    "parse_firehose_response",
    # Samsung Download Mode
    "OdinState",
    "PitRecord",
    "SamsungDownloadModeExtractor",
    "SamsungDownloadModeResult",
    "build_odin_packet",
    "parse_pit",
    # Screen lock assessment
    "AuthorisedEntryResult",
    "LockScreenProfile",
    "LockType",
    "ScreenLockAssessmentService",
    "WipeRisk",
    "_estimate_search_space",
    # Unisoc FDL
    "FdlPartitionEntry",
    "FdlState",
    "SpreadtrumBootromExtractor",
    "UnisocFdlAcquisitionResult",
    "build_fdl_packet",
    "build_read_partition_cmd",
    "hdlc_decode",
    "hdlc_encode",
]
