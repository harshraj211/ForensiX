"""Forensic acquisition job handlers package."""

from .breakthrough_suite_handler import handle_breakthrough_suite
from .cve_2024_31317_handler import handle_cve_2024_31317
from .generic_downgrade_handler import get_apk_manifest_info, handle_generic_downgrade
from .nextgen_suite_handler import handle_nextgen_suite
from .non_rooted_handler import handle_non_rooted_suite
from .pin_bruteforce_handler import handle_pin_bruteforce
from .signal_sqlcipher_handler import handle_signal_sqlcipher
from .telegram_caches_handler import handle_telegram_caches
from .tier1_handler import handle_tier1_deep_forensics
from .whatsapp_downgrade_handler import handle_whatsapp_downgrade

__all__ = [
    "get_apk_manifest_info",
    "handle_breakthrough_suite",
    "handle_cve_2024_31317",
    "handle_generic_downgrade",
    "handle_nextgen_suite",
    "handle_non_rooted_suite",
    "handle_pin_bruteforce",
    "handle_signal_sqlcipher",
    "handle_telegram_caches",
    "handle_tier1_deep_forensics",
    "handle_whatsapp_downgrade",
]
