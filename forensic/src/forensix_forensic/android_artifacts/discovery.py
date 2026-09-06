"""Generic Application Artifact Discovery Layer.

Scans acquired directories, archives, and Agent artifact manifests to produce a
structured inventory of present applications, acquired files, matching adapters,
readability status, and encryption state.
"""

# ruff: noqa: E501


from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensix_forensic.evidence_io import ParserRegistry

from .adapter import AdapterParseStatus


@dataclass(frozen=True, slots=True)
class DiscoveredArtifactSummary:
    package_name: str
    application_name: str
    artifact_path: str
    adapter_id: str | None
    readable_status: str  # readable, encrypted, unsupported, corrupted, partially_recovered
    parse_status: AdapterParseStatus | str
    is_encrypted: bool
    size_bytes: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ApplicationInventorySummary:
    total_applications_found: int = 0
    total_artifacts_found: int = 0
    discovered_artifacts: list[DiscoveredArtifactSummary] = field(default_factory=list)
    applications_by_package: dict[str, list[DiscoveredArtifactSummary]] = field(default_factory=dict)

    def add_artifact(self, summary: DiscoveredArtifactSummary) -> None:
        self.discovered_artifacts.append(summary)
        if summary.package_name not in self.applications_by_package:
            self.applications_by_package[summary.package_name] = []
        self.applications_by_package[summary.package_name].append(summary)
        self.total_artifacts_found = len(self.discovered_artifacts)
        self.total_applications_found = len(self.applications_by_package)


KNOWN_APP_PACKAGES = {
    "com.whatsapp": "WhatsApp",
    "org.telegram.messenger": "Telegram",
    "org.thoughtcrime.securesms": "Signal",
    "com.snapchat.android": "Snapchat",
    "com.discord": "Discord",
    "com.zhiliaoapp.musically": "TikTok",
    "com.google.android.gm": "Gmail",
    "com.tencent.mm": "WeChat",
    "com.facebook.orca": "Messenger",
    "com.facebook.katana": "Facebook",
    "com.instagram.android": "Instagram",
    "com.android.providers.contacts": "Android Contacts Provider",
    "com.android.providers.telephony": "Android Telephony Provider",
    "com.android.providers.calllog": "Android Call Log Provider",
}


class ApplicationArtifactDiscoveryService:
    """Discovers application artifacts in extracted directory bundles or Agent manifests."""

    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self.registry = registry

    def discover_directory(self, root_dir: Path) -> ApplicationInventorySummary:
        inventory = ApplicationInventorySummary()
        if not root_dir.exists():
            return inventory

        # Scan for matching SQLite DBs and manifest files
        for path in root_dir.rglob("*"):
            if not path.is_file():
                continue

            name = path.name.lower()
            rel_str = str(path.relative_to(root_dir))

            # Package identification hint
            pkg = "unknown"
            app_name = "Unknown Application"
            for known_pkg, known_name in KNOWN_APP_PACKAGES.items():
                if known_pkg in rel_str.lower() or known_name.lower() in rel_str.lower():
                    pkg = known_pkg
                    app_name = known_name
                    break

            if pkg == "unknown":
                if "msgstore" in name or "wa.db" in name:
                    pkg = "com.whatsapp"
                    app_name = "WhatsApp"
                elif "cache4.db" in name or "userconf.xml" in name:
                    pkg = "org.telegram.messenger"
                    app_name = "Telegram"
                elif "signal" in name or "securesms" in rel_str.lower():
                    pkg = "org.thoughtcrime.securesms"
                    app_name = "Signal"
                elif "contacts2.db" in name:
                    pkg = "com.android.providers.contacts"
                    app_name = "Android Contacts Provider"
                elif "calllog.db" in name:
                    pkg = "com.android.providers.calllog"
                    app_name = "Android Call Log Provider"
                elif "mmssms.db" in name or "telephony.db" in name:
                    pkg = "com.android.providers.telephony"
                    app_name = "Android Telephony Provider"

            if pkg == "unknown" and not name.endswith(".db"):
                continue

            # Readability & encryption check
            is_encrypted = False
            readable_status = "readable"
            parse_status: AdapterParseStatus = AdapterParseStatus.SUPPORTED

            if any(ext in name for ext in ("crypt12", "crypt14", "crypt15")):
                is_encrypted = True
                readable_status = "encrypted"
                parse_status = AdapterParseStatus.ENCRYPTED_UNPARSED
            elif name.endswith(".db"):
                try:
                    with path.open("rb") as f:
                        header = f.read(16)
                        if header.startswith(b"SQLite format 3\x00"):
                            readable_status = "readable"
                            parse_status = AdapterParseStatus.SUPPORTED
                        elif header and not header.startswith(b"SQLite format 3\x00"):
                            is_encrypted = True
                            readable_status = "encrypted"
                            parse_status = AdapterParseStatus.ENCRYPTED_UNPARSED
                except Exception:
                    readable_status = "corrupted"
                    parse_status = AdapterParseStatus.CORRUPTED

            adapter_id = None
            if self.registry:
                candidates = self.registry.compatible(frozenset(), source_locator=rel_str)
                if candidates:
                    adapter_id = candidates[0].metadata.parser_id

            inventory.add_artifact(
                DiscoveredArtifactSummary(
                    package_name=pkg,
                    application_name=app_name,
                    artifact_path=rel_str,
                    adapter_id=adapter_id,
                    readable_status=readable_status,
                    parse_status=parse_status,
                    is_encrypted=is_encrypted,
                    size_bytes=path.stat().st_size if path.exists() else 0,
                )
            )

        return inventory
