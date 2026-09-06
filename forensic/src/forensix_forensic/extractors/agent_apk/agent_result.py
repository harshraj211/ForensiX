"""Data models for the ForensiX Android agent extraction results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class AgentContact:
    """Extracted contact entry."""

    name: str
    phone_numbers: tuple[str, ...]
    emails: tuple[str, ...]
    account_type: str


@dataclass(frozen=True, slots=True)
class AgentSms:
    """Extracted SMS message."""

    address: str
    body: str
    date_ms: int
    type: int
    thread_id: int


@dataclass(frozen=True, slots=True)
class AgentCallLog:
    """Extracted call log entry."""

    number: str
    type: int
    date_ms: int
    duration_seconds: int
    name: str | None


@dataclass(frozen=True, slots=True)
class AgentInstalledApp:
    """Extracted installed package information and capability surfaces profile."""

    package_name: str
    app_label: str
    version_name: str
    install_time_ms: int
    is_system: bool
    version_code: int = 0
    uid: int = -1
    target_sdk: int = -1
    min_sdk: int = -1
    last_update_time_ms: int = 0
    is_enabled: bool = True
    source_dir: str = ""
    installer_package: str = ""
    is_debuggable: bool = False
    allow_backup: bool = False
    requested_permissions: tuple[str, ...] = ()
    granted_permissions: tuple[str, ...] = ()
    surfaces: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AgentAppArtifact:
    """Extracted accessible application file, backup, or media artifact."""

    package_name: str
    artifact_category: str
    relative_path: str
    absolute_path: str
    size_bytes: int
    last_modified_ms: int
    mime_type: str
    sha256_hash: str
    accessibility_status: str


@dataclass(frozen=True, slots=True)
class AgentDeviceMetadata:
    """Extracted device, system, and runtime metadata collected by the Agent."""

    source: str
    category: str
    collected_at_ms: int
    data: dict[str, Any]
    availability_map: dict[str, str]


@dataclass(frozen=True, slots=True)
class AgentExtractionResult:
    """Container for data extracted via the ForensiX agent APK."""

    extraction_id: str
    device_serial: str
    case_id: str
    contacts: tuple[AgentContact, ...]
    sms_messages: tuple[AgentSms, ...]
    call_logs: tuple[AgentCallLog, ...]
    installed_apps: tuple[AgentInstalledApp, ...]
    media_file_count: int
    output_dir: str
    timeline: list[dict[str, Any]]
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool
    error_message: str | None
    device_metadata: AgentDeviceMetadata | None = None
    app_artifacts: tuple[AgentAppArtifact, ...] = ()


def contacts_from_json(data: list[dict[str, Any]]) -> tuple[AgentContact, ...]:
    """Parse JSON dictionary list into AgentContact objects."""
    res: list[AgentContact] = []
    for item in data:
        res.append(
            AgentContact(
                name=item.get("name", ""),
                phone_numbers=tuple(item.get("phone_numbers", [])),
                emails=tuple(item.get("emails", [])),
                account_type=item.get("account_type", ""),
            )
        )
    return tuple(res)


def sms_from_json(data: list[dict[str, Any]]) -> tuple[AgentSms, ...]:
    """Parse JSON dictionary list into AgentSms objects."""
    res: list[AgentSms] = []
    for item in data:
        res.append(
            AgentSms(
                address=item.get("address", ""),
                body=item.get("body", ""),
                date_ms=item.get("date_ms", 0),
                type=item.get("type", 1),
                thread_id=item.get("thread_id", 0),
            )
        )
    return tuple(res)


def call_logs_from_json(data: list[dict[str, Any]]) -> tuple[AgentCallLog, ...]:
    """Parse JSON dictionary list into AgentCallLog objects."""
    res: list[AgentCallLog] = []
    for item in data:
        res.append(
            AgentCallLog(
                number=item.get("number", ""),
                type=item.get("type", 1),
                date_ms=item.get("date_ms", 0),
                duration_seconds=item.get("duration_seconds", 0),
                name=item.get("name"),
            )
        )
    return tuple(res)


def installed_apps_from_json(data: list[dict[str, Any]]) -> tuple[AgentInstalledApp, ...]:
    """Parse JSON dictionary list into AgentInstalledApp objects."""
    res: list[AgentInstalledApp] = []
    for item in data:
        surfaces = item.get("surfaces")
        surfaces_dict = dict(surfaces) if isinstance(surfaces, dict) else {}
        req_perms = tuple(item.get("requested_permissions", []))
        granted_perms = tuple(item.get("granted_permissions", []))

        res.append(
            AgentInstalledApp(
                package_name=item.get("package_name", ""),
                app_label=item.get("app_label", ""),
                version_name=item.get("version_name", ""),
                install_time_ms=item.get("install_time_ms", 0),
                is_system=item.get("is_system", False),
                version_code=int(item.get("version_code", 0)),
                uid=int(item.get("uid", -1)),
                target_sdk=int(item.get("target_sdk", -1)),
                min_sdk=int(item.get("min_sdk", -1)),
                last_update_time_ms=int(item.get("last_update_time_ms", 0)),
                is_enabled=bool(item.get("is_enabled", True)),
                source_dir=str(item.get("source_dir", "")),
                installer_package=str(item.get("installer_package", "")),
                is_debuggable=bool(item.get("is_debuggable", False)),
                allow_backup=bool(item.get("allow_backup", False)),
                requested_permissions=req_perms,
                granted_permissions=granted_perms,
                surfaces=surfaces_dict,
            )
        )
    return tuple(res)


def app_artifacts_from_json(
    data: list[dict[str, Any]] | None,
) -> tuple[AgentAppArtifact, ...]:
    """Parse JSON dictionary list into AgentAppArtifact objects."""
    res: list[AgentAppArtifact] = []
    if not isinstance(data, list):
        return ()
    for item in data:
        if isinstance(item, dict):
            res.append(
                AgentAppArtifact(
                    package_name=str(item.get("package_name", "unknown")),
                    artifact_category=str(item.get("artifact_category", "shared_storage")),
                    relative_path=str(item.get("relative_path", "")),
                    absolute_path=str(item.get("absolute_path", "")),
                    size_bytes=int(item.get("size_bytes", 0)),
                    last_modified_ms=int(item.get("last_modified_ms", 0)),
                    mime_type=str(item.get("mime_type", "application/octet-stream")),
                    sha256_hash=str(item.get("sha256_hash", "")),
                    accessibility_status=str(item.get("accessibility_status", "available")),
                )
            )
    return tuple(res)


def device_metadata_from_json(data: dict[str, Any] | None) -> AgentDeviceMetadata | None:
    """Parse JSON dictionary into AgentDeviceMetadata object."""
    if not isinstance(data, dict):
        return None

    data_payload = data.get("data")
    if not isinstance(data_payload, dict):
        data_payload = {}

    availability = data.get("availability_map")
    if not isinstance(availability, dict):
        availability = {}

    return AgentDeviceMetadata(
        source=str(data.get("source", "android_agent")),
        category=str(data.get("category", "device_metadata")),
        collected_at_ms=int(data.get("collected_at_ms", 0)),
        data=dict(data_payload),
        availability_map={str(k): str(v) for k, v in availability.items()},
    )
