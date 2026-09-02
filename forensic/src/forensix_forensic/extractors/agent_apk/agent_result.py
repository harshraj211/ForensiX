"""Data models for the ForensiX Android agent extraction results."""

from __future__ import annotations

from dataclasses import dataclass
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
    """Extracted installed package information."""

    package_name: str
    app_label: str
    version_name: str
    install_time_ms: int
    is_system: bool


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
        res.append(
            AgentInstalledApp(
                package_name=item.get("package_name", ""),
                app_label=item.get("app_label", ""),
                version_name=item.get("version_name", ""),
                install_time_ms=item.get("install_time_ms", 0),
                is_system=item.get("is_system", False),
            )
        )
    return tuple(res)
