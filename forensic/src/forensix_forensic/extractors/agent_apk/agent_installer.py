"""ForensiX Android agent APK installer and session manager.

Installs the forensix_agent.apk onto an unrooted Android device via ADB,
grants required permissions via ``adb shell pm grant``, and starts the
extraction foreground service via an ADB intent.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forensix_forensic.adb.client import AdbClient


@dataclass(frozen=True, slots=True)
class AgentInstallerConfig:
    """Configuration options for the Agent APK installer."""

    apk_path: Path
    package_name: str = "com.forensix.agent"
    output_staging_dir_on_device: str = "/sdcard/forensix_out"
    install_timeout_seconds: int = 60
    start_timeout_seconds: int = 10


@dataclass(frozen=True, slots=True)
class InstallResult:
    """Sealed result of an agent installation operation."""

    installed: bool
    package_name: str
    apk_sha256: str
    timeline: list[dict[str, str]]
    error_message: str | None


class AgentInstaller:
    """Manages installation, permission granting, and launching of the ForensiX Agent APK."""

    def __init__(self, adb: AdbClient, config: AgentInstallerConfig) -> None:
        self._adb = adb
        self._cfg = config
        self._timeline: list[dict[str, str]] = []

    async def install(self, serial: str) -> InstallResult:
        """Install APK on device and grant required permissions."""
        self._log("install_start", {"serial": serial, "apk_path": str(self._cfg.apk_path)})
        try:
            if not self._cfg.apk_path.exists():
                raise FileNotFoundError(f"Agent APK not found at: {self._cfg.apk_path}")

            sha = hashlib.sha256(self._cfg.apk_path.read_bytes()).hexdigest()

            # Install APK via ADB
            await self._adb.shell(serial, f"pm install -r {self._cfg.apk_path}")  # type: ignore[attr-defined]

            # Grant permissions
            permissions = [
                "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS",
                "android.permission.READ_CALL_LOG",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.READ_MEDIA_IMAGES",
                "android.permission.READ_MEDIA_VIDEO",
            ]

            for perm in permissions:
                try:
                    await self._adb.shell(  # type: ignore[attr-defined]
                        serial, f"pm grant {self._cfg.package_name} {perm}"
                    )
                except Exception:  # noqa: BLE001, S112
                    continue

            # Create staging dir
            await self._adb.shell(  # type: ignore[attr-defined]
                serial, f"mkdir -p {self._cfg.output_staging_dir_on_device}"
            )

            self._log("install_success", {"package": self._cfg.package_name, "sha256": sha})
            return InstallResult(
                installed=True,
                package_name=self._cfg.package_name,
                apk_sha256=sha,
                timeline=list(self._timeline),
                error_message=None,
            )

        except Exception as exc:  # noqa: BLE001
            self._log("install_error", {"error": str(exc)})
            return InstallResult(
                installed=False,
                package_name=self._cfg.package_name,
                apk_sha256="",
                timeline=list(self._timeline),
                error_message=str(exc),
            )

    async def start_extraction(self, serial: str, case_id: str) -> bool:
        """Trigger the foreground extraction service via AM broadcast/start."""
        self._log("start_service", {"serial": serial, "case_id": case_id})
        try:
            cmd = (
                f"am start-foreground-service -n {self._cfg.package_name}/.AgentService "
                f"--es case_id {case_id}"
            )
            await self._adb.shell(serial, cmd)  # type: ignore[attr-defined]
            return True
        except Exception as exc:  # noqa: BLE001
            self._log("start_service_failed", {"error": str(exc)})
            return False

    async def uninstall(self, serial: str) -> bool:
        """Uninstall agent APK from device post-collection."""
        self._log("uninstall", {"serial": serial})
        try:
            await self._adb.shell(serial, f"pm uninstall {self._cfg.package_name}")  # type: ignore[attr-defined]
            return True
        except Exception as exc:  # noqa: BLE001
            self._log("uninstall_failed", {"error": str(exc)})
            return False

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append({
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **details,
        })
