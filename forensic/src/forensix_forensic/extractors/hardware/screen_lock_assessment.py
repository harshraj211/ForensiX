"""Lock screen passcode assessment and authorised-entry framework.

This module provides a **forensic passcode assessment service** for Android
devices.  It does NOT brute-force the device; instead it:

1.  **Classifies** the lock-screen type (PIN, pattern, password, biometric
    fallback) by reading ``/data/system/locksettings.db`` via ADB root.
2.  **Estimates** the search space size so the examiner can choose an
    offline or chip-off approach for high-entropy credentials.
3.  **Provides an authorised-entry helper** \u2014 when the examiner supplies a
    known passcode, it validates the credential format and guides entry
    via ADB ``input`` events without storing the passcode in logs.
4.  **Applies mandatory safeguards**: wipe-threshold detection, delay
    enforcement between attempts, and a hard stop at the configured
    attempt limit.

Automated high-volume guessing (brute-force) is explicitly out of scope
and is blocked by the :attr:`ScreenLockAssessment.MAX_ATTEMPTS` guard.

References
----------
* Android ``LockSettingsService``:
  ``frameworks/base/services/core/java/com/android/server/locksettings/``
* ADB input event injection:
  ``https://developer.android.com/reference/android/view/KeyEvent``
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum authorised entry attempts before this service self-stops
MAX_ATTEMPTS = 5

# Minimum seconds between two consecutive entry attempts (wipe-risk guard)
MIN_ATTEMPT_INTERVAL_SECONDS = 3.0

# Remote paths
LOCK_SETTINGS_DB = "/data/system/locksettings.db"
GATEKEEPER_DIR = "/data/misc/gatekeeper"
SPBLOB_DIR = "/data/system_de/0/spblob"

# Android KeyguardManager lock types
LOCK_PATTERN = "pattern"
LOCK_PIN = "pin"
LOCK_PASSWORD = "password"  # noqa: S105
LOCK_SWIPE = "swipe"
LOCK_NONE = "none"
LOCK_UNKNOWN = "unknown"

# ADB input keycodes for PIN digit entry
_DIGIT_KEYCODE: dict[str, int] = {
    "0": 7,
    "1": 8,
    "2": 9,
    "3": 10,
    "4": 11,
    "5": 12,
    "6": 13,
    "7": 14,
    "8": 15,
    "9": 16,
}

# Most-common 4-digit PINs (FBI/NIST frequency order, first 20)
COMMON_PINS_4: tuple[str, ...] = (
    "1234",
    "0000",
    "1111",
    "1212",
    "7777",
    "1004",
    "2000",
    "4444",
    "2222",
    "6969",
    "9999",
    "3333",
    "5555",
    "6666",
    "1122",
    "1313",
    "8888",
    "4321",
    "2001",
    "1010",
)

# Most-common 6-digit PINs
COMMON_PINS_6: tuple[str, ...] = (
    "123456",
    "000000",
    "111111",
    "123123",
    "666666",
    "112233",
    "121212",
    "789456",
    "159753",
    "123321",
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class LockType(StrEnum):
    """Android lock screen mechanism type."""

    NONE = "none"
    SWIPE = "swipe"
    PIN = "pin"
    PATTERN = "pattern"
    PASSWORD = "password"  # noqa: S105
    UNKNOWN = "unknown"


class WipeRisk(StrEnum):
    """Wipe risk level based on device settings."""

    LOW = "low"  # no automatic wipe configured
    MEDIUM = "medium"  # MDM policy or 10-attempt wipe
    HIGH = "high"  # Samsung Knox or strict MDM


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LockScreenProfile:
    """Forensic profile of a device's lock screen configuration."""

    lock_type: str
    """One of the :class:`LockType` string values."""

    pin_length: int | None
    """PIN length if determinable (4, 6, or None for variable-length)."""

    pattern_complexity: str | None
    """Pattern complexity hint: ``'low'``, ``'medium'``, ``'high'``, or None."""

    max_failed_attempts: int | None
    """Maximum attempts before wipe (from MDM / DevicePolicyManager)."""

    wipe_risk: str
    """One of the :class:`WipeRisk` string values."""

    biometric_enrolled: bool
    """True if fingerprint or face data is enrolled."""

    search_space_estimate: int
    """Estimated number of unique credentials in the search space."""

    gatekeeper_present: bool
    """True if Gatekeeper (/data/misc/gatekeeper) has enrolled passwords."""

    spblob_present: bool
    """True if synthetic password blob exists (Android 8+)."""

    raw_settings: dict[str, str]
    """Raw locksettings.db key-value pairs for audit trail."""


@dataclass(frozen=True, slots=True)
class AuthorisedEntryResult:
    """Result of an examiner-supervised authorised credential entry attempt."""

    attempt_id: str
    credential_type: str
    unlock_success: bool
    attempts_made: int
    timeline: list[dict[str, str]]
    started_at: str
    finished_at: str
    duration_seconds: float
    error_message: str | None


# ---------------------------------------------------------------------------
# Core service
# ---------------------------------------------------------------------------


class ScreenLockAssessmentService:
    """Forensic lock-screen assessment and authorised-entry service.

    This service provides two capabilities:

    * :meth:`assess` \u2014 Read-only analysis of the lock screen configuration,
      producing a :class:`LockScreenProfile` with search-space estimates.

    * :meth:`authorised_entry` \u2014 When the examiner supplies a passcode
      obtained through lawful means (warrant, device owner consent), this
      method enters it via ADB ``input`` events under strict safeguards.

    Usage::

        svc = ScreenLockAssessmentService(adb=adb_client)
        profile = await svc.assess('emulator-5554', case_id='CASE-001')
        print(profile.lock_type, profile.search_space_estimate)
    """

    MAX_ATTEMPTS = MAX_ATTEMPTS

    def __init__(self, adb: Any = None, output_dir: Path | None = None) -> None:
        self._adb: Any = adb
        self._output_dir = output_dir
        self._attempt_count = 0
        self._last_attempt_time: float = 0.0
        self._timeline: list[dict[str, str]] = []

    @classmethod
    def assess_from_parameters(
        cls,
        lock_type: LockType | str,
        pin_length: int = 0,
        pattern_size: int = 0,
        has_biometrics: bool = False,
        device_rooted: bool = False,
    ) -> LockScreenProfile:
        """Create a LockScreenProfile directly from specified parameters."""
        lock_enum = LockType(lock_type) if isinstance(lock_type, str) else lock_type
        pattern_str = str(pattern_size) if pattern_size else "3x3"
        search_space = _estimate_search_space(lock_enum.value, pin_length, pattern_str)
        return LockScreenProfile(
            lock_type=lock_enum.value,
            pin_length=pin_length,
            pattern_complexity=pattern_str,
            max_failed_attempts=MAX_ATTEMPTS,
            wipe_risk=WipeRisk.LOW,
            biometric_enrolled=has_biometrics,
            search_space_estimate=search_space,
            gatekeeper_present=device_rooted,
            spblob_present=device_rooted,
            raw_settings={},
        )

    # ------------------------------------------------------------------
    # Public: assess
    # ------------------------------------------------------------------

    async def assess(self, serial: str, case_id: str) -> LockScreenProfile:
        """Read lock screen settings and build a forensic profile.

        Reads ``/data/system/locksettings.db`` via ``su -c`` and checks for
        Gatekeeper / spblob directories to classify the credential type.

        Parameters
        ----------
        serial:
            ADB device serial.
        case_id:
            Case identifier logged in the timeline.

        Returns
        -------
        LockScreenProfile
            Frozen profile with lock type, search space estimate, and
            wipe-risk classification.
        """
        self._log("assess_start", {"serial": serial, "case_id": case_id})
        settings = await self._read_lock_settings(serial)
        lock_type = self._classify_lock_type(settings)
        pin_length = self._detect_pin_length(settings)
        pattern_complexity = self._classify_pattern(settings)
        max_attempts = self._detect_max_attempts(settings)
        wipe_risk = self._classify_wipe_risk(max_attempts, settings)
        biometric = await self._check_biometric(serial)
        search_space = _estimate_search_space(lock_type, pin_length, pattern_complexity)
        gk_present = await self._path_exists(serial, GATEKEEPER_DIR)
        spblob_present = await self._path_exists(serial, SPBLOB_DIR)

        self._log(
            "assess_complete",
            {
                "lock_type": lock_type,
                "pin_length": str(pin_length),
                "wipe_risk": wipe_risk,
                "search_space": str(search_space),
            },
        )

        return LockScreenProfile(
            lock_type=lock_type,
            pin_length=pin_length,
            pattern_complexity=pattern_complexity,
            max_failed_attempts=max_attempts,
            wipe_risk=wipe_risk,
            biometric_enrolled=biometric,
            search_space_estimate=search_space,
            gatekeeper_present=gk_present,
            spblob_present=spblob_present,
            raw_settings=settings,
        )

    # ------------------------------------------------------------------
    # Public: authorised_entry
    # ------------------------------------------------------------------

    async def authorised_entry(
        self,
        serial: str,
        credential: str,
        credential_type: str,
        case_id: str,
        operator_id: str,
    ) -> AuthorisedEntryResult:
        """Enter a known passcode via ADB input events under strict safeguards.

        This method is for **authorised credential entry only** \u2014 not
        high-volume automated guessing.  It enforces:

        * Hard stop after :attr:`MAX_ATTEMPTS` total calls.
        * Minimum :data:`MIN_ATTEMPT_INTERVAL_SECONDS` between attempts.
        * Credential is never written to the timeline log.

        Parameters
        ----------
        serial:
            ADB device serial.
        credential:
            The passcode to enter (PIN digits or password string).
            **Not logged.**
        credential_type:
            ``'pin'`` or ``'password'``.
        case_id:
            Case identifier for chain-of-custody.
        operator_id:
            Examiner identity for audit trail.

        Returns
        -------
        AuthorisedEntryResult
            Outcome of the entry attempt.
        """
        attempt_id = str(uuid4())
        started_at = datetime.now(UTC).isoformat()
        t0 = asyncio.get_event_loop().time()

        self._log(
            "authorised_entry_start",
            {
                "attempt_id": attempt_id,
                "case_id": case_id,
                "operator_id": operator_id,
                "credential_type": credential_type,
                "attempt_number": str(self._attempt_count + 1),
            },
        )

        # Safeguard: attempt limit
        if self._attempt_count >= self.MAX_ATTEMPTS:
            return AuthorisedEntryResult(
                attempt_id=attempt_id,
                credential_type=credential_type,
                unlock_success=False,
                attempts_made=self._attempt_count,
                timeline=list(self._timeline),
                started_at=started_at,
                finished_at=datetime.now(UTC).isoformat(),
                duration_seconds=0.0,
                error_message=(
                    f"Attempt limit reached ({self.MAX_ATTEMPTS}). "
                    "Use offline analysis for further investigation."
                ),
            )

        # Safeguard: minimum interval
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_attempt_time
        if elapsed < MIN_ATTEMPT_INTERVAL_SECONDS:
            await asyncio.sleep(MIN_ATTEMPT_INTERVAL_SECONDS - elapsed)

        # Perform entry
        success = False
        error_msg: str | None = None
        try:
            if credential_type == "pin":
                await self._enter_pin(serial, credential)
            elif credential_type == "password":
                await self._enter_text(serial, credential)
            else:
                raise ValueError(f"Unknown credential_type: {credential_type!r}")

            # Check unlock by reading window dump
            success = await self._verify_unlock(serial)
        except Exception as exc:  # noqa: BLE001
            error_msg = str(exc)

        self._attempt_count += 1
        self._last_attempt_time = asyncio.get_event_loop().time()

        finished_at = datetime.now(UTC).isoformat()
        duration = asyncio.get_event_loop().time() - t0

        self._log(
            "authorised_entry_result",
            {
                "attempt_id": attempt_id,
                "success": str(success),
                "attempts_total": str(self._attempt_count),
            },
        )

        return AuthorisedEntryResult(
            attempt_id=attempt_id,
            credential_type=credential_type,
            unlock_success=success,
            attempts_made=self._attempt_count,
            timeline=list(self._timeline),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(duration, 3),
            error_message=error_msg,
        )

    # ------------------------------------------------------------------
    # ADB helpers
    # ------------------------------------------------------------------

    async def _read_lock_settings(self, serial: str) -> dict[str, str]:
        """Pull lock settings from ``locksettings.db`` via ADB root."""
        settings: dict[str, str] = {}
        try:
            cmd = (
                f'su -c "sqlite3 {LOCK_SETTINGS_DB} '  # noqa: S608
                "'SELECT name,value FROM locksettings;'\""
            )
            output = await self._adb.shell(serial, cmd)
            for line in output.splitlines():
                if "|" in line:
                    key, _, value = line.partition("|")
                    settings[key.strip()] = value.strip()
        except Exception:  # noqa: BLE001, S110
            pass
        return settings

    async def _check_biometric(self, serial: str) -> bool:
        """Check if biometric data is enrolled."""
        try:
            output = await self._adb.shell(
                serial,
                "su -c 'ls /data/vendor_de/0/fpdata/ 2>/dev/null || echo EMPTY'",
            )
            return bool(output.strip()) and "EMPTY" not in output
        except Exception:  # noqa: BLE001
            return False

    async def _path_exists(self, serial: str, path: str) -> bool:
        """Return True if *path* exists on the device."""
        try:
            output = await self._adb.shell(serial, f"su -c '[ -e {path} ] && echo YES || echo NO'")
            return "YES" in output
        except Exception:  # noqa: BLE001
            return False

    async def _enter_pin(self, serial: str, pin: str) -> None:
        """Enter PIN digits via ADB input keycodes."""
        # Wake + swipe up to reveal PIN entry
        await self._adb.shell(serial, "input keyevent KEYCODE_WAKEUP")
        await asyncio.sleep(0.5)
        await self._adb.shell(serial, "input keyevent KEYCODE_MENU")
        await asyncio.sleep(0.3)
        for digit in pin:
            keycode = _DIGIT_KEYCODE.get(digit)
            if keycode is not None:
                await self._adb.shell(serial, f"input keyevent {keycode}")
                await asyncio.sleep(0.05)
        await self._adb.shell(serial, "input keyevent KEYCODE_ENTER")

    async def _enter_text(self, serial: str, text: str) -> None:
        """Enter a text password via ADB input text command."""
        await self._adb.shell(serial, "input keyevent KEYCODE_WAKEUP")
        await asyncio.sleep(0.5)
        await self._adb.shell(serial, "input keyevent KEYCODE_MENU")
        await asyncio.sleep(0.3)
        safe = text.replace(" ", "%s").replace("'", "\\'")
        await self._adb.shell(serial, f"input text '{safe}'")
        await asyncio.sleep(0.1)
        await self._adb.shell(serial, "input keyevent KEYCODE_ENTER")

    async def _verify_unlock(self, serial: str) -> bool:
        """Check if the device is unlocked by inspecting window dump."""
        try:
            output = await self._adb.shell(
                serial,
                "dumpsys window | grep -E 'mDreamingLockscreen|mShowingLockscreen'",
            )
            # mShowingLockscreen=false and mDreamingLockscreen=false = unlocked
            return "mShowingLockscreen=false" in output and "mDreamingLockscreen=false" in output
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------

    def _classify_lock_type(self, settings: dict[str, str]) -> str:
        lock_type_raw = settings.get("lockscreen.password_type", "0")
        try:
            val = int(lock_type_raw)
        except ValueError:
            return LockType.UNKNOWN
        # Android DevicePolicyManager password quality constants
        if val == 0:
            return LockType.NONE
        if val == 65536:
            return LockType.SWIPE
        if val == 131072:
            return LockType.PATTERN
        if val in (196608, 262144):
            return LockType.PIN
        if val >= 327680:
            return LockType.PASSWORD
        return LockType.UNKNOWN

    def _detect_pin_length(self, settings: dict[str, str]) -> int | None:
        min_len = settings.get("lockscreen.password_min_length", "")
        max_len = settings.get("lockscreen.password_max_length", "")
        try:
            mn, mx = int(min_len), int(max_len)
            return mn if mn == mx else None
        except ValueError:
            return None

    def _classify_pattern(self, settings: dict[str, str]) -> str | None:
        visible = settings.get("lockscreen.patternvisible", "1") == "1"
        error_val = settings.get("lockscreen.pattern_ever_chosen", "0")
        if error_val == "0":
            return None
        # Rough complexity based on visible / recorded error count
        return "low" if visible else "medium"

    def _detect_max_attempts(self, settings: dict[str, str]) -> int | None:
        val = settings.get("lockscreen.lockoutattempt", "")
        try:
            return int(val) if val else None
        except ValueError:
            return None

    @staticmethod
    def _classify_wipe_risk(max_attempts: int | None, settings: dict[str, str]) -> str:
        if max_attempts is not None and max_attempts <= 5:
            return WipeRisk.HIGH
        if "knox" in str(settings).lower():
            return WipeRisk.HIGH
        if max_attempts is not None and max_attempts <= 10:
            return WipeRisk.MEDIUM
        return WipeRisk.LOW

    def _log(self, event: str, details: dict[str, str]) -> None:
        self._timeline.append({"ts": datetime.now(UTC).isoformat(), "event": event, **details})


# ---------------------------------------------------------------------------
# Search space estimation
# ---------------------------------------------------------------------------


def _estimate_search_space(
    lock_type: str, pin_length: int | None, pattern_complexity: str | None
) -> int:
    """Estimate the number of unique credentials in the search space.

    These are *upper bounds* for display purposes; actual space may be
    smaller due to user behaviour (common PINs, low-complexity patterns).
    """
    if lock_type in (LockType.NONE, LockType.SWIPE):
        return 0
    if lock_type == LockType.PIN:
        length = pin_length or 4
        return int(10**length)
    if lock_type == LockType.PATTERN:
        # 3x3 grid: ~389,112 valid patterns; 3-9 nodes
        return 389_112
    if lock_type == LockType.PASSWORD:
        # Estimated average: 8-char alphanumeric space
        return 62**8
    return 0
