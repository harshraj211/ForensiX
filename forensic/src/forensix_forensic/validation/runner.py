"""Policy-bounded validation runner for mock and controlled physical devices."""

import asyncio
import hashlib
import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forensix_forensic.adb import AdbClient, DeviceState, SharedStorageRoot

from .models import (
    SealedValidationReport,
    ValidationCheck,
    ValidationEnvironment,
    ValidationOutcome,
    ValidationReport,
    ValidationStatus,
)

TOOL_VERSION = "0.1.0"


async def run_adb_validation(
    client: AdbClient,
    *,
    mode: str,
    selected_serial: str | None = None,
) -> SealedValidationReport:
    """Run non-content ADB checks and a repeatability probe over bounded path metadata."""
    if mode not in {"mock", "system"}:
        raise ValueError("Validation mode must be mock or system.")
    started_at = datetime.now(UTC)
    checks: list[ValidationCheck] = []
    adb_version: str | None = None
    adb_executable_sha256: str | None = None
    serial_hash: str | None = None
    android_release: str | None = None
    android_sdk: str | None = None
    fingerprint_hash: str | None = None

    try:
        server = await client.server_info()
        adb_version = server.version
        executable = Path(server.executable_path)
        if mode == "system" and await asyncio.to_thread(executable.is_file):
            adb_executable_sha256 = await asyncio.to_thread(_hash_file, executable)
        checks.append(
            _check(
                "adb_server",
                ValidationStatus.SUCCEEDED,
                "ADB responded and its version was parsed.",
                version=server.version,
                executable_hashed=adb_executable_sha256 is not None,
            )
        )

        transports = await client.list_transports()
        counts = {state.value: 0 for state in DeviceState}
        for transport in transports:
            counts[transport.state.value] += 1
        checks.append(
            _check(
                "transport_enumeration",
                ValidationStatus.SUCCEEDED if transports else ValidationStatus.WARNING,
                "ADB transport states were classified without retaining raw serials.",
                total=len(transports),
                authorized=counts[DeviceState.AUTHORIZED.value],
                unauthorized=counts[DeviceState.UNAUTHORIZED.value],
                offline=counts[DeviceState.OFFLINE.value],
            )
        )

        selected = next(
            (
                transport
                for transport in transports
                if transport.state is DeviceState.AUTHORIZED
                and (selected_serial is None or transport.serial == selected_serial)
            ),
            None,
        )
        if selected is None:
            reason = (
                "The selected serial was not an authorized transport."
                if selected_serial
                else "No authorized transport was available."
            )
            checks.append(_check("authorized_device", ValidationStatus.SKIPPED, reason))
        else:
            serial_hash = _hash_text(selected.serial)
            checks.append(
                _check(
                    "authorized_device",
                    ValidationStatus.SUCCEEDED,
                    "One authorized device was selected using a redacted identity.",
                    model=selected.model,
                )
            )
            properties = await client.get_properties(selected.serial)
            android_release = properties.get("ro.build.version.release")
            android_sdk = properties.get("ro.build.version.sdk")
            fingerprint = properties.get("ro.build.fingerprint")
            fingerprint_hash = _hash_text(fingerprint) if fingerprint else None
            required = {
                "release": android_release,
                "sdk": android_sdk,
                "fingerprint": fingerprint_hash,
                "security_patch": properties.get("ro.build.version.security_patch"),
            }
            missing = sum(value is None for value in required.values())
            checks.append(
                _check(
                    "device_properties",
                    ValidationStatus.SUCCEEDED if missing == 0 else ValidationStatus.WARNING,
                    "Core build properties were collected and identifiers were redacted.",
                    fields_observed=len(required) - missing,
                    fields_expected=len(required),
                )
            )

            packages = await client.list_packages(selected.serial)
            checks.append(
                _check(
                    "package_inventory",
                    ValidationStatus.SUCCEEDED,
                    (
                        "Package identifiers were counted; package names were not stored in the "
                        "report."
                    ),
                    package_count=len(packages),
                )
            )

            root_probe = await client.probe_root_access(selected.serial)
            checks.append(
                _check(
                    "root_capability",
                    ValidationStatus.SUCCEEDED,
                    "Root capability was classified without changing the access mode.",
                    root_status=root_probe.status.value,
                    reason_code=root_probe.reason_code,
                )
            )

            storage_probes = await client.probe_shared_storage(selected.serial)
            readable = [probe for probe in storage_probes if probe.readable]
            checks.append(
                _check(
                    "shared_storage_probe",
                    ValidationStatus.SUCCEEDED if readable else ValidationStatus.WARNING,
                    "Approved shared-storage roots were probed without reading file contents.",
                    roots_observed=len(storage_probes),
                    roots_readable=len(readable),
                )
            )
            if readable:
                root = SharedStorageRoot(readable[0].root_id)
                first = await client.inventory_shared_storage(selected.serial, root)
                second = await client.inventory_shared_storage(selected.serial, root)
                first_digest = _inventory_digest(first.model_dump(mode="json"))
                second_digest = _inventory_digest(second.model_dump(mode="json"))
                repeatable = first_digest == second_digest
                checks.append(
                    _check(
                        "inventory_repeatability",
                        ValidationStatus.SUCCEEDED if repeatable else ValidationStatus.WARNING,
                        (
                            "Two immediate bounded inventories produced the same canonical digest."
                            if repeatable
                            else (
                                "The device inventory changed between repetitions; review device "
                                "activity."
                            )
                        ),
                        repeatable=repeatable,
                        first_count=first.discovered_count,
                        second_count=second.discovered_count,
                        first_manifest_sha256=first_digest,
                        second_manifest_sha256=second_digest,
                    )
                )
            else:
                checks.append(
                    _check(
                        "inventory_repeatability",
                        ValidationStatus.SKIPPED,
                        "No readable approved root was available for repeatability testing.",
                    )
                )
    except Exception as error:  # Validation must preserve a sealed failure record.
        checks.append(
            _check(
                "validation_runtime",
                ValidationStatus.FAIL,
                "The validation run stopped safely after an operational error.",
                error_type=type(error).__name__,
            )
        )

    report = ValidationReport(
        run_id=str(uuid4()),
        started_at=started_at,
        completed_at=datetime.now(UTC),
        tool_version=TOOL_VERSION,
        mode=mode,
        outcome=_outcome(checks),
        environment=ValidationEnvironment(
            operating_system=platform.system() or "unknown",
            operating_system_release=platform.release() or "unknown",
            machine=platform.machine() or "unknown",
            python_version=platform.python_version(),
        ),
        adb_version=adb_version,
        adb_executable_sha256=adb_executable_sha256,
        device_serial_sha256=serial_hash,
        android_release=android_release,
        android_sdk=android_sdk,
        build_fingerprint_sha256=fingerprint_hash,
        checks=tuple(checks),
        limitations=(
            (
                "This record validates observed behavior only; it does not prove evidentiary "
                "admissibility."
            ),
            "ADB is not a hardware write blocker and may cause device-side effects.",
            "A passing mock run is software regression evidence, not physical-device validation.",
            "Inventory repeatability does not prove completeness or access to private app data.",
        ),
    )
    return SealedValidationReport(report=report, canonical_sha256=_report_digest(report))


def verify_validation_report(sealed: SealedValidationReport) -> bool:
    return _report_digest(sealed.report) == sealed.canonical_sha256


def _check(
    check_id: str,
    status: ValidationStatus,
    summary: str,
    **observed: str | int | bool | None,
) -> ValidationCheck:
    return ValidationCheck(check_id=check_id, status=status, summary=summary, observed=observed)


def _outcome(checks: list[ValidationCheck]) -> ValidationOutcome:
    statuses = {check.status for check in checks}
    if ValidationStatus.FAIL in statuses:
        return ValidationOutcome.FAILED
    if ValidationStatus.SKIPPED in statuses:
        return ValidationOutcome.INCOMPLETE
    if ValidationStatus.WARNING in statuses:
        return ValidationOutcome.PASSED_WITH_WARNINGS
    return ValidationOutcome.PASSED


def _report_digest(report: ValidationReport) -> str:
    payload = report.model_dump(mode="json")
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _inventory_digest(payload: dict[str, object]) -> str:
    entries = payload.get("entries")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("relative_path"), str):
                entry["relative_path"] = _hash_text(entry["relative_path"])
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
