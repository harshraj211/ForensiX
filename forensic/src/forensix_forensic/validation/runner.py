"""Policy-bounded validation runner for controlled physical devices."""

import asyncio
import hashlib
import json
import platform
import tempfile
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forensix_forensic.adb import (
    KNOWN_FILE_FIXTURE_ID,
    KNOWN_FILE_RELATIVE_PATH,
    KNOWN_FILE_SHA256,
    KNOWN_FILE_SIZE_BYTES,
    AdbClient,
    DeviceState,
    SharedStorageRoot,
    StorageInventoryResult,
)

from .models import (
    SealedValidationReport,
    ValidationCheck,
    ValidationEnvironment,
    ValidationOutcome,
    ValidationReport,
    ValidationRunContext,
    ValidationStatus,
)

TOOL_VERSION = "0.1.0"
TRANSPORT_CYCLE_TIMEOUT_SECONDS = 60.0
TRANSPORT_POLL_INTERVAL_SECONDS = 0.5
ValidationCheckpoint = Callable[[str], Awaitable[None]]


async def run_adb_validation(
    client: AdbClient,
    *,
    mode: str,
    selected_serial: str | None = None,
    validate_known_file: bool = False,
    validate_transport_cycle: bool = False,
    checkpoint: ValidationCheckpoint | None = None,
    run_context: ValidationRunContext | None = None,
) -> SealedValidationReport:
    """Run bounded ADB checks and an optional fixed-profile known-file acquisition."""
    if mode != "system":
        raise ValueError("Validation mode must be system.")
    if validate_transport_cycle and not validate_known_file:
        raise ValueError("Transport-cycle validation requires known-file validation.")
    if validate_transport_cycle and checkpoint is None:
        raise ValueError("Transport-cycle validation requires an operator checkpoint callback.")
    if mode == "system" and validate_known_file and run_context is None:
        raise ValueError(
            "Physical known-file validation requires sealed operator, authority, connection, "
            "and release context."
        )
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
                    manufacturer=properties.get("ro.product.manufacturer"),
                    model=properties.get("ro.product.model"),
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
                if validate_known_file:
                    known_file_check = await _validate_known_file_acquisition(
                        client, selected.serial, root, first
                    )
                    checks.append(known_file_check)
                    if validate_transport_cycle:
                        if known_file_check.status is ValidationStatus.SUCCEEDED:
                            assert checkpoint is not None
                            checks.append(
                                await _validate_transport_cycle(
                                    client,
                                    selected.serial,
                                    root,
                                    checkpoint,
                                )
                            )
                        else:
                            checks.append(
                                _check(
                                    "transport_disconnect_reconnect",
                                    ValidationStatus.SKIPPED,
                                    "The transport cycle was not attempted because the initial "
                                    "known-file check did not pass.",
                                    fixture_id=KNOWN_FILE_FIXTURE_ID,
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
                if validate_known_file:
                    checks.append(
                        _check(
                            "known_file_acquisition",
                            ValidationStatus.SKIPPED,
                            "No readable approved root was available for known-file acquisition.",
                            fixture_id=KNOWN_FILE_FIXTURE_ID,
                        )
                    )
                    if validate_transport_cycle:
                        checks.append(
                            _check(
                                "transport_disconnect_reconnect",
                                ValidationStatus.SKIPPED,
                                "No readable approved root was available for the transport cycle.",
                                fixture_id=KNOWN_FILE_FIXTURE_ID,
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
        run_context=run_context,
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
            "Inventory repeatability does not prove completeness or access to private app data.",
            (
                "Known-file validation applies only to the fixed controlled fixture and does not "
                "prove acquisition completeness for other files or devices."
            ),
            (
                "A passing transport cycle proves detection and reacquisition only for the "
                "observed controlled run; it does not guarantee recovery from every interruption."
            ),
            "Physical run context is examiner-supplied and is not independently authenticated.",
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
    if report.schema_version == "forensix-validation/1.0":
        payload.pop("run_context", None)
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


async def _validate_known_file_acquisition(
    client: AdbClient,
    serial: str,
    root: SharedStorageRoot,
    inventory: StorageInventoryResult,
) -> ValidationCheck:
    """Pull the one closed-profile fixture twice and compare known-answer hashes."""
    fixture = next(
        (entry for entry in inventory.entries if entry.relative_path == KNOWN_FILE_RELATIVE_PATH),
        None,
    )
    if fixture is None:
        return _check(
            "known_file_acquisition",
            ValidationStatus.SKIPPED,
            "The fixed validation fixture was not present in the bounded inventory.",
            fixture_id=KNOWN_FILE_FIXTURE_ID,
            expected_size_bytes=KNOWN_FILE_SIZE_BYTES,
            expected_sha256=KNOWN_FILE_SHA256,
        )

    try:
        with tempfile.TemporaryDirectory(prefix="forensix-known-file-") as directory:
            destinations = (Path(directory) / "pass-1.partial", Path(directory) / "pass-2.partial")
            observed: list[tuple[int, str]] = []
            for destination in destinations:
                result = await client.pull_inventory_file(
                    serial,
                    root,
                    KNOWN_FILE_RELATIVE_PATH,
                    destination,
                )
                actual_size = await asyncio.to_thread(_regular_file_size, destination)
                if actual_size is None:
                    raise ValueError("Known-file pull did not produce a regular local file.")
                if result.size_bytes != actual_size:
                    raise ValueError("ADB pull result size did not match the local file size.")
                observed.append((actual_size, await asyncio.to_thread(_hash_file, destination)))
    except Exception as error:
        return _check(
            "known_file_acquisition",
            ValidationStatus.FAIL,
            "The fixed validation fixture could not be acquired and verified safely.",
            fixture_id=KNOWN_FILE_FIXTURE_ID,
            error_type=type(error).__name__,
        )

    first_size, first_hash = observed[0]
    second_size, second_hash = observed[1]
    inventory_size_matches = fixture.size_bytes == KNOWN_FILE_SIZE_BYTES
    known_answer_matches = (
        first_size == second_size == KNOWN_FILE_SIZE_BYTES
        and first_hash == second_hash == KNOWN_FILE_SHA256
    )
    status = (
        ValidationStatus.SUCCEEDED
        if inventory_size_matches and known_answer_matches
        else ValidationStatus.FAIL
    )
    return _check(
        "known_file_acquisition",
        status,
        (
            "Two acquisitions reproduced the fixed known size and SHA-256."
            if status is ValidationStatus.SUCCEEDED
            else "The acquired fixture did not reproduce its fixed known-answer metadata."
        ),
        fixture_id=KNOWN_FILE_FIXTURE_ID,
        inventory_size_matches=inventory_size_matches,
        acquisition_count=2,
        first_size_bytes=first_size,
        second_size_bytes=second_size,
        expected_size_bytes=KNOWN_FILE_SIZE_BYTES,
        first_sha256=first_hash,
        second_sha256=second_hash,
        expected_sha256=KNOWN_FILE_SHA256,
        repeatable=first_hash == second_hash and first_size == second_size,
        known_answer_matches=known_answer_matches,
    )


def _regular_file_size(path: Path) -> int | None:
    try:
        if not path.is_file() or path.is_symlink():
            return None
        return path.stat().st_size
    except OSError:
        return None


async def _validate_transport_cycle(
    client: AdbClient,
    serial: str,
    root: SharedStorageRoot,
    checkpoint: ValidationCheckpoint,
) -> ValidationCheck:
    """Observe a real disconnect, reauthorization, and fixed-file reacquisition."""
    try:
        await checkpoint("disconnect")
        disconnected_state = await _wait_for_transport(client, serial, authorized=False)
        await checkpoint("reconnect")
        await _wait_for_transport(client, serial, authorized=True)
        inventory = await client.inventory_shared_storage(serial, root)
        fixture = next(
            (
                entry
                for entry in inventory.entries
                if entry.relative_path == KNOWN_FILE_RELATIVE_PATH
            ),
            None,
        )
        if fixture is None:
            raise ValueError("The fixed fixture was absent after reconnection.")
        with tempfile.TemporaryDirectory(prefix="forensix-reconnect-") as directory:
            destination = Path(directory) / "post-reconnect.partial"
            result = await client.pull_inventory_file(
                serial,
                root,
                KNOWN_FILE_RELATIVE_PATH,
                destination,
            )
            size_bytes = await asyncio.to_thread(_regular_file_size, destination)
            if size_bytes is None or result.size_bytes != size_bytes:
                raise ValueError("Post-reconnect pull size could not be validated.")
            sha256 = await asyncio.to_thread(_hash_file, destination)
    except Exception as error:
        return _check(
            "transport_disconnect_reconnect",
            ValidationStatus.FAIL,
            "The controlled disconnect/reconnect sequence did not complete safely.",
            fixture_id=KNOWN_FILE_FIXTURE_ID,
            error_type=type(error).__name__,
        )

    known_answer_matches = (
        fixture.size_bytes == size_bytes == KNOWN_FILE_SIZE_BYTES and sha256 == KNOWN_FILE_SHA256
    )
    return _check(
        "transport_disconnect_reconnect",
        ValidationStatus.SUCCEEDED if known_answer_matches else ValidationStatus.FAIL,
        (
            "Disconnect was observed, authorization returned, and the fixture was reacquired."
            if known_answer_matches
            else "The post-reconnect fixture did not match the known answer."
        ),
        fixture_id=KNOWN_FILE_FIXTURE_ID,
        disconnected_state=disconnected_state,
        reauthorized=True,
        post_reconnect_size_bytes=size_bytes,
        post_reconnect_sha256=sha256,
        expected_sha256=KNOWN_FILE_SHA256,
        known_answer_matches=known_answer_matches,
    )


async def _wait_for_transport(client: AdbClient, serial: str, *, authorized: bool) -> str:
    deadline = time.monotonic() + TRANSPORT_CYCLE_TIMEOUT_SECONDS
    while True:
        transports = await client.list_transports()
        selected = next((item for item in transports if item.serial == serial), None)
        if authorized and selected is not None and selected.state is DeviceState.AUTHORIZED:
            return DeviceState.AUTHORIZED.value
        if not authorized and (
            selected is None or selected.state in {DeviceState.OFFLINE, DeviceState.UNKNOWN}
        ):
            return "missing" if selected is None else selected.state.value
        if time.monotonic() >= deadline:
            expected = "authorized" if authorized else "missing or offline"
            raise TimeoutError(f"Transport did not become {expected} within the fixed timeout.")
        await asyncio.sleep(TRANSPORT_POLL_INTERVAL_SECONDS)
