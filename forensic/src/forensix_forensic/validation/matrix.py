"""Integrity-sealed release-matrix coverage over physical validation records."""

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from .models import (
    SealedValidationReport,
    ValidationOutcome,
    ValidationStatus,
)
from .runner import verify_validation_report


class PhysicalMatrixPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    required_hosts: tuple[str, ...] = Field(min_length=1)
    required_android_releases: tuple[str, ...] = Field(min_length=1)
    release_commit: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{7,64}$")
    minimum_manufacturer_families: int = Field(default=2, ge=1, le=100)
    require_non_rooted: bool = True
    require_rooted: bool = True
    require_known_file: bool = True
    require_transport_cycle: bool = True


class PhysicalMatrixCoverage(BaseModel):
    model_config = ConfigDict(frozen=True)

    input_records: int = Field(ge=0)
    accepted_system_records: int = Field(ge=0)
    invalid_records: int = Field(ge=0)
    rejected_non_system_records: int = Field(ge=0)
    rejected_unverifiable_system_records: int = Field(default=0, ge=0)
    duplicate_records: int = Field(ge=0)
    hosts: tuple[str, ...]
    android_releases: tuple[str, ...]
    manufacturer_families: tuple[str, ...]
    release_commits: tuple[str, ...] = ()
    non_rooted_records: int = Field(ge=0)
    rooted_records: int = Field(ge=0)
    known_file_passes: int = Field(ge=0)
    transport_cycle_passes: int = Field(ge=0)


class PhysicalMatrixReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(
        default="forensix-physical-matrix/1.1",
        pattern=r"^forensix-physical-matrix/1\.[01]$",
    )
    generated_at: datetime
    outcome: ValidationOutcome
    policy: PhysicalMatrixPolicy
    coverage: PhysicalMatrixCoverage
    source_report_sha256: tuple[str, ...]
    gaps: tuple[str, ...]
    limitations: tuple[str, ...]


class SealedPhysicalMatrixReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    report: PhysicalMatrixReport
    canonical_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


def build_physical_matrix(
    records: tuple[SealedValidationReport, ...],
    policy: PhysicalMatrixPolicy,
) -> SealedPhysicalMatrixReport:
    """Verify, deduplicate, and evaluate physical validation records against policy."""
    if policy.release_commit is None:
        raise ValueError("New physical matrices require one declared release commit.")
    accepted: list[SealedValidationReport] = []
    seen: set[str] = set()
    invalid_records = 0
    rejected_non_system = 0
    rejected_unverifiable_system = 0
    duplicate_records = 0
    for sealed in records:
        if not verify_validation_report(sealed):
            invalid_records += 1
            continue
        if sealed.canonical_sha256 in seen:
            duplicate_records += 1
            continue
        seen.add(sealed.canonical_sha256)
        if sealed.report.mode != "system":
            rejected_non_system += 1
            continue
        if not _has_physical_identity_evidence(sealed):
            rejected_unverifiable_system += 1
            continue
        accepted.append(sealed)

    hosts = _values(accepted, lambda item: item.report.environment.operating_system)
    releases = _values(accepted, lambda item: item.report.android_release)
    manufacturers = _check_values(accepted, "device_properties", "manufacturer")
    release_commits = _values(
        accepted,
        lambda item: (
            item.report.run_context.release_commit.casefold()
            if item.report.run_context is not None
            else None
        ),
    )
    known_file_passes = _passing_check_count(accepted, "known_file_acquisition")
    transport_cycle_passes = _passing_check_count(accepted, "transport_disconnect_reconnect")
    non_rooted_records = _check_value_count(
        accepted, "root_capability", "root_status", "unavailable"
    )
    rooted_records = _check_value_count(accepted, "root_capability", "root_status", "available")

    gaps: list[str] = []
    if invalid_records:
        gaps.append(f"{invalid_records} input record(s) failed canonical seal verification.")
    if rejected_non_system:
        gaps.append(f"{rejected_non_system} mock/non-system record(s) were rejected.")
    if rejected_unverifiable_system:
        gaps.append(
            f"{rejected_unverifiable_system} system record(s) lacked hashed ADB or device "
            "identity evidence."
        )
    if not accepted:
        gaps.append("No unique, sealed system-mode validation record was accepted.")
    missing_hosts = sorted(set(policy.required_hosts) - set(hosts))
    if missing_hosts:
        gaps.append(f"Missing required host coverage: {', '.join(missing_hosts)}.")
    missing_releases = sorted(set(policy.required_android_releases) - set(releases))
    if missing_releases:
        gaps.append(f"Missing required Android coverage: {', '.join(missing_releases)}.")
    if len(manufacturers) < policy.minimum_manufacturer_families:
        gaps.append(
            "Manufacturer-family coverage is below the declared minimum of "
            f"{policy.minimum_manufacturer_families}."
        )
    expected_release_commit = policy.release_commit.casefold()
    if release_commits != (expected_release_commit,):
        gaps.append(
            f"Accepted records must all bind to declared release commit {expected_release_commit}."
        )
    if policy.require_non_rooted and non_rooted_records == 0:
        gaps.append("No sealed non-rooted physical validation record was accepted.")
    if policy.require_rooted and rooted_records == 0:
        gaps.append("No sealed rooted physical validation record was accepted.")
    if policy.require_known_file and known_file_passes != len(accepted):
        gaps.append("Every accepted record must pass the fixed known-file acquisition check.")
    if policy.require_transport_cycle and transport_cycle_passes != len(accepted):
        gaps.append("Every accepted record must pass the disconnect/reconnect check.")

    outcome = (
        ValidationOutcome.FAILED
        if invalid_records or rejected_non_system or rejected_unverifiable_system
        else ValidationOutcome.INCOMPLETE
        if gaps
        else ValidationOutcome.PASSED
    )
    report = PhysicalMatrixReport(
        generated_at=datetime.now(UTC),
        outcome=outcome,
        policy=policy,
        coverage=PhysicalMatrixCoverage(
            input_records=len(records),
            accepted_system_records=len(accepted),
            invalid_records=invalid_records,
            rejected_non_system_records=rejected_non_system,
            rejected_unverifiable_system_records=rejected_unverifiable_system,
            duplicate_records=duplicate_records,
            hosts=hosts,
            android_releases=releases,
            manufacturer_families=manufacturers,
            release_commits=release_commits,
            non_rooted_records=non_rooted_records,
            rooted_records=rooted_records,
            known_file_passes=known_file_passes,
            transport_cycle_passes=transport_cycle_passes,
        ),
        source_report_sha256=tuple(item.canonical_sha256 for item in accepted),
        gaps=tuple(gaps),
        limitations=(
            "Coverage is derived from supplied sealed records; it does not prove the truth of "
            "examiner-entered context or evidentiary admissibility.",
            "System mode and a passing ADB workflow do not prove hardware write blocking.",
            "A release decision still requires independent review of devices, datasets, failures, "
            "and declared support boundaries.",
        ),
    )
    return SealedPhysicalMatrixReport(report=report, canonical_sha256=_digest(report))


def verify_physical_matrix(sealed: SealedPhysicalMatrixReport) -> bool:
    return _digest(sealed.report) == sealed.canonical_sha256


def _values(
    records: list[SealedValidationReport],
    callback: Callable[[SealedValidationReport], str | None],
) -> tuple[str, ...]:
    values: set[str] = set()
    for item in records:
        value = callback(item)
        if isinstance(value, str) and value:
            values.add(value)
    return tuple(sorted(values))


def _check_values(
    records: list[SealedValidationReport], check_id: str, field: str
) -> tuple[str, ...]:
    values: set[str] = set()
    for sealed in records:
        check = next((item for item in sealed.report.checks if item.check_id == check_id), None)
        value = check.observed.get(field) if check else None
        if isinstance(value, str) and value:
            values.add(value)
    return tuple(sorted(values))


def _passing_check_count(records: list[SealedValidationReport], check_id: str) -> int:
    return sum(
        any(
            check.check_id == check_id and check.status is ValidationStatus.SUCCEEDED
            for check in sealed.report.checks
        )
        for sealed in records
    )


def _check_value_count(
    records: list[SealedValidationReport],
    check_id: str,
    field: str,
    expected: str,
) -> int:
    count = 0
    for sealed in records:
        check = next((item for item in sealed.report.checks if item.check_id == check_id), None)
        if check is not None and check.observed.get(field) == expected:
            count += 1
    return count


def _has_physical_identity_evidence(sealed: SealedValidationReport) -> bool:
    report = sealed.report
    authorized = any(
        check.check_id == "authorized_device" and check.status is ValidationStatus.SUCCEEDED
        for check in report.checks
    )
    return bool(
        authorized
        and report.adb_executable_sha256
        and report.device_serial_sha256
        and report.build_fingerprint_sha256
        and report.android_release
        and report.android_sdk
        and report.run_context is not None
        and report.run_context.device_role == "controlled_test_device"
    )


def _digest(report: PhysicalMatrixReport) -> str:
    model = report.model_dump(mode="json")
    if report.schema_version == "forensix-physical-matrix/1.0":
        policy = model.get("policy")
        coverage = model.get("coverage")
        if isinstance(policy, dict):
            policy.pop("release_commit", None)
        if isinstance(coverage, dict):
            coverage.pop("rejected_unverifiable_system_records", None)
            coverage.pop("release_commits", None)
    payload = json.dumps(
        model,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()
