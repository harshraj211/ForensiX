"""Phase 0 operational metadata and durable local-job models."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


def _uuid() -> str:
    return str(uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SystemEvent(Base):
    __tablename__ = "system_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    safe_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class DeviceDetectionRun(Base):
    __tablename__ = "device_detection_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    adb_version: Mapped[str] = mapped_column(String(32), nullable=False)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False, index=True)


class DeviceCapabilityRun(Base):
    __tablename__ = "device_capability_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    serial_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    manufacturer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    android_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sdk_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)


class JobRecord(Base):
    """Durable state for one local background operation."""

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(
            "job_type IN ('device_assessment', 'acquisition', 'parsing', 'indexing', "
            "'hashing', 'timeline', 'report', 'export', 'hash_verification')",
            name="ck_jobs_job_type",
        ),
        CheckConstraint(
            "state IN ('created', 'validating', 'ready', 'running', 'paused', "
            "'cancelling', 'cancelled', 'interrupted', 'failed', 'completed', "
            "'verifying', 'verified')",
            name="ck_jobs_state",
        ),
        CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_jobs_progress_percent",
        ),
        CheckConstraint("version >= 1", name="ck_jobs_version"),
        CheckConstraint("last_event_sequence >= 0", name="ck_jobs_last_event_sequence"),
        UniqueConstraint("plan_id", name="uq_jobs_plan_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    owner_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    case_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    plan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("acquisition_plans.id", ondelete="RESTRICT"), nullable=True
    )
    job_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_step: Mapped[str | None] = mapped_column(String(255), nullable=True)
    current_module: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    resume_supported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    result_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    checkpoint_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_event_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __mapper_args__ = {"version_id_col": version}


class JobEventRecord(Base):
    """Append-only, reconstructable progress history for one durable job."""

    __tablename__ = "job_events"
    __table_args__ = (
        CheckConstraint("sequence >= 1", name="ck_job_events_sequence"),
        CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_job_events_progress_percent",
        ),
        UniqueConstraint("job_id", "sequence", name="uq_job_events_job_sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False)
    current_step: Mapped[str | None] = mapped_column(String(255), nullable=True)
    current_module: Mapped[str | None] = mapped_column(String(128), nullable=True)
    checkpoint_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    safe_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class UserRecord(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_count"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class RoleRecord(Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class UserRoleRecord(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    assigned_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )


class AuthSessionRecord(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthEventRecord(Base):
    __tablename__ = "auth_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    username_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    safe_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class CaseRecord(Base):
    __tablename__ = "cases"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'active', 'closed', 'archived')",
            name="ck_cases_status",
        ),
        CheckConstraint("version >= 1", name="ck_cases_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    legal_authority: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __mapper_args__ = {"version_id_col": version}


class CaseMemberRecord(Base):
    __tablename__ = "case_members"
    __table_args__ = (
        CheckConstraint(
            "access_level IN ('owner', 'investigator', 'analyst', 'supervisor', 'reviewer')",
            name="ck_case_members_access_level",
        ),
    )

    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    access_level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    assigned_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )


class CaseEventRecord(Base):
    __tablename__ = "case_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    safe_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class CaseDeviceRecord(Base):
    """Stable, case-scoped identity for an assessed Android device."""

    __tablename__ = "case_devices"
    __table_args__ = (
        UniqueConstraint("case_id", "serial_hash", name="uq_case_devices_case_serial_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    serial_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    serial_suffix: Mapped[str] = mapped_column(String(8), nullable=False)
    manufacturer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    android_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sdk_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    build_fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)
    security_patch: Mapped[str | None] = mapped_column(String(64), nullable=True)
    registered_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class CaseDeviceDetectionRecord(Base):
    """Append-only record that a case-scoped ADB enumeration occurred."""

    __tablename__ = "case_device_detections"
    __table_args__ = (
        CheckConstraint("device_count >= 0", name="ck_case_device_detections_count"),
        CheckConstraint(
            "result IN ('no_devices', 'single_device', 'multiple_devices')",
            name="ck_case_device_detections_result",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    operator_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    adb_version: Mapped[str] = mapped_column(String(32), nullable=False)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False, index=True)


class CaseDeviceAssessmentRecord(Base):
    """Immutable readiness snapshot for a device at a point in time."""

    __tablename__ = "case_device_assessments"
    __table_args__ = (
        CheckConstraint("package_count >= 0", name="ck_case_device_assessments_packages"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("case_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assessed_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    package_count: Mapped[int] = mapped_column(Integer, nullable=False)
    assessor_version: Mapped[str] = mapped_column(String(32), nullable=False)
    snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)


class RootAccessProbeRecord(Base):
    """Append-only result of an explicitly acknowledged elevated identity probe."""

    __tablename__ = "root_access_probes"
    __table_args__ = (
        CheckConstraint(
            "status IN ('available', 'unavailable', 'indeterminate')",
            name="ck_root_access_probes_status",
        ),
        CheckConstraint("uid IS NULL OR uid >= 0", name="ck_root_access_probes_uid"),
        UniqueConstraint("probe_hash", name="uq_root_access_probes_hash"),
        Index("ix_root_access_probes_device_time", "device_id", "probed_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("case_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    probed_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    uid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    identity: Mapped[str | None] = mapped_column(String(240), nullable=True)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    potential_side_effect: Mapped[str] = mapped_column(String(500), nullable=False)
    probe_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    probed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class PhysicalBlockProbeRecord(Base):
    """Append-only size observation for one fixed experimental block profile."""

    __tablename__ = "physical_block_probes"
    __table_args__ = (
        CheckConstraint("profile IN ('userdata_by_name')", name="ck_physical_block_probes_profile"),
        CheckConstraint("size_bytes > 0", name="ck_physical_block_probes_size"),
        CheckConstraint(
            "encryption_state IN ('unknown', 'suspected', 'not_detected')",
            name="ck_physical_block_probes_encryption",
        ),
        UniqueConstraint("probe_hash", name="uq_physical_block_probes_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("case_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    root_probe_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("root_access_probes.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    probed_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    device_path: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    encryption_state: Mapped[str] = mapped_column(String(16), nullable=False)
    probe_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    probed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class AcquisitionPlanRecord(Base):
    """Immutable, reviewable authorization boundary for a future acquisition."""

    __tablename__ = "acquisition_plans"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('metadata_only', 'quick_triage', 'shared_storage_inventory', "
            "'media_files', 'document_files', 'downloads_files', 'custom')",
            name="ck_acquisition_plans_scope",
        ),
        CheckConstraint("status IN ('ready')", name="ck_acquisition_plans_status"),
        UniqueConstraint("plan_hash", name="uq_acquisition_plans_plan_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("case_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("case_device_assessments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    scope: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    modules_json: Mapped[str] = mapped_column(Text, nullable=False)
    limitations_json: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    readiness_assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    readiness_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class AcquisitionInventoryRecord(Base):
    """Immutable summary for one bounded, content-free shared-storage inventory."""

    __tablename__ = "acquisition_inventories"
    __table_args__ = (
        CheckConstraint(
            "status IN ('completed', 'truncated')", name="ck_acquisition_inventories_status"
        ),
        CheckConstraint(
            "discovered_count >= 0 AND persisted_count >= 0 AND skipped_count >= 0",
            name="ck_acquisition_inventories_counts",
        ),
        CheckConstraint(
            "max_items >= 1 AND max_depth >= 1",
            name="ck_acquisition_inventories_limits",
        ),
        UniqueConstraint("job_id", name="uq_acquisition_inventories_job_id"),
        UniqueConstraint("manifest_hash", name="uq_acquisition_inventories_manifest_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    plan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquisition_plans.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("case_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    root_id: Mapped[str] = mapped_column(String(32), nullable=False)
    display_path: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    discovered_count: Mapped[int] = mapped_column(Integer, nullable=False)
    persisted_count: Mapped[int] = mapped_column(Integer, nullable=False)
    skipped_count: Mapped[int] = mapped_column(Integer, nullable=False)
    max_items: Mapped[int] = mapped_column(Integer, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class AcquisitionInventoryItemRecord(Base):
    """Path metadata only; no Android file content or caller-provided path is stored."""

    __tablename__ = "acquisition_inventory_items"
    __table_args__ = (
        CheckConstraint("ordinal >= 1", name="ck_acquisition_inventory_items_ordinal"),
        CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_acquisition_inventory_items_size",
        ),
        CheckConstraint(
            "timestamp_confidence IS NULL OR timestamp_confidence IN ('medium')",
            name="ck_acquisition_inventory_items_timestamp_confidence",
        ),
        UniqueConstraint("inventory_id", "ordinal", name="uq_acquisition_inventory_items_ordinal"),
        UniqueConstraint(
            "inventory_id", "path_hash", name="uq_acquisition_inventory_items_path_hash"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    inventory_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquisition_inventories.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=False)
    path_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    extension: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    modified_time_raw: Mapped[str | None] = mapped_column(String(32), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    timestamp_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)


class AcquiredEvidenceFileRecord(Base):
    """Durable provenance and integrity result for one selected inventory item."""

    __tablename__ = "acquired_evidence_files"
    __table_args__ = (
        CheckConstraint(
            "status IN ('acquiring', 'completed', 'failed', 'interrupted')",
            name="ck_acquired_evidence_files_status",
        ),
        CheckConstraint(
            "validation_state IN ('not_physically_validated')",
            name="ck_acquired_evidence_files_validation_state",
        ),
        CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_acquired_evidence_files_size",
        ),
        CheckConstraint(
            "transfer_limit_bytes >= 1",
            name="ck_acquired_evidence_files_transfer_limit",
        ),
        UniqueConstraint("inventory_item_id", name="uq_acquired_evidence_files_item"),
        UniqueConstraint("storage_key", name="uq_acquired_evidence_files_storage_key"),
        UniqueConstraint(
            "manifest_storage_key", name="uq_acquired_evidence_files_manifest_storage_key"
        ),
        UniqueConstraint("manifest_hash", name="uq_acquired_evidence_files_manifest_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    inventory_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquisition_inventories.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    inventory_item_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquisition_inventory_items.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    plan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquisition_plans.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("case_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    acquired_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    source_root_id: Mapped[str] = mapped_column(String(32), nullable=False)
    source_path_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    manifest_storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    manifest_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    transfer_limit_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_state: Mapped[str] = mapped_column(String(32), nullable=False)
    partial_preserved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )


class AcquisitionPartialRecord(Base):
    """Durable ledger entry for one bounded transfer attempt's temporary bytes."""

    __tablename__ = "acquisition_partials"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'retained', 'discarded', 'sealed', 'missing')",
            name="ck_acquisition_partials_status",
        ),
        CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_acquisition_partials_size",
        ),
        UniqueConstraint("storage_key", name="uq_acquisition_partials_storage_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_file_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquired_evidence_files.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    disposition_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    reconciled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    disposition_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ArtifactRecord(Base):
    """Immutable normalized metadata derived from one sealed evidence file."""

    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint(
            "category IN ('image', 'video', 'audio', 'document', 'archive', 'other')",
            name="ck_artifacts_category",
        ),
        CheckConstraint(
            "status IN ('active', 'deleted', 'recovered', 'partial', 'corrupted', 'unverified')",
            name="ck_artifacts_status",
        ),
        CheckConstraint("size_bytes >= 0", name="ck_artifacts_size"),
        UniqueConstraint("evidence_file_id", name="uq_artifacts_evidence_file"),
        Index("ix_artifacts_case_category_collected", "case_id", "category", "collected_at"),
        Index("ix_artifacts_case_status_collected", "case_id", "status", "collected_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_file_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquired_evidence_files.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("case_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    subtype: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    source_relative_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    source_path_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    extension: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    detected_mime: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    primary_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parser_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)
    timestamp_confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    provenance_json: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class ArtifactPreviewRecord(Base):
    """Append-only metadata for a safe derivative; never the source evidence object."""

    __tablename__ = "artifact_previews"
    __table_args__ = (
        CheckConstraint(
            "status IN ('available', 'rejected', 'failed')",
            name="ck_artifact_previews_status",
        ),
        CheckConstraint(
            "output_size_bytes IS NULL OR output_size_bytes >= 1",
            name="ck_artifact_previews_output_size",
        ),
        UniqueConstraint("artifact_id", name="uq_artifact_previews_artifact"),
        UniqueConstraint("output_storage_key", name="uq_artifact_previews_storage_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    evidence_file_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquired_evidence_files.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    generated_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    extension_mismatch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    detected_mime: Mapped[str] = mapped_column(String(255), nullable=False)
    output_mime: Mapped[str | None] = mapped_column(String(255), nullable=True)
    output_storage_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    output_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    media_metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    worker_version: Mapped[str] = mapped_column(String(32), nullable=False)
    limits_json: Mapped[str] = mapped_column(Text, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class TimelineEventRecord(Base):
    """Deterministic timestamp claim materialized from one normalized artifact."""

    __tablename__ = "timeline_events"
    __table_args__ = (
        CheckConstraint(
            "category IN ('device', 'file', 'media', 'communication', 'application', "
            "'location', 'system', 'acquisition', 'custody')",
            name="ck_timeline_events_category",
        ),
        UniqueConstraint("artifact_id", "timestamp_type", name="uq_timeline_events_artifact_type"),
        UniqueConstraint("event_hash", name="uq_timeline_events_hash"),
        Index("ix_timeline_events_case_time", "case_id", "event_time", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    timestamp_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    original_time: Mapped[str] = mapped_column(String(128), nullable=False)
    timezone_basis: Mapped[str] = mapped_column(String(64), nullable=False)
    precision: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    builder_version: Mapped[str] = mapped_column(String(32), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class EvidenceSourceTimelineEventRecord(Base):
    """Deterministic timestamp claim derived from an imported-source artifact."""

    __tablename__ = "evidence_source_timeline_events"
    __table_args__ = (
        CheckConstraint(
            "category IN ('device', 'file', 'media', 'communication', 'application', "
            "'location', 'system', 'acquisition', 'custody')",
            name="ck_source_timeline_events_category",
        ),
        UniqueConstraint(
            "source_artifact_id",
            "timestamp_type",
            name="uq_source_timeline_events_artifact_type",
        ),
        UniqueConstraint("event_hash", name="uq_source_timeline_events_hash"),
        Index("ix_source_timeline_events_case_time", "case_id", "event_time", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    source_artifact_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_source_artifacts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    parser_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_parser_runs.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    timestamp_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    original_time: Mapped[str] = mapped_column(String(128), nullable=False)
    timezone_basis: Mapped[str] = mapped_column(String(128), nullable=False)
    precision: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    builder_version: Mapped[str] = mapped_column(String(32), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class BookmarkRecord(Base):
    """User-scoped bookmark state; source artifacts remain immutable."""

    __tablename__ = "bookmarks"
    __table_args__ = (
        UniqueConstraint("artifact_id", "user_id", name="uq_bookmarks_artifact_user"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TagRecord(Base):
    """Case-scoped normalized analyst tag."""

    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("case_id", "normalized_name", name="uq_tags_case_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class ArtifactTagRecord(Base):
    """Append-protected association between an artifact and case tag."""

    __tablename__ = "artifact_tags"
    __table_args__ = (UniqueConstraint("artifact_id", "tag_id", name="uq_artifact_tags_pair"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    tag_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tags.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    added_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class AnalystNoteRecord(Base):
    """Append-only analyst observation; corrections point to superseded notes."""

    __tablename__ = "analyst_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    author_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    body: Mapped[str] = mapped_column(String(4000), nullable=False)
    supersedes_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("analyst_notes.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class EvidenceVerificationRecord(Base):
    """Append-only known-answer re-verification of one file and its manifest."""

    __tablename__ = "evidence_verifications"
    __table_args__ = (
        CheckConstraint(
            "status IN ('verified', 'mismatch', 'missing', 'error')",
            name="ck_evidence_verifications_status",
        ),
        UniqueConstraint("verification_hash", name="uq_evidence_verifications_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_file_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("acquired_evidence_files.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    verified_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    expected_file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_matches: Mapped[bool] = mapped_column(Boolean, nullable=False)
    expected_manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_matches: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class EvidenceSourceRecord(Base):
    """One imported or acquired master source sealed for offline examination."""

    __tablename__ = "evidence_sources"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('imported_file', 'logical_adb', 'rooted_filesystem', "
            "'physical_block')",
            name="ck_evidence_sources_type",
        ),
        CheckConstraint(
            "acquisition_level IN ('logical', 'selective', 'filesystem', 'physical')",
            name="ck_evidence_sources_level",
        ),
        CheckConstraint(
            "status IN ('pending', 'sealed', 'failed')",
            name="ck_evidence_sources_status",
        ),
        CheckConstraint(
            "container_format IN ('raw', 'img', 'dd', 'tar', 'zip', 'directory_bundle', 'unknown')",
            name="ck_evidence_sources_format",
        ),
        CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_evidence_sources_size",
        ),
        CheckConstraint(
            "chunk_size_bytes >= 1048576 AND chunk_size_bytes <= 67108864",
            name="ck_evidence_sources_chunk_size",
        ),
        CheckConstraint("chunk_count >= 0", name="ck_evidence_sources_chunk_count"),
        UniqueConstraint("sealed_storage_key", name="uq_evidence_sources_storage_key"),
        UniqueConstraint("chunks_storage_key", name="uq_evidence_sources_chunks_key"),
        UniqueConstraint("manifest_storage_key", name="uq_evidence_sources_manifest_key"),
        Index("ix_evidence_sources_case_created", "case_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("case_devices.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    acquisition_level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    container_format: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    sealed_storage_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    chunks_storage_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    manifest_storage_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    chunks_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    chunk_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    read_only_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    validation_state: Mapped[str] = mapped_column(String(64), nullable=False)
    limitations_json: Mapped[str] = mapped_column(Text, nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    sealed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class EvidenceSourceChunkRecord(Base):
    """Deterministic chunk digest supporting interruption and corruption detection."""

    __tablename__ = "evidence_source_chunks"
    __table_args__ = (
        CheckConstraint("ordinal >= 0", name="ck_evidence_source_chunks_ordinal"),
        CheckConstraint("offset_bytes >= 0", name="ck_evidence_source_chunks_offset"),
        CheckConstraint("size_bytes >= 1", name="ck_evidence_source_chunks_size"),
        UniqueConstraint("evidence_source_id", "ordinal", name="uq_evidence_source_chunks_ordinal"),
        UniqueConstraint(
            "evidence_source_id", "offset_bytes", name="uq_evidence_source_chunks_offset"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    offset_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class EvidenceWorkingCopyRecord(Base):
    """A verified examination copy derived from one sealed master source."""

    __tablename__ = "evidence_working_copies"
    __table_args__ = (
        CheckConstraint(
            "status IN ('creating', 'ready', 'verification_failed')",
            name="ck_evidence_working_copies_status",
        ),
        CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_evidence_working_copies_size",
        ),
        UniqueConstraint("storage_key", name="uq_evidence_working_copies_storage_key"),
        Index("ix_evidence_working_copies_source_created", "evidence_source_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expected_source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    copy_method: Mapped[str] = mapped_column(String(32), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class EvidenceSourceVerificationRecord(Base):
    """Append-only integrity observation for a master or working copy."""

    __tablename__ = "evidence_source_verifications"
    __table_args__ = (
        CheckConstraint(
            "target_type IN ('master', 'working_copy')",
            name="ck_evidence_source_verifications_target",
        ),
        CheckConstraint(
            "status IN ('verified', 'mismatch', 'missing', 'error')",
            name="ck_evidence_source_verifications_status",
        ),
        CheckConstraint(
            "(target_type = 'master' AND working_copy_id IS NULL) OR "
            "(target_type = 'working_copy' AND working_copy_id IS NOT NULL)",
            name="ck_evidence_source_verifications_reference",
        ),
        UniqueConstraint("verification_hash", name="uq_evidence_source_verifications_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    working_copy_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("evidence_working_copies.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    verified_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    target_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    expected_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class EvidenceSourceInspectionRecord(Base):
    """Immutable signature-based classification of one verified working copy."""

    __tablename__ = "evidence_source_inspections"
    __table_args__ = (
        CheckConstraint(
            "detected_type IN ('zip', 'tar', 'sqlite', 'android_sparse', 'ext4', "
            "'f2fs', 'opaque', 'unknown')",
            name="ck_evidence_source_inspections_type",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_evidence_source_inspections_confidence",
        ),
        CheckConstraint(
            "encryption_state IN ('not_detected', 'suspected', 'unknown')",
            name="ck_evidence_source_inspections_encryption",
        ),
        UniqueConstraint("working_copy_id", name="uq_evidence_source_inspections_working_copy"),
        UniqueConstraint("inspection_hash", name="uq_evidence_source_inspections_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    working_copy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_working_copies.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    inspected_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    detected_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    encryption_state: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    signature_json: Mapped[str] = mapped_column(Text, nullable=False)
    warnings_json: Mapped[str] = mapped_column(Text, nullable=False)
    detector_version: Mapped[str] = mapped_column(String(32), nullable=False)
    inspection_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    inspected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class EvidenceParserRunRecord(Base):
    """Immutable outcome of one versioned parser against one verified working copy."""

    __tablename__ = "evidence_parser_runs"
    __table_args__ = (
        CheckConstraint("status IN ('completed', 'failed')", name="ck_evidence_parser_runs_status"),
        CheckConstraint("artifact_count >= 0", name="ck_evidence_parser_runs_artifact_count"),
        UniqueConstraint(
            "working_copy_id",
            "input_locator",
            "parser_id",
            "parser_version",
            name="uq_evidence_parser_runs_identity",
        ),
        UniqueConstraint("run_hash", name="uq_evidence_parser_runs_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    evidence_source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    working_copy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_working_copies.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    inspection_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_source_inspections.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    executed_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    parser_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    artifact_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    input_locator: Mapped[str] = mapped_column(String(1024), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    run_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class EvidenceSourceArtifactRecord(Base):
    """Normalized artifact derived from an Evidence Twin working copy."""

    __tablename__ = "evidence_source_artifacts"
    __table_args__ = (
        CheckConstraint(
            "category IN ('contact', 'communication', 'application', 'location', 'system', 'file')",
            name="ck_evidence_source_artifacts_category",
        ),
        CheckConstraint(
            "status IN ('active', 'deleted', 'recovered', 'partial', 'corrupted', 'unverified')",
            name="ck_evidence_source_artifacts_status",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_evidence_source_artifacts_confidence",
        ),
        UniqueConstraint("artifact_hash", name="uq_evidence_source_artifacts_hash"),
        Index(
            "ix_evidence_source_artifacts_case_event",
            "case_id",
            "event_time",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    parser_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_parser_runs.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    evidence_source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    working_copy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_working_copies.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subtype: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[str] = mapped_column(String(2000), nullable=False)
    event_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    source_locator: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    parser_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False)
    provenance_json: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class EvidenceToolOutputRecord(Base):
    """Sealed output file produced by one pinned external forensic tool run."""

    __tablename__ = "evidence_tool_outputs"
    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="ck_evidence_tool_outputs_size"),
        UniqueConstraint(
            "parser_run_id", "relative_path", name="uq_evidence_tool_outputs_run_path"
        ),
        UniqueConstraint("storage_key", name="uq_evidence_tool_outputs_storage_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    parser_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_parser_runs.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    evidence_source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    working_copy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_working_copies.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    relative_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )


class ReportRecord(Base):
    """Immutable report snapshot and generation result."""

    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint("status IN ('available')", name="ck_reports_status"),
        CheckConstraint("report_type IN ('preliminary')", name="ck_reports_type"),
        CheckConstraint("snapshot_size_bytes >= 1", name="ck_reports_snapshot_size"),
        UniqueConstraint("snapshot_storage_key", name="uq_reports_snapshot_storage_key"),
        UniqueConstraint("snapshot_sha256", name="uq_reports_snapshot_sha256"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    generated_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    report_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    template_version: Mapped[str] = mapped_column(String(32), nullable=False)
    snapshot_storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    snapshot_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class ReportOutputRecord(Base):
    """One sealed, hashed rendering of an immutable report snapshot."""

    __tablename__ = "report_outputs"
    __table_args__ = (
        CheckConstraint("format IN ('pdf', 'json', 'csv')", name="ck_report_outputs_format"),
        CheckConstraint("size_bytes >= 1", name="ck_report_outputs_size"),
        UniqueConstraint("report_id", "format", name="uq_report_outputs_report_format"),
        UniqueConstraint("storage_key", name="uq_report_outputs_storage_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    report_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("reports.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    format: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class CustodyEventRecord(Base):
    """Append-only, per-case hash-chained custody history."""

    __tablename__ = "custody_events"
    __table_args__ = (
        CheckConstraint("sequence >= 1", name="ck_custody_events_sequence"),
        CheckConstraint(
            "event_type IN ('evidence_registered', 'integrity_verified', "
            "'integrity_exception', 'evidence_source_registered', "
            "'source_integrity_verified', 'working_copy_verified', "
            "'parser_completed', 'parser_failed', "
            "'transferred', 'amendment', 'report_generated')",
            name="ck_custody_events_type",
        ),
        UniqueConstraint("case_id", "sequence", name="uq_custody_events_case_sequence"),
        UniqueConstraint("event_hash", name="uq_custody_events_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    evidence_file_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("acquired_evidence_files.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    evidence_source_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    parser_run_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("evidence_parser_runs.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    report_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("reports.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    from_custodian: Mapped[str | None] = mapped_column(String(255), nullable=True)
    to_custodian: Mapped[str | None] = mapped_column(String(255), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    purpose: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    related_event_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("custody_events.id", ondelete="RESTRICT"), nullable=True
    )
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class AuditLogRecord(Base):
    """Global tamper-evident audit chain; local storage is not tamper-proof."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("sequence >= 1", name="ck_audit_logs_sequence"),
        UniqueConstraint("sequence", name="uq_audit_logs_sequence"),
        UniqueConstraint("entry_hash", name="uq_audit_logs_entry_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    case_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    object_type: Mapped[str] = mapped_column(String(32), nullable=False)
    object_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    detail_json: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
