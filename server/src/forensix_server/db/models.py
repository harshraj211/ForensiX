"""Phase 0 operational metadata and durable local-job models."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
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


class AcquisitionPlanRecord(Base):
    """Immutable, reviewable authorization boundary for a future acquisition."""

    __tablename__ = "acquisition_plans"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('metadata_only', 'quick_triage', 'shared_storage_inventory', 'custom')",
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
