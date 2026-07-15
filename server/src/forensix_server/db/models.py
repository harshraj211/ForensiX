"""Phase 0 operational metadata and durable local-job models."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, String, Text
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
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
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
