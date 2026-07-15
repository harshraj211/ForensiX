"""Phase 0 operational metadata models."""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


def _uuid() -> str:
    return str(uuid4())


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
