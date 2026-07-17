"""Immutable preliminary report generation and retrieval."""

from __future__ import annotations

import builtins
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_forensic.storage import EvidenceStore, StoredEvidence
from forensix_server import __version__
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError, CaseService
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryRecord,
    AcquisitionPlanRecord,
    AnalystNoteRecord,
    ArtifactRecord,
    ArtifactTagRecord,
    BookmarkRecord,
    CaseDeviceAssessmentRecord,
    CaseDeviceRecord,
    CustodyEventRecord,
    Database,
    EvidenceVerificationRecord,
    ReportOutputRecord,
    ReportRecord,
    TagRecord,
    TimelineEventRecord,
)

from .renderers import render_csv, render_json, render_pdf
from .snapshot import (
    AcquisitionSnapshot,
    ArtifactSnapshot,
    CaseSnapshot,
    CustodySnapshot,
    DeviceSnapshot,
    HashManifestItem,
    ReportIdentity,
    ReportSnapshot,
    TimelineSnapshot,
)

PRELIMINARY_WARNING = (
    "PRELIMINARY: This controlled logical triage report may be incomplete and must be "
    "reviewed by a qualified examiner before investigative or legal use."
)


class ReportError(CaseInvalidStateError):
    code = "REPORT_INVALID"


class ReportNotFoundError(ReportError):
    code = "REPORT_NOT_FOUND"


@dataclass(frozen=True, slots=True)
class ReportBundle:
    report: ReportRecord
    outputs: tuple[ReportOutputRecord, ...]


@dataclass(frozen=True, slots=True)
class ReportContent:
    output: ReportOutputRecord
    path: str


class ReportService:
    def generate(self, database: Database, principal: Principal, case_id: str) -> ReportBundle:
        report_id = str(uuid4())
        generated_at = datetime.now(UTC)
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            if not principal.can(Permission.REPORTS_GENERATE):
                raise CaseAccessDeniedError("The current user cannot generate reports.")
            snapshot = self._snapshot(
                session, principal, case_id, report_id, generated_at=generated_at
            )
            snapshot_bytes = _canonical_bytes(snapshot)
            rendered = {
                "pdf": ("application/pdf", render_pdf(snapshot)),
                "json": ("application/json", render_json(snapshot)),
                "csv": ("text/csv; charset=utf-8", render_csv(snapshot)),
            }
            store = EvidenceStore(database.data_dir / "evidence")
            prefix = f"reports/{case_id}/{report_id}"
            stored_snapshot = _store(store, f"{prefix}/snapshot.json", snapshot_bytes)
            report = ReportRecord(
                id=report_id,
                case_id=case_id,
                generated_by=principal.user_id,
                report_type="preliminary",
                status="available",
                title=f"Preliminary report - {case.case_number}",
                schema_version=snapshot.schema_version,
                template_version=snapshot.template_version,
                snapshot_storage_key=stored_snapshot.storage_key,
                snapshot_size_bytes=stored_snapshot.size_bytes,
                snapshot_sha256=stored_snapshot.sha256,
                generated_at=generated_at,
            )
            session.add(report)
            session.flush()
            safe_case = re.sub(r"[^A-Za-z0-9._-]", "_", case.case_number)
            outputs: list[ReportOutputRecord] = []
            for output_format, (media_type, content) in rendered.items():
                stored = _store(store, f"{prefix}/report.{output_format}", content)
                output = ReportOutputRecord(
                    report_id=report_id,
                    case_id=case_id,
                    format=output_format,
                    media_type=media_type,
                    filename=f"ForensiX_{safe_case}_Preliminary_{report_id[:8]}.{output_format}",
                    storage_key=stored.storage_key,
                    size_bytes=stored.size_bytes,
                    sha256=stored.sha256,
                    created_at=generated_at,
                )
                session.add(output)
                outputs.append(output)
            session.flush()
            CustodyService().append_report_generated(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                report_id=report_id,
                purpose="Preliminary report generated from a versioned evidence snapshot.",
            )
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="report.generated",
                object_type="report",
                object_id=report_id,
                detail={
                    "snapshot_sha256": stored_snapshot.sha256,
                    "outputs": {item.format: item.sha256 for item in outputs},
                    "report_type": "preliminary",
                },
                created_at=generated_at,
            )
            session.flush()
            return ReportBundle(report=report, outputs=tuple(outputs))

    def list(
        self, session: Session, principal: Principal, case_id: str
    ) -> builtins.list[ReportBundle]:
        CaseService().get(session, principal, case_id)
        reports = list(
            session.scalars(
                select(ReportRecord)
                .where(ReportRecord.case_id == case_id)
                .order_by(ReportRecord.generated_at.desc(), ReportRecord.id.desc())
            )
        )
        return [ReportBundle(item, tuple(self._outputs(session, item.id))) for item in reports]

    def get(
        self, session: Session, principal: Principal, case_id: str, report_id: str
    ) -> ReportBundle:
        CaseService().get(session, principal, case_id)
        report = session.get(ReportRecord, report_id)
        if report is None or report.case_id != case_id:
            raise ReportNotFoundError("The requested report does not exist in this case.")
        return ReportBundle(report, tuple(self._outputs(session, report_id)))

    def content(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        report_id: str,
        output_format: str,
    ) -> ReportContent:
        with database.session() as session:
            bundle = self.get(session, principal, case_id, report_id)
            output = next((item for item in bundle.outputs if item.format == output_format), None)
            if output is None:
                raise ReportNotFoundError("The requested report output does not exist.")
            store = EvidenceStore(database.data_dir / "evidence")
            if not store.verify(output.storage_key, output.sha256):
                raise ReportError("Report output integrity verification failed.")
            path = str(store.resolve(output.storage_key, require_file=True))
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="report.downloaded",
                object_type="report",
                object_id=report_id,
                detail={"format": output.format, "sha256": output.sha256},
                created_at=datetime.now(UTC),
            )
            return ReportContent(output=output, path=path)

    @staticmethod
    def _outputs(session: Session, report_id: str) -> builtins.list[ReportOutputRecord]:
        return list(
            session.scalars(
                select(ReportOutputRecord)
                .where(ReportOutputRecord.report_id == report_id)
                .order_by(ReportOutputRecord.format)
            )
        )

    def _snapshot(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
        report_id: str,
        *,
        generated_at: datetime,
    ) -> ReportSnapshot:
        case = CaseService().get(session, principal, case_id)
        devices = list(
            session.scalars(select(CaseDeviceRecord).where(CaseDeviceRecord.case_id == case_id))
        )
        assessments = list(
            session.scalars(
                select(CaseDeviceAssessmentRecord)
                .where(CaseDeviceAssessmentRecord.case_id == case_id)
                .order_by(CaseDeviceAssessmentRecord.assessed_at.desc())
            )
        )
        latest_assessment = {item.device_id: item for item in assessments}
        plans = list(
            session.scalars(
                select(AcquisitionPlanRecord)
                .where(AcquisitionPlanRecord.case_id == case_id)
                .order_by(AcquisitionPlanRecord.created_at)
            )
        )
        inventories = list(
            session.scalars(
                select(AcquisitionInventoryRecord).where(
                    AcquisitionInventoryRecord.case_id == case_id
                )
            )
        )
        inventory_by_plan = {item.plan_id: item for item in inventories}
        evidence = list(
            session.scalars(
                select(AcquiredEvidenceFileRecord).where(
                    AcquiredEvidenceFileRecord.case_id == case_id
                )
            )
        )
        artifacts = list(
            session.scalars(select(ArtifactRecord).where(ArtifactRecord.case_id == case_id))
        )
        bookmarks = list(
            session.scalars(
                select(BookmarkRecord).where(
                    BookmarkRecord.case_id == case_id, BookmarkRecord.removed_at.is_(None)
                )
            )
        )
        bookmark_by_artifact = {item.artifact_id: item for item in bookmarks}
        selected = [item for item in artifacts if item.id in bookmark_by_artifact]
        notes = list(
            session.scalars(select(AnalystNoteRecord).where(AnalystNoteRecord.case_id == case_id))
        )
        notes_by_artifact: dict[str, list[str]] = {}
        for note in notes:
            notes_by_artifact.setdefault(note.artifact_id, []).append(note.body)
        tag_rows = session.execute(
            select(ArtifactTagRecord.artifact_id, TagRecord.name)
            .join(TagRecord, TagRecord.id == ArtifactTagRecord.tag_id)
            .where(TagRecord.case_id == case_id)
        ).all()
        tags_by_artifact: dict[str, list[str]] = {}
        for artifact_id, name in tag_rows:
            tags_by_artifact.setdefault(artifact_id, []).append(name)
        timeline = list(
            session.scalars(
                select(TimelineEventRecord)
                .where(TimelineEventRecord.case_id == case_id)
                .order_by(TimelineEventRecord.event_time, TimelineEventRecord.id)
                .limit(500)
            )
        )
        verification = list(
            session.scalars(
                select(EvidenceVerificationRecord).where(
                    EvidenceVerificationRecord.case_id == case_id
                )
            )
        )
        custody = list(
            session.scalars(
                select(CustodyEventRecord)
                .where(CustodyEventRecord.case_id == case_id)
                .order_by(CustodyEventRecord.sequence)
            )
        )
        return ReportSnapshot(
            report=ReportIdentity(
                report_id=report_id,
                generated_at=generated_at,
                generated_by_id=principal.user_id,
                generated_by_name=principal.display_name,
                preliminary_warning=PRELIMINARY_WARNING,
            ),
            case=CaseSnapshot(
                id=case.id,
                case_number=case.case_number,
                title=case.title,
                description=case.description,
                legal_authority=case.legal_authority,
                status=case.status,
                created_at=case.created_at,
            ),
            devices=[
                DeviceSnapshot(
                    id=item.id,
                    serial_suffix=item.serial_suffix,
                    manufacturer=item.manufacturer,
                    model=item.model,
                    android_version=item.android_version,
                    sdk_level=item.sdk_level,
                    build_fingerprint=item.build_fingerprint,
                    security_patch=item.security_patch,
                    latest_assessment=(
                        json.loads(latest_assessment[item.id].snapshot_json)
                        if item.id in latest_assessment
                        else None
                    ),
                )
                for item in devices
            ],
            acquisitions=[
                _acquisition_snapshot(item, inventory_by_plan.get(item.id)) for item in plans
            ],
            evidence_summary=dict(Counter(item.category for item in artifacts)),
            selected_artifacts=[
                ArtifactSnapshot(
                    id=item.id,
                    evidence_file_id=item.evidence_file_id,
                    title=item.title,
                    category=item.category,
                    status=item.status,
                    source_relative_path=item.source_relative_path,
                    detected_mime=item.detected_mime,
                    size_bytes=item.size_bytes,
                    sha256=item.primary_sha256,
                    collected_at=item.collected_at,
                    bookmark_reason=bookmark_by_artifact[item.id].reason,
                    tags=sorted(tags_by_artifact.get(item.id, [])),
                    analyst_notes=notes_by_artifact.get(item.id, []),
                )
                for item in selected
            ],
            timeline=[
                TimelineSnapshot(
                    artifact_id=item.artifact_id,
                    category=item.category,
                    timestamp_type=item.timestamp_type,
                    event_time=item.event_time,
                    timezone_basis=item.timezone_basis,
                    confidence=item.confidence,
                    summary=item.summary,
                    event_hash=item.event_hash,
                )
                for item in timeline
            ],
            hash_manifest=[
                HashManifestItem(
                    evidence_file_id=item.id,
                    status=item.status,
                    size_bytes=item.size_bytes,
                    file_sha256=item.sha256,
                    manifest_sha256=item.manifest_hash,
                    validation_state=item.validation_state,
                )
                for item in evidence
            ],
            integrity_summary=dict(Counter(item.status for item in verification)),
            custody=[
                CustodySnapshot(
                    sequence=item.sequence,
                    event_type=item.event_type,
                    actor_id=item.actor_id,
                    evidence_file_id=item.evidence_file_id,
                    report_id=item.report_id,
                    purpose=item.purpose,
                    event_hash=item.event_hash,
                    created_at=item.created_at,
                )
                for item in custody
            ],
            errors=[
                f"Evidence {item.id}: {item.error_code or item.status}"
                for item in evidence
                if item.status not in {"completed"}
            ],
            limitations=[
                "ADB is not a hardware write blocker and may cause device-side effects.",
                "This is controlled logical triage, not physical acquisition or lock bypass.",
                "Private application data is unavailable unless separately and lawfully obtained.",
                "Device-side timestamps are not claimed when the source did not expose them.",
                "A local hash chain is tamper-evident, not tamper-proof.",
            ],
            methodology=[
                "Case-authorized, capability-gated collection through predefined ADB operations.",
                "Files were sealed into contained local storage and hashed with SHA-256.",
                "Artifacts were normalized by versioned parsers; source evidence was not modified.",
                "Only active investigator bookmarks are included in the selected-artifact export.",
            ],
            tool_version=__version__,
        )


def _acquisition_snapshot(
    plan: AcquisitionPlanRecord, inventory: AcquisitionInventoryRecord | None
) -> AcquisitionSnapshot:
    return AcquisitionSnapshot(
        plan_id=plan.id,
        scope=plan.scope,
        modules=list(json.loads(plan.modules_json)),
        limitations=list(json.loads(plan.limitations_json)),
        plan_hash=plan.plan_hash,
        created_at=plan.created_at,
        inventory_status=inventory.status if inventory else None,
        inventory_manifest_hash=inventory.manifest_hash if inventory else None,
        inventory_started_at=inventory.started_at if inventory else None,
        inventory_completed_at=inventory.completed_at if inventory else None,
    )


def _canonical_bytes(snapshot: ReportSnapshot) -> bytes:
    return json.dumps(
        snapshot.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _store(store: EvidenceStore, key: str, content: bytes) -> StoredEvidence:
    with store.open_writer(key) as writer:
        writer.write(content)
        return writer.seal()
