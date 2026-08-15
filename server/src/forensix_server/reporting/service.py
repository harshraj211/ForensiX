"""Immutable preliminary report generation and retrieval."""

from __future__ import annotations

import builtins
import hashlib
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
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    AcquisitionPlanRecord,
    AnalystNoteRecord,
    ArtifactRecord,
    ArtifactTagRecord,
    AuditLogRecord,
    BookmarkRecord,
    CaseDeviceAssessmentRecord,
    CaseDeviceRecord,
    CustodyEventRecord,
    Database,
    EvidenceParserRunRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceInspectionRecord,
    EvidenceSourceRecord,
    EvidenceSourceTimelineEventRecord,
    EvidenceSourceVerificationRecord,
    EvidenceToolOutputRecord,
    EvidenceVerificationRecord,
    EvidenceWorkingCopyRecord,
    ReportOutputRecord,
    ReportRecord,
    ReportReviewEventRecord,
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
    EvidenceInspectionSnapshot,
    EvidenceParserRunSnapshot,
    EvidenceSourceSnapshot,
    EvidenceSourceVerificationSnapshot,
    EvidenceToolOutputSnapshot,
    EvidenceWorkingCopySnapshot,
    HashManifestItem,
    ImportedArtifactSnapshot,
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
    latest_review: ReportReviewEventRecord | None = None


@dataclass(frozen=True, slots=True)
class ReportContent:
    output: ReportOutputRecord
    path: str


class ReportService:
    def generate(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        *,
        redaction_profile: str = "full",
    ) -> ReportBundle:
        if redaction_profile not in {"full", "mask_sensitive", "metadata_only"}:
            raise ReportError("The selected report redaction profile is unsupported.")
        report_id = str(uuid4())
        generated_at = datetime.now(UTC)
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            if not principal.can(Permission.REPORTS_GENERATE):
                raise CaseAccessDeniedError("The current user cannot generate reports.")
            snapshot = self._snapshot(
                session, principal, case_id, report_id, generated_at=generated_at
            )
            snapshot = _apply_redaction(snapshot, redaction_profile)
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
                redaction_profile=redaction_profile,
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
                    "redaction_profile": redaction_profile,
                },
                created_at=generated_at,
            )
            session.flush()
            return ReportBundle(report=report, outputs=tuple(outputs), latest_review=None)

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
        return [
            ReportBundle(
                item,
                tuple(self._outputs(session, item.id)),
                self._latest_review(session, item.id),
            )
            for item in reports
        ]

    def get(
        self, session: Session, principal: Principal, case_id: str, report_id: str
    ) -> ReportBundle:
        CaseService().get(session, principal, case_id)
        report = session.get(ReportRecord, report_id)
        if report is None or report.case_id != case_id:
            raise ReportNotFoundError("The requested report does not exist in this case.")
        return ReportBundle(
            report,
            tuple(self._outputs(session, report_id)),
            self._latest_review(session, report_id),
        )

    def review(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        report_id: str,
        *,
        decision: str,
        note: str,
    ) -> ReportBundle:
        if decision not in {"approved", "rejected"}:
            raise ReportError("The report review decision is unsupported.")
        normalized_note = note.strip()
        if not 5 <= len(normalized_note) <= 1000:
            raise ReportError("A review note between 5 and 1000 characters is required.")
        now = datetime.now(UTC)
        with database.session() as session:
            bundle = self.get(session, principal, case_id, report_id)
            if not principal.can(Permission.REPORTS_APPROVE):
                raise CaseAccessDeniedError("The current user cannot approve reports.")
            if bundle.report.generated_by == principal.user_id:
                raise ReportError("A report must be reviewed by a different authorized user.")
            store = EvidenceStore(database.data_dir / "evidence")
            if not store.verify(
                bundle.report.snapshot_storage_key, bundle.report.snapshot_sha256
            ) or any(not store.verify(item.storage_key, item.sha256) for item in bundle.outputs):
                raise ReportError("Report review was blocked by an integrity verification failure.")
            previous = self._latest_review(session, report_id)
            sequence = (previous.sequence if previous else 0) + 1
            previous_hash = previous.event_hash if previous else "0" * 64
            event_id = str(uuid4())
            canonical = {
                "case_id": case_id,
                "created_at": now.isoformat(),
                "decision": decision,
                "id": event_id,
                "note": normalized_note,
                "previous_hash": previous_hash,
                "report_id": report_id,
                "reviewed_by": principal.user_id,
                "sequence": sequence,
            }
            event_hash = hashlib.sha256(
                json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest()
            review = ReportReviewEventRecord(
                id=event_id,
                report_id=report_id,
                case_id=case_id,
                reviewed_by=principal.user_id,
                sequence=sequence,
                decision=decision,
                note=normalized_note,
                previous_hash=previous_hash,
                event_hash=event_hash,
                created_at=now,
            )
            session.add(review)
            session.flush()
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type=f"report.{decision}",
                object_type="report",
                object_id=report_id,
                detail={
                    "event_hash": event_hash,
                    "redaction_profile": bundle.report.redaction_profile,
                    "review_sequence": sequence,
                    "snapshot_sha256": bundle.report.snapshot_sha256,
                },
                created_at=now,
            )
            session.flush()
            return ReportBundle(bundle.report, bundle.outputs, review)

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

    @staticmethod
    def _latest_review(session: Session, report_id: str) -> ReportReviewEventRecord | None:
        return session.scalar(
            select(ReportReviewEventRecord)
            .where(ReportReviewEventRecord.report_id == report_id)
            .order_by(ReportReviewEventRecord.sequence.desc())
            .limit(1)
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
        inventory_items = {
            item.id: item
            for item in session.scalars(
                select(AcquisitionInventoryItemRecord).where(
                    AcquisitionInventoryItemRecord.inventory_id.in_(
                        [inventory.id for inventory in inventories]
                    )
                )
            )
        }
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
        evidence_sources = list(
            session.scalars(
                select(EvidenceSourceRecord)
                .where(EvidenceSourceRecord.case_id == case_id)
                .order_by(EvidenceSourceRecord.created_at, EvidenceSourceRecord.id)
            )
        )
        working_copies = list(
            session.scalars(
                select(EvidenceWorkingCopyRecord).where(
                    EvidenceWorkingCopyRecord.case_id == case_id
                )
            )
        )
        source_verifications = list(
            session.scalars(
                select(EvidenceSourceVerificationRecord).where(
                    EvidenceSourceVerificationRecord.case_id == case_id
                )
            )
        )
        source_inspections = list(
            session.scalars(
                select(EvidenceSourceInspectionRecord).where(
                    EvidenceSourceInspectionRecord.case_id == case_id
                )
            )
        )
        parser_runs = list(
            session.scalars(
                select(EvidenceParserRunRecord).where(EvidenceParserRunRecord.case_id == case_id)
            )
        )
        tool_outputs = list(
            session.scalars(
                select(EvidenceToolOutputRecord).where(EvidenceToolOutputRecord.case_id == case_id)
            )
        )
        parser_audits = list(
            session.scalars(
                select(AuditLogRecord).where(
                    AuditLogRecord.case_id == case_id,
                    AuditLogRecord.object_type == "evidence_parser_run",
                )
            )
        )
        imported_artifacts = list(
            session.scalars(
                select(EvidenceSourceArtifactRecord)
                .where(EvidenceSourceArtifactRecord.case_id == case_id)
                .order_by(
                    EvidenceSourceArtifactRecord.event_time,
                    EvidenceSourceArtifactRecord.created_at,
                    EvidenceSourceArtifactRecord.id,
                )
                .limit(1000)
            )
        )
        source_timeline = list(
            session.scalars(
                select(EvidenceSourceTimelineEventRecord)
                .where(EvidenceSourceTimelineEventRecord.case_id == case_id)
                .order_by(
                    EvidenceSourceTimelineEventRecord.event_time,
                    EvidenceSourceTimelineEventRecord.id,
                )
                .limit(500)
            )
        )
        timeline_snapshots = [
            TimelineSnapshot(
                artifact_id=item.artifact_id,
                source_artifact_id=None,
                parser_run_id=None,
                category=item.category,
                timestamp_type=item.timestamp_type,
                event_time=item.event_time,
                timezone_basis=item.timezone_basis,
                confidence=item.confidence,
                summary=item.summary,
                event_hash=item.event_hash,
            )
            for item in timeline
        ] + [
            TimelineSnapshot(
                artifact_id=None,
                source_artifact_id=item.source_artifact_id,
                parser_run_id=item.parser_run_id,
                category=item.category,
                timestamp_type=item.timestamp_type,
                event_time=item.event_time,
                timezone_basis=item.timezone_basis,
                confidence=item.confidence,
                summary=item.summary,
                event_hash=item.event_hash,
            )
            for item in source_timeline
        ]
        timeline_snapshots.sort(key=lambda item: (item.event_time, item.event_hash))
        return ReportSnapshot(
            report=ReportIdentity(
                report_id=report_id,
                generated_at=generated_at,
                generated_by_id=principal.user_id,
                generated_by_name=principal.display_name,
                preliminary_warning=PRELIMINARY_WARNING,
                redaction_profile="full",
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
            evidence_sources=[
                _evidence_source_snapshot(
                    item,
                    working_copies=working_copies,
                    verifications=source_verifications,
                    inspections=source_inspections,
                    parser_runs=parser_runs,
                    tool_outputs=tool_outputs,
                    parser_audits=parser_audits,
                )
                for item in evidence_sources
            ],
            imported_artifacts=[
                ImportedArtifactSnapshot(
                    id=item.id,
                    evidence_source_id=item.evidence_source_id,
                    parser_run_id=item.parser_run_id,
                    category=item.category,
                    subtype=item.subtype,
                    title=item.title,
                    summary=item.summary,
                    event_time=item.event_time,
                    source_locator=item.source_locator,
                    status=item.status,
                    confidence=item.confidence,
                    parser_id=item.parser_id,
                    parser_version=item.parser_version,
                    artifact_hash=item.artifact_hash,
                )
                for item in imported_artifacts
            ],
            imported_evidence_summary=dict(Counter(item.category for item in imported_artifacts)),
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
            timeline=timeline_snapshots[:500],
            hash_manifest=[
                HashManifestItem(
                    evidence_file_id=item.id,
                    source_relative_path=(
                        inventory_items[item.inventory_item_id].relative_path
                        if item.inventory_item_id in inventory_items
                        else "[inventory metadata unavailable]"
                    ),
                    storage_key=item.storage_key,
                    manifest_storage_key=item.manifest_storage_key,
                    status=item.status,
                    size_bytes=item.size_bytes,
                    file_sha256=item.sha256,
                    manifest_sha256=item.manifest_hash,
                    validation_state=item.validation_state,
                )
                for item in evidence
            ],
            integrity_summary=dict(
                Counter(
                    [item.status for item in verification]
                    + [item.status for item in source_verifications]
                )
            ),
            custody=[
                CustodySnapshot(
                    sequence=item.sequence,
                    event_type=item.event_type,
                    actor_id=item.actor_id,
                    evidence_file_id=item.evidence_file_id,
                    evidence_source_id=item.evidence_source_id,
                    parser_run_id=item.parser_run_id,
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
            ]
            + [
                f"Evidence source {item.id}: {item.error_code or item.status}"
                for item in evidence_sources
                if item.status == "failed"
            ]
            + [
                f"Parser {item.parser_id} ({item.id}): {item.error_code or item.status}"
                for item in parser_runs
                if item.status == "failed"
            ],
            limitations=[
                "ADB is not a hardware write blocker and may cause device-side effects.",
                "This is controlled logical triage, not physical acquisition or lock bypass.",
                "Private application data is unavailable unless separately and lawfully obtained.",
                "Device-side timestamps are not claimed when the source did not expose them.",
                "A local hash chain is tamper-evident, not tamper-proof.",
                "Imported-source sealing proves subsequent byte identity, not how the source "
                "was originally acquired.",
                "Third-party parser output is derived evidence and requires examiner validation "
                "against the sealed source and pinned parser version.",
            ],
            methodology=[
                "Case-authorized, capability-gated collection through predefined ADB operations.",
                "Files were sealed into contained local storage and hashed with SHA-256.",
                "Artifacts were normalized by versioned parsers; source evidence was not modified.",
                "Only active investigator bookmarks are included in the selected-artifact export.",
                "Imported masters were chunk-hashed, sealed, and examined through "
                "SHA-256-verified working copies.",
                "Imported Android artifacts retain parser version, source locator, run hash, "
                "and confidence provenance.",
            ],
            tool_version=__version__,
        )


def _apply_redaction(snapshot: ReportSnapshot, profile: str) -> ReportSnapshot:
    if profile == "full":
        return snapshot
    mask_sensitive = profile == "mask_sensitive"
    metadata_only = profile == "metadata_only"
    case = snapshot.case.model_copy(update={"description": None, "legal_authority": "[REDACTED]"})
    devices = [
        item.model_copy(
            update={
                "build_fingerprint": None,
                "latest_assessment": None if metadata_only else item.latest_assessment,
            }
        )
        for item in snapshot.devices
    ]
    selected_artifacts = (
        []
        if metadata_only
        else [
            item.model_copy(
                update={
                    "source_relative_path": "[REDACTED]",
                    "analyst_notes": [] if mask_sensitive else item.analyst_notes,
                }
            )
            for item in snapshot.selected_artifacts
        ]
    )
    imported_artifacts = (
        []
        if metadata_only
        else [
            item.model_copy(update={"summary": "[REDACTED]", "source_locator": "[REDACTED]"})
            for item in snapshot.imported_artifacts
        ]
    )
    timeline = (
        []
        if metadata_only
        else [item.model_copy(update={"summary": "[REDACTED]"}) for item in snapshot.timeline]
    )
    hash_manifest = [
        item.model_copy(
            update={
                "source_relative_path": "[REDACTED]",
                "storage_key": "[REDACTED]",
                "manifest_storage_key": "[REDACTED]",
            }
        )
        for item in snapshot.hash_manifest
    ]
    return snapshot.model_copy(
        update={
            "report": snapshot.report.model_copy(update={"redaction_profile": profile}),
            "case": case,
            "devices": devices,
            "selected_artifacts": selected_artifacts,
            "imported_artifacts": imported_artifacts,
            "timeline": timeline,
            "hash_manifest": hash_manifest,
            "limitations": snapshot.limitations + [f"Report redaction profile applied: {profile}."],
            "methodology": snapshot.methodology
            + ["Redaction was applied before rendering; sealed source evidence was unchanged."],
        }
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


def _evidence_source_snapshot(
    source: EvidenceSourceRecord,
    *,
    working_copies: list[EvidenceWorkingCopyRecord],
    verifications: list[EvidenceSourceVerificationRecord],
    inspections: list[EvidenceSourceInspectionRecord],
    parser_runs: list[EvidenceParserRunRecord],
    tool_outputs: list[EvidenceToolOutputRecord],
    parser_audits: list[AuditLogRecord],
) -> EvidenceSourceSnapshot:
    return EvidenceSourceSnapshot(
        id=source.id,
        display_name=source.display_name,
        source_name=source.source_name,
        source_type=source.source_type,
        acquisition_level=source.acquisition_level,
        status=source.status,
        container_format=source.container_format,
        size_bytes=source.size_bytes,
        sha256=source.sha256,
        chunks_sha256=source.chunks_sha256,
        manifest_sha256=source.manifest_sha256,
        chunk_size_bytes=source.chunk_size_bytes,
        chunk_count=source.chunk_count,
        read_only_applied=source.read_only_applied,
        validation_state=source.validation_state,
        limitations=_json_string_list(source.limitations_json),
        tool_version=source.tool_version,
        sealed_at=source.sealed_at,
        created_at=source.created_at,
        working_copies=[
            EvidenceWorkingCopySnapshot(
                id=item.id,
                status=item.status,
                size_bytes=item.size_bytes,
                expected_source_sha256=item.expected_source_sha256,
                observed_sha256=item.observed_sha256,
                copy_method=item.copy_method,
                verified_at=item.verified_at,
                created_at=item.created_at,
            )
            for item in working_copies
            if item.evidence_source_id == source.id
        ],
        verifications=[
            EvidenceSourceVerificationSnapshot(
                id=item.id,
                target_type=item.target_type,
                working_copy_id=item.working_copy_id,
                status=item.status,
                expected_sha256=item.expected_sha256,
                observed_sha256=item.observed_sha256,
                size_bytes=item.size_bytes,
                verification_hash=item.verification_hash,
                tool_version=item.tool_version,
                verified_at=item.verified_at,
            )
            for item in verifications
            if item.evidence_source_id == source.id
        ],
        inspections=[
            EvidenceInspectionSnapshot(
                id=item.id,
                working_copy_id=item.working_copy_id,
                detected_type=item.detected_type,
                confidence=item.confidence,
                encryption_state=item.encryption_state,
                signature=_json_object(item.signature_json),
                warnings=_json_string_list(item.warnings_json),
                detector_version=item.detector_version,
                inspection_hash=item.inspection_hash,
                inspected_at=item.inspected_at,
            )
            for item in inspections
            if item.evidence_source_id == source.id
        ],
        parser_runs=[
            EvidenceParserRunSnapshot(
                id=item.id,
                working_copy_id=item.working_copy_id,
                parser_id=item.parser_id,
                parser_version=item.parser_version,
                status=item.status,
                artifact_count=item.artifact_count,
                source_sha256=item.source_sha256,
                input_locator=item.input_locator,
                input_sha256=item.input_sha256,
                run_hash=item.run_hash,
                error_code=item.error_code,
                execution_detail=_parser_execution_detail(parser_audits, item.id),
                completed_at=item.completed_at,
            )
            for item in parser_runs
            if item.evidence_source_id == source.id
        ],
        tool_outputs=[
            EvidenceToolOutputSnapshot(
                id=item.id,
                parser_run_id=item.parser_run_id,
                relative_path=item.relative_path,
                size_bytes=item.size_bytes,
                sha256=item.sha256,
                created_at=item.created_at,
            )
            for item in tool_outputs
            if item.evidence_source_id == source.id
        ],
    )


def _json_string_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return ["Stored metadata could not be decoded."]
    if not isinstance(parsed, list):
        return ["Stored metadata was not a list."]
    return [str(item) for item in parsed]


def _json_object(value: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {"decode_error": True}
    return parsed if isinstance(parsed, dict) else {"invalid_shape": True}


def _parser_execution_detail(audits: list[AuditLogRecord], parser_run_id: str) -> dict[str, object]:
    matching = [item for item in audits if item.object_id == parser_run_id]
    if not matching:
        return {}
    return _json_object(matching[-1].detail_json)


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
