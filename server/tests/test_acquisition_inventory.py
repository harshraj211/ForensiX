import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

import pytest
from sqlalchemy import select, text

from forensix_forensic.adb import (
    AdbCommandError,
    AdbDeviceNotFoundError,
    MockAdbClient,
    MockAdbScenario,
    SharedStorageRoot,
    SharedStorageRootProbe,
    StorageProbeStatus,
)
from forensix_forensic.capabilities import (
    CapabilityDecision,
    CapabilityStatus,
    DeviceCapabilitySnapshot,
)
from forensix_server.acquisitions import (
    AcquisitionExecutionService,
    AcquisitionFileError,
    AcquisitionFileService,
    AcquisitionInventoryError,
    AcquisitionInventoryService,
    AcquisitionPlanService,
    AcquisitionRecoveryService,
    AcquisitionScope,
    DeviceIdentityChangedError,
    EvidenceVerificationService,
    PartialIntegrityChangedError,
)
from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.case_devices import CaseDeviceService
from forensix_server.cases import CaseService
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    AcquiredEvidenceFileRecord,
    AcquisitionInventoryItemRecord,
    AcquisitionInventoryRecord,
    AcquisitionPartialRecord,
    ArtifactRecord,
    AuditLogRecord,
    Database,
    EvidenceVerificationRecord,
    JobRecord,
    UserRecord,
)
from forensix_server.evidence import (
    AnalysisService,
    ArtifactError,
    ArtifactService,
    TimelineService,
)
from forensix_server.jobs import JobService, JobState


class _PartialDisconnectClient(MockAdbClient):
    async def pull_inventory_file(
        self,
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ) -> NoReturn:
        await asyncio.to_thread(destination.write_bytes, b"known interrupted bytes")
        raise AdbCommandError(1, "The controlled device disconnected during transfer.")


class _ProcessTermination(BaseException):
    pass


class _TerminatedTransferClient(MockAdbClient):
    async def pull_inventory_file(
        self,
        serial: str,
        root: SharedStorageRoot,
        relative_path: str,
        destination: Path,
    ) -> NoReturn:
        await asyncio.to_thread(destination.write_bytes, b"bytes present at process termination")
        raise _ProcessTermination


@pytest.fixture
def database(tmp_path: Path) -> Database:
    active = Database(f"sqlite:///{(tmp_path / 'inventory.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal(database: Database) -> Principal:
    with database.session() as session:
        user = UserRecord(
            username="inventory.owner",
            display_name="Inventory Owner",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        return Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.INVESTIGATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.INVESTIGATOR],
        )


def _decision(status: CapabilityStatus) -> CapabilityDecision:
    return CapabilityDecision(
        status=status,
        reason_code=f"TEST_{status.value.upper()}",
        explanation="Controlled inventory test decision.",
    )


def _snapshot() -> DeviceCapabilitySnapshot:
    return DeviceCapabilitySnapshot(
        assessed_at=datetime.now(UTC),
        serial="FX-DEMO-001",
        manufacturer="ForensiX Labs",
        model="Controlled Test Device",
        android_version="14",
        sdk_level=34,
        build_fingerprint="forensix/demo/fx_virtual:14/TEST/001:user/test-keys",
        security_patch="2026-07-01",
        package_count=3,
        storage_roots=tuple(
            SharedStorageRootProbe(
                root_id=root_id,
                display_path=display_path,
                status=StorageProbeStatus.ACCESSIBLE,
                exists=True,
                readable=True,
                reason_code="ROOT_READABLE",
            )
            for root_id, display_path in (
                ("primary_alias", "/sdcard"),
                ("emulated_primary", "/storage/emulated/0"),
            )
        ),
        capabilities={
            "device_metadata": _decision(CapabilityStatus.SUPPORTED),
            "package_inventory": _decision(CapabilityStatus.SUPPORTED),
            "shared_storage": _decision(CapabilityStatus.SUPPORTED),
        },
        warnings=("Controlled inventory fixture.",),
    )


def _ready_job(
    database: Database,
    principal: Principal,
    *,
    scope: AcquisitionScope = AcquisitionScope.QUICK_TRIAGE,
) -> tuple[str, str, str]:
    with database.session() as session:
        case = CaseService().create(session, principal, title="Bounded inventory case")
        device, assessment = CaseDeviceService().register_assessment(
            session, principal, case.id, _snapshot()
        )
        plan = AcquisitionPlanService().create(
            session,
            principal,
            case.id,
            device_id=device.id,
            assessment_id=assessment.id,
            scope=scope,
            limitations_acknowledged=True,
        )
        job, _ = AcquisitionExecutionService().prepare(session, principal, case.id, plan.id)
        return case.id, plan.id, job.id


@pytest.mark.asyncio
async def test_bounded_inventory_revalidates_persists_and_hashes_paths(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, plan_id, job_id = _ready_job(database, principal)
    service = AcquisitionInventoryService()

    inventory = await service.run(database, principal, case_id, job_id, MockAdbClient())
    repeated = await service.run(database, principal, case_id, job_id, MockAdbClient())

    assert repeated.id == inventory.id
    assert inventory.plan_id == plan_id
    assert inventory.root_id == "emulated_primary"
    assert inventory.status == "completed"
    assert inventory.discovered_count == inventory.persisted_count == 3
    assert len(inventory.manifest_hash) == 64
    with database.session() as session:
        job = session.get(JobRecord, job_id)
        items = list(
            session.scalars(
                select(AcquisitionInventoryItemRecord).order_by(
                    AcquisitionInventoryItemRecord.ordinal
                )
            )
        )
        events = JobService().list_events(session, job_id)
        inventories = list(session.scalars(select(AcquisitionInventoryRecord)))
    assert job is not None
    assert job.state == JobState.COMPLETED.value
    assert job.progress_percent == 100
    assert job.result_reference == inventory.id
    assert len(inventories) == 1
    assert [item.relative_path for item in items] == [
        "DCIM/Camera/IMG_0001.jpg",
        "Documents/timeline.csv",
        "Download/incident-notes.pdf",
    ]
    assert all(len(item.path_hash) == 64 for item in items)
    assert [item.extension for item in items] == ["jpg", "csv", "pdf"]
    assert events[-1].state == JobState.COMPLETED.value
    assert events[-1].checkpoint_json is not None


@pytest.mark.asyncio
async def test_plan_without_storage_module_cannot_run_inventory(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal, scope=AcquisitionScope.METADATA_ONLY)

    with pytest.raises(AcquisitionInventoryError, match="does not authorize"):
        await AcquisitionInventoryService().run(
            database, principal, case_id, job_id, MockAdbClient()
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.state == JobState.READY.value


@pytest.mark.asyncio
async def test_missing_live_device_fails_job_without_inventory(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)

    with pytest.raises(AdbDeviceNotFoundError):
        await AcquisitionInventoryService().run(
            database,
            principal,
            case_id,
            job_id,
            MockAdbClient(MockAdbScenario.NO_DEVICES),
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
        inventories = list(session.scalars(select(AcquisitionInventoryRecord)))
    assert job is not None
    assert job.state == JobState.FAILED.value
    assert job.error_code == "DEVICE_NOT_FOUND"
    assert inventories == []


@pytest.mark.asyncio
async def test_live_storage_block_is_recorded_as_failed_revalidation(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)

    with pytest.raises(AcquisitionInventoryError, match="no longer readable"):
        await AcquisitionInventoryService().run(
            database,
            principal,
            case_id,
            job_id,
            MockAdbClient(MockAdbScenario.STORAGE_BLOCKED),
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.state == JobState.FAILED.value
    assert job.error_code == "ACQUISITION_INVENTORY_INVALID"


class ChangedFingerprintClient(MockAdbClient):
    async def get_properties(self, serial: str) -> dict[str, str]:
        properties = await super().get_properties(serial)
        properties["ro.build.fingerprint"] = "changed/build/fingerprint"
        return properties


@pytest.mark.asyncio
async def test_build_fingerprint_change_blocks_inventory(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)

    with pytest.raises(DeviceIdentityChangedError):
        await AcquisitionInventoryService().run(
            database, principal, case_id, job_id, ChangedFingerprintClient()
        )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.error_code == "DEVICE_IDENTITY_CHANGED"


class CancellingInventoryClient(MockAdbClient):
    def __init__(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        job_id: str,
    ) -> None:
        super().__init__()
        self.database = database
        self.principal = principal
        self.case_id = case_id
        self.job_id = job_id

    async def inventory_shared_storage(self, serial, root):  # type: ignore[no-untyped-def]
        with self.database.session() as session:
            AcquisitionExecutionService().cancel(session, self.principal, self.case_id, self.job_id)
        return await super().inventory_shared_storage(serial, root)


@pytest.mark.asyncio
async def test_cancellation_preserves_completed_inventory_metadata(database: Database) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)
    client = CancellingInventoryClient(database, principal, case_id, job_id)

    inventory = await AcquisitionInventoryService().run(
        database, principal, case_id, job_id, client
    )

    with database.session() as session:
        job = session.get(JobRecord, job_id)
    assert job is not None
    assert job.state == JobState.CANCELLED.value
    assert job.result_reference == inventory.id
    assert inventory.persisted_count == 3


@pytest.mark.asyncio
async def test_selected_inventory_item_is_pulled_hashed_and_manifested(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)
    await AcquisitionInventoryService().run(database, principal, case_id, job_id, MockAdbClient())
    with database.session() as session:
        inventory = session.scalar(
            select(AcquisitionInventoryRecord).where(AcquisitionInventoryRecord.job_id == job_id)
        )
        assert inventory is not None
        item = session.scalar(
            select(AcquisitionInventoryItemRecord).where(
                AcquisitionInventoryItemRecord.inventory_id == inventory.id,
                AcquisitionInventoryItemRecord.relative_path == "Documents/timeline.csv",
            )
        )
        assert item is not None
        item_id = item.id

    service = AcquisitionFileService()
    acquired = await service.acquire(database, principal, case_id, job_id, item_id, MockAdbClient())
    repeated = await service.acquire(database, principal, case_id, job_id, item_id, MockAdbClient())

    payload = b"timestamp,event\n2026-07-16T00:00:00Z,test\n"
    evidence_path = database.data_dir / "evidence" / Path(acquired.storage_key)
    manifest_path = database.data_dir / "evidence" / Path(acquired.manifest_storage_key)
    assert repeated.id == acquired.id
    assert acquired.status == "completed"
    assert acquired.size_bytes == len(payload)
    assert acquired.sha256 == hashlib.sha256(payload).hexdigest()
    assert acquired.manifest_hash == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert evidence_path.read_bytes() == payload
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["source_relative_path"] == "Documents/timeline.csv"
    assert manifest["file_sha256"] == acquired.sha256
    assert manifest["validation_state"] == "not_physically_validated"
    with database.session() as session:
        records = list(session.scalars(select(AcquiredEvidenceFileRecord)))
    assert len(records) == 1


@pytest.mark.asyncio
async def test_completed_file_is_normalized_and_searchable_without_content_parsing(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, job_id, acquired = await _acquire_timeline_fixture(database, principal)

    with database.session() as session:
        artifacts = list(session.scalars(select(ArtifactRecord)))
        by_title = ArtifactService().search(
            session,
            principal,
            case_id,
            query="timeline",
            category="document",
            status="active",
            extension=".CSV",
        )
        content_not_indexed = ArtifactService().search(
            session, principal, case_id, query="timestamp"
        )
        backfilled = ArtifactService().backfill_completed(session)

    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.evidence_file_id == acquired.id
    assert artifact.title == "timeline.csv"
    assert artifact.source_relative_path == "Documents/timeline.csv"
    assert artifact.category == "document"
    assert artifact.detected_mime == "text/csv"
    assert artifact.primary_sha256 == acquired.sha256
    assert artifact.parser_id == "generic_file_metadata"
    assert json.loads(artifact.metadata_json)["content_parsed"] is False
    assert json.loads(artifact.metadata_json)["classification_basis"] == ("filename_extension_only")
    assert by_title.total == 1
    assert by_title.items[0].id == artifact.id
    assert by_title.category_facets == {"document": 1}
    assert content_not_indexed.total == 0
    assert backfilled == 0


@pytest.mark.asyncio
async def test_artifact_search_is_case_scoped_bounded_and_reindexable(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, _ = await _acquire_timeline_fixture(database, principal)
    other_case_id, _, _ = await _acquire_timeline_fixture(database, principal)

    with database.session() as session:
        first = session.scalar(select(ArtifactRecord).where(ArtifactRecord.case_id == case_id))
        assert first is not None
        session.execute(
            text("DELETE FROM artifact_search WHERE artifact_id = :artifact_id"),
            {"artifact_id": first.id},
        )
        assert ArtifactService().search(session, principal, case_id, query="timeline").total == 0
        ArtifactService().backfill_completed(session)
        restored = ArtifactService().search(session, principal, case_id, query="timeline")
        other = ArtifactService().search(session, principal, other_case_id, query="timeline")
        with pytest.raises(ArtifactError):
            ArtifactService().get(session, principal, other_case_id, first.id)
        with pytest.raises(ArtifactError, match="too complex"):
            ArtifactService().search(
                session,
                principal,
                case_id,
                query="one two three four five six seven eight nine",
            )

    assert restored.total == 1
    assert other.total == 1
    assert restored.items[0].case_id == case_id
    assert other.items[0].case_id == other_case_id


@pytest.mark.asyncio
async def test_timeline_is_deterministic_and_contains_only_collection_claim(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, acquired = await _acquire_timeline_fixture(database, principal)

    with database.session() as session:
        artifact = session.scalar(
            select(ArtifactRecord).where(ArtifactRecord.evidence_file_id == acquired.id)
        )
        assert artifact is not None
        first = TimelineService().materialize(session, artifact)
        repeated = TimelineService().materialize(session, artifact)
        result = TimelineService().search(
            session,
            principal,
            case_id,
            category="file",
            confidence="high",
        )
        backfilled = TimelineService().backfill(session)

    assert repeated.id == first.id
    assert repeated.event_hash == first.event_hash
    assert result.total == 1
    assert result.category_facets == {"file": 1}
    assert result.items[0].timestamp_type == "acquisition_collected_at"
    assert result.items[0].event_time == artifact.collected_at
    assert result.items[0].timezone_basis == "UTC recorded by acquisition workstation"
    assert "modified" not in result.items[0].timestamp_type
    assert backfilled == 0


@pytest.mark.asyncio
async def test_analyst_annotations_do_not_modify_artifact_and_notes_are_append_only(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, acquired = await _acquire_timeline_fixture(database, principal)
    service = AnalysisService()

    with database.session() as session:
        artifact = session.scalar(
            select(ArtifactRecord).where(ArtifactRecord.evidence_file_id == acquired.id)
        )
        assert artifact is not None
        source_hash = artifact.primary_sha256
        bookmark = service.bookmark(
            session, principal, case_id, artifact.id, reason="Review for report"
        )
        repeated_bookmark = service.bookmark(
            session, principal, case_id, artifact.id, reason="Review for report"
        )
        tag = service.add_tag(session, principal, case_id, artifact.id, "Priority Evidence")
        repeated_tag = service.add_tag(
            session, principal, case_id, artifact.id, "priority   evidence"
        )
        note = service.add_note(
            session, principal, case_id, artifact.id, "Initial analyst observation."
        )
        amendment = service.add_note(
            session,
            principal,
            case_id,
            artifact.id,
            "Corrected analyst observation.",
            supersedes_id=note.id,
        )
        active_bookmark, tags, notes = service.annotations(session, principal, case_id, artifact.id)
        persisted_artifact = session.get(ArtifactRecord, artifact.id)
        audit_events = list(session.scalars(select(AuditLogRecord)))

    assert repeated_bookmark.id == bookmark.id
    assert repeated_tag.id == tag.id
    assert active_bookmark is not None
    assert [item.normalized_name for item in tags] == ["priority evidence"]
    assert [item.id for item in notes] == [note.id, amendment.id]
    assert amendment.supersedes_id == note.id
    assert persisted_artifact is not None
    assert persisted_artifact.primary_sha256 == source_hash
    assert {event.event_type for event in audit_events} >= {
        "artifact_bookmarked",
        "artifact_tag_added",
        "analyst_note_added",
        "analyst_note_amended",
    }


@pytest.mark.asyncio
async def test_file_acquisition_revalidates_device_and_records_failure(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)
    await AcquisitionInventoryService().run(database, principal, case_id, job_id, MockAdbClient())
    with database.session() as session:
        item = session.scalar(select(AcquisitionInventoryItemRecord))
        assert item is not None
        item_id = item.id

    with pytest.raises(AdbDeviceNotFoundError):
        await AcquisitionFileService().acquire(
            database,
            principal,
            case_id,
            job_id,
            item_id,
            MockAdbClient(MockAdbScenario.NO_DEVICES),
        )

    with database.session() as session:
        record = session.scalar(select(AcquiredEvidenceFileRecord))
    assert record is not None
    assert record.status == "failed"
    assert record.error_code == "DEVICE_NOT_FOUND"
    assert record.sha256 is None


@pytest.mark.asyncio
async def test_interrupted_partial_requires_review_before_byte_zero_restart(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)
    await AcquisitionInventoryService().run(database, principal, case_id, job_id, MockAdbClient())
    with database.session() as session:
        item = session.scalar(select(AcquisitionInventoryItemRecord))
        assert item is not None
        item_id = item.id

    with pytest.raises(AdbCommandError):
        await AcquisitionFileService().acquire(
            database,
            principal,
            case_id,
            job_id,
            item_id,
            _PartialDisconnectClient(),
        )

    with database.session() as session:
        evidence = session.scalar(select(AcquiredEvidenceFileRecord))
        partial = session.scalar(select(AcquisitionPartialRecord))
    assert evidence is not None
    assert partial is not None
    assert evidence.status == "failed"
    assert evidence.partial_preserved is True
    assert partial.status == "retained"
    assert partial.size_bytes == len(b"known interrupted bytes")
    assert partial.sha256 == hashlib.sha256(b"known interrupted bytes").hexdigest()
    partial_path = database.data_dir / "evidence" / Path(partial.storage_key)
    assert partial_path.read_bytes() == b"known interrupted bytes"

    with pytest.raises(AcquisitionFileError, match="Review whether"):
        await AcquisitionFileService().acquire(
            database, principal, case_id, job_id, item_id, MockAdbClient()
        )

    reviewed = AcquisitionRecoveryService().review_pending(
        database,
        principal,
        case_id,
        job_id,
        evidence.id,
        disposition="retain",
    )
    restarted = await AcquisitionFileService().acquire(
        database, principal, case_id, job_id, item_id, MockAdbClient()
    )

    assert reviewed[0].disposition_by == principal.user_id
    assert partial_path.exists()
    assert restarted.status == "completed"
    with database.session() as session:
        attempts = list(
            session.scalars(
                select(AcquisitionPartialRecord).order_by(AcquisitionPartialRecord.created_at)
            )
        )
    assert [attempt.status for attempt in attempts] == ["retained", "sealed"]


@pytest.mark.asyncio
async def test_backend_restart_reconciles_then_verified_discard_allows_restart(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)
    await AcquisitionInventoryService().run(database, principal, case_id, job_id, MockAdbClient())
    with database.session() as session:
        item = session.scalar(select(AcquisitionInventoryItemRecord))
        assert item is not None
        item_id = item.id

    with pytest.raises(_ProcessTermination):
        await AcquisitionFileService().acquire(
            database,
            principal,
            case_id,
            job_id,
            item_id,
            _TerminatedTransferClient(),
        )
    with database.session() as session:
        before = session.scalar(select(AcquisitionPartialRecord))
        evidence = session.scalar(select(AcquiredEvidenceFileRecord))
    assert before is not None and before.status == "active"
    assert evidence is not None and evidence.status == "acquiring"

    reconciled = AcquisitionRecoveryService().recover_after_restart(database)

    with database.session() as session:
        partial = session.get(AcquisitionPartialRecord, before.id)
        interrupted = session.get(AcquiredEvidenceFileRecord, evidence.id)
    assert reconciled == 1
    assert partial is not None and partial.status == "retained"
    assert partial.sha256 == hashlib.sha256(b"bytes present at process termination").hexdigest()
    assert interrupted is not None and interrupted.status == "interrupted"
    assert interrupted.error_code == "SERVICE_RESTARTED"
    partial_path = database.data_dir / "evidence" / Path(partial.storage_key)

    await asyncio.to_thread(partial_path.write_bytes, b"tampered partial")
    with pytest.raises(PartialIntegrityChangedError):
        AcquisitionRecoveryService().review_pending(
            database,
            principal,
            case_id,
            job_id,
            evidence.id,
            disposition="discard",
        )
    assert partial_path.exists()
    await asyncio.to_thread(partial_path.write_bytes, b"bytes present at process termination")
    AcquisitionRecoveryService().review_pending(
        database,
        principal,
        case_id,
        job_id,
        evidence.id,
        disposition="discard",
    )
    assert not partial_path.exists()
    restarted = await AcquisitionFileService().acquire(
        database, principal, case_id, job_id, item_id, MockAdbClient()
    )
    assert restarted.status == "completed"


@pytest.mark.asyncio
async def test_file_acquisition_rejects_inventory_item_from_another_job(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, job_id = _ready_job(database, principal)
    await AcquisitionInventoryService().run(database, principal, case_id, job_id, MockAdbClient())
    other_case_id, _, other_job_id = _ready_job(database, principal)
    await AcquisitionInventoryService().run(
        database, principal, other_case_id, other_job_id, MockAdbClient()
    )
    with database.session() as session:
        other_inventory = session.scalar(
            select(AcquisitionInventoryRecord).where(
                AcquisitionInventoryRecord.job_id == other_job_id
            )
        )
        assert other_inventory is not None
        other_item = session.scalar(
            select(AcquisitionInventoryItemRecord).where(
                AcquisitionInventoryItemRecord.inventory_id == other_inventory.id
            )
        )
        assert other_item is not None
        other_item_id = other_item.id

    with pytest.raises(AcquisitionFileError, match="not issued"):
        await AcquisitionFileService().acquire(
            database,
            principal,
            case_id,
            job_id,
            other_item_id,
            MockAdbClient(),
        )


async def _acquire_timeline_fixture(
    database: Database, principal: Principal
) -> tuple[str, str, AcquiredEvidenceFileRecord]:
    case_id, _, job_id = _ready_job(database, principal)
    await AcquisitionInventoryService().run(database, principal, case_id, job_id, MockAdbClient())
    with database.session() as session:
        inventory = session.scalar(
            select(AcquisitionInventoryRecord).where(AcquisitionInventoryRecord.job_id == job_id)
        )
        assert inventory is not None
        item = session.scalar(
            select(AcquisitionInventoryItemRecord).where(
                AcquisitionInventoryItemRecord.inventory_id == inventory.id,
                AcquisitionInventoryItemRecord.relative_path == "Documents/timeline.csv",
            )
        )
        assert item is not None
        item_id = item.id
    acquired = await AcquisitionFileService().acquire(
        database, principal, case_id, job_id, item_id, MockAdbClient()
    )
    return case_id, job_id, acquired


@pytest.mark.asyncio
async def test_evidence_verification_is_append_only_and_matches_known_hashes(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, job_id, acquired = await _acquire_timeline_fixture(database, principal)
    service = EvidenceVerificationService()

    first = await service.verify(database, principal, case_id, job_id, acquired.id)
    second = await service.verify(database, principal, case_id, job_id, acquired.id)

    assert first.status == second.status == "verified"
    assert first.file_matches is True
    assert first.manifest_matches is True
    assert first.observed_file_sha256 == acquired.sha256
    assert first.observed_manifest_sha256 == acquired.manifest_hash
    assert first.id != second.id
    assert first.verification_hash != second.verification_hash
    with database.session() as session:
        records = list(session.scalars(select(EvidenceVerificationRecord)))
    assert len(records) == 2


@pytest.mark.asyncio
async def test_evidence_verification_records_mismatch_without_overwriting_expected_hash(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, job_id, acquired = await _acquire_timeline_fixture(database, principal)
    expected_sha256 = acquired.sha256
    evidence_path = database.data_dir / "evidence" / Path(acquired.storage_key)
    evidence_path.write_bytes(b"tampered bytes")

    verification = await EvidenceVerificationService().verify(
        database, principal, case_id, job_id, acquired.id
    )

    assert verification.status == "mismatch"
    assert verification.file_matches is False
    assert verification.manifest_matches is True
    assert verification.expected_file_sha256 == expected_sha256
    assert verification.observed_file_sha256 == hashlib.sha256(b"tampered bytes").hexdigest()
    with database.session() as session:
        persisted = session.get(AcquiredEvidenceFileRecord, acquired.id)
    assert persisted is not None
    assert persisted.sha256 == expected_sha256


@pytest.mark.asyncio
async def test_evidence_verification_records_missing_manifest(database: Database) -> None:
    principal = _principal(database)
    case_id, job_id, acquired = await _acquire_timeline_fixture(database, principal)
    manifest_path = database.data_dir / "evidence" / Path(acquired.manifest_storage_key)
    manifest_path.unlink()

    verification = await EvidenceVerificationService().verify(
        database, principal, case_id, job_id, acquired.id
    )

    assert verification.status == "missing"
    assert verification.file_matches is True
    assert verification.manifest_matches is False
    assert verification.error_code == "EVIDENCE_MISSING"


@pytest.mark.asyncio
async def test_acquisition_and_verification_append_chained_custody_and_audit(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, job_id, acquired = await _acquire_timeline_fixture(database, principal)
    await EvidenceVerificationService().verify(database, principal, case_id, job_id, acquired.id)

    with database.session() as session:
        custody = CustodyService().list(session, principal, case_id)
        custody_valid, broken = CustodyService().verify_chain(session, principal, case_id)
        audits = list(session.scalars(select(AuditLogRecord).order_by(AuditLogRecord.sequence)))

    assert [event.event_type for event in custody] == [
        "evidence_registered",
        "integrity_verified",
    ]
    assert custody[0].previous_hash == "0" * 64
    assert custody[1].previous_hash == custody[0].event_hash
    assert custody_valid is True
    assert broken is None
    assert len(audits) == 2
    assert audits[1].previous_hash == audits[0].entry_hash


@pytest.mark.asyncio
async def test_custody_transfer_correction_is_append_only_amendment(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, acquired = await _acquire_timeline_fixture(database, principal)
    with database.session() as session:
        transfer = CustodyService().create_manual(
            session,
            principal,
            case_id,
            event_type="transferred",
            evidence_file_id=acquired.id,
            from_custodian="Investigator A",
            to_custodian="Forensic Lab",
            location="Evidence locker 4",
            purpose="Laboratory examination",
            notes=None,
            related_event_id=None,
        )
        transfer_id = transfer.id
    with database.session() as session:
        amendment = CustodyService().create_manual(
            session,
            principal,
            case_id,
            event_type="amendment",
            evidence_file_id=acquired.id,
            from_custodian=None,
            to_custodian=None,
            location=None,
            purpose=None,
            notes="Correct locker reference is evidence locker 5.",
            related_event_id=transfer_id,
        )
        events = CustodyService().list(session, principal, case_id)

    assert amendment.related_event_id == transfer_id
    assert [event.event_type for event in events] == [
        "evidence_registered",
        "transferred",
        "amendment",
    ]
    assert events[1].location == "Evidence locker 4"


@pytest.mark.asyncio
async def test_custody_and_audit_verification_detect_database_tampering(
    database: Database,
) -> None:
    principal = _principal(database)
    case_id, _, _ = await _acquire_timeline_fixture(database, principal)
    audit_principal = Principal(
        user_id=principal.user_id,
        username=principal.username,
        display_name=principal.display_name,
        roles=frozenset({RoleName.ADMINISTRATOR}),
        permissions=ROLE_PERMISSIONS[RoleName.ADMINISTRATOR],
    )
    with database.engine.begin() as connection:
        connection.execute(
            text("UPDATE custody_events SET purpose = 'tampered' WHERE sequence = 1")
        )
        connection.execute(text("UPDATE audit_logs SET event_type = 'tampered' WHERE sequence = 1"))
    with database.session() as session:
        custody_valid, custody_broken = CustodyService().verify_chain(session, principal, case_id)
        audit_valid, audit_broken = AuditService().verify(session, audit_principal)

    assert custody_valid is False
    assert custody_broken == 1
    assert audit_valid is False
    assert audit_broken == 1
