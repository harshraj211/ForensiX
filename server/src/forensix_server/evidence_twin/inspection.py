"""Read-only signature inspection for verified Evidence Twin working copies."""

import json
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import select

from forensix_forensic.storage import EvidenceStore
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError
from forensix_server.custody import AuditService
from forensix_server.db import (
    Database,
    EvidenceSourceInspectionRecord,
    EvidenceWorkingCopyRecord,
)

from .service import (
    EvidenceTwinError,
    EvidenceTwinIntegrityError,
    EvidenceTwinNotFoundError,
    EvidenceTwinService,
)

DETECTOR_VERSION = "1.0.0"
DetectedType = Literal[
    "zip", "tar", "sqlite", "android_sparse", "ext4", "f2fs", "opaque", "unknown"
]
Confidence = Literal["high", "medium", "low"]
EncryptionState = Literal["not_detected", "suspected", "unknown"]


@dataclass(frozen=True, slots=True)
class InspectionDecision:
    detected_type: DetectedType
    confidence: Confidence
    encryption_state: EncryptionState
    signature: dict[str, Any]
    warnings: tuple[str, ...]


class EvidenceInspectionService:
    def inspect_working_copy(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceSourceInspectionRecord:
        source = EvidenceTwinService().get_source(database, principal, case_id, source_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot inspect evidence sources.")
        with database.session() as session:
            copy = session.get(EvidenceWorkingCopyRecord, working_copy_id)
            if copy is None or copy.case_id != case_id or copy.evidence_source_id != source_id:
                raise EvidenceTwinNotFoundError(
                    "The requested Evidence Twin working copy does not exist."
                )
            if copy.status != "ready":
                raise EvidenceTwinError("Only a verified working copy can be inspected.")
            existing = session.scalar(
                select(EvidenceSourceInspectionRecord).where(
                    EvidenceSourceInspectionRecord.working_copy_id == working_copy_id
                )
            )
            if existing is not None:
                return existing
        store = EvidenceStore(database.data_dir / "evidence")
        path = store.resolve(copy.storage_key, require_file=True)
        decision = detect_evidence_container(path)
        now = datetime.now(UTC)
        payload = {
            "case_id": case_id,
            "confidence": decision.confidence,
            "detected_type": decision.detected_type,
            "detector_version": DETECTOR_VERSION,
            "encryption_state": decision.encryption_state,
            "evidence_source_id": source.id,
            "inspected_at": now.isoformat(),
            "signature": decision.signature,
            "warnings": list(decision.warnings),
            "working_copy_id": copy.id,
        }
        record = EvidenceSourceInspectionRecord(
            evidence_source_id=source.id,
            working_copy_id=copy.id,
            case_id=case_id,
            inspected_by=principal.user_id,
            detected_type=decision.detected_type,
            confidence=decision.confidence,
            encryption_state=decision.encryption_state,
            signature_json=_canonical_json(decision.signature),
            warnings_json=_canonical_json(list(decision.warnings)),
            detector_version=DETECTOR_VERSION,
            inspection_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
            inspected_at=now,
        )
        with database.session() as session:
            session.add(record)
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="evidence_working_copy_inspected",
                object_type="evidence_working_copy",
                object_id=copy.id,
                detail={
                    "detected_type": decision.detected_type,
                    "encryption_state": decision.encryption_state,
                    "inspection_hash": record.inspection_hash,
                },
                created_at=now,
            )
            session.flush()
            return record

    def get_for_working_copy(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        source_id: str,
        working_copy_id: str,
    ) -> EvidenceSourceInspectionRecord:
        EvidenceTwinService().get_source(database, principal, case_id, source_id)
        with database.session() as session:
            record = session.scalar(
                select(EvidenceSourceInspectionRecord).where(
                    EvidenceSourceInspectionRecord.working_copy_id == working_copy_id,
                    EvidenceSourceInspectionRecord.evidence_source_id == source_id,
                    EvidenceSourceInspectionRecord.case_id == case_id,
                )
            )
            if record is None:
                raise EvidenceTwinNotFoundError(
                    "No inspection exists for this Evidence Twin working copy."
                )
            return record


def detect_evidence_container(path: Path) -> InspectionDecision:
    """Classify bytes without mounting, executing, or trusting the filename."""
    with path.open("rb") as stream:
        header = stream.read(4096)
    if header[:4] == b"\x3a\xff\x26\xed":
        return _image_decision("android_sparse", "Android sparse image magic")
    if len(header) >= 1082 and header[1080:1082] == b"\x53\xef":
        return _image_decision("ext4", "ext4 superblock magic")
    if len(header) >= 1028 and header[1024:1028] == b"\x10\x20\xf5\xf2":
        return _image_decision("f2fs", "F2FS superblock magic")
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            encrypted = any(item.flag_bits & 0x1 for item in archive.infolist())
            signature = {
                "entry_count": len(archive.infolist()),
                "magic": "PK",
            }
        return InspectionDecision(
            detected_type="zip",
            confidence="high",
            encryption_state="suspected" if encrypted else "not_detected",
            signature=signature,
            warnings=(
                "Encrypted ZIP entries require examiner-supplied credentials and are not extracted."
                if encrypted
                else "Archive members must pass safe-extraction policy before parsing.",
            ),
        )
    if tarfile.is_tarfile(path):
        return InspectionDecision(
            detected_type="tar",
            confidence="high",
            encryption_state="unknown",
            signature={"ustar_marker": header[257:263].rstrip(b"\x00").decode("ascii", "ignore")},
            warnings=("Archive members must pass safe-extraction policy before parsing.",),
        )
    if header.startswith(b"SQLite format 3\x00"):
        return InspectionDecision(
            detected_type="sqlite",
            confidence="high",
            encryption_state="not_detected",
            signature={"magic": "SQLite format 3"},
            warnings=("SQLite examination uses read-only immutable connections.",),
        )
    if header:
        return InspectionDecision(
            detected_type="opaque",
            confidence="low",
            encryption_state="unknown",
            signature={"sample_sha256": sha256(header).hexdigest(), "sample_size": len(header)},
            warnings=(
                "No supported container signature was recognized; "
                "the source is not mounted automatically.",
            ),
        )
    return InspectionDecision(
        detected_type="unknown",
        confidence="low",
        encryption_state="unknown",
        signature={"sample_size": 0},
        warnings=("The working copy is empty or unreadable.",),
    )


def _image_decision(detected_type: DetectedType, signature_name: str) -> InspectionDecision:
    return InspectionDecision(
        detected_type=detected_type,
        confidence="high",
        encryption_state="unknown",
        signature={"magic": signature_name},
        warnings=(
            "A filesystem signature does not prove that Android user data is decrypted.",
            "ForensiX does not mount block images automatically in the application process.",
        ),
    )


def inspection_signature(record: EvidenceSourceInspectionRecord) -> dict[str, Any]:
    value: object = json.loads(record.signature_json)
    if not isinstance(value, dict):
        raise EvidenceTwinIntegrityError("The stored inspection signature is malformed.")
    return {str(key): item for key, item in value.items()}


def inspection_warnings(record: EvidenceSourceInspectionRecord) -> list[str]:
    value: object = json.loads(record.warnings_json)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise EvidenceTwinIntegrityError("The stored inspection warnings are malformed.")
    return [item for item in value if isinstance(item, str)]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
