"""Durable custody/audit checkpoint exports for independent external anchoring."""

from __future__ import annotations

import json
import re
from base64 import b64decode
from binascii import Error as Base64Error
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from sqlalchemy import select

from forensix_forensic.storage import EvidenceStore
from forensix_server import __version__
from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseInvalidStateError, CaseService
from forensix_server.custody import AuditService, CustodyService
from forensix_server.db import (
    AuditLogRecord,
    CustodyCheckpointAnchorRecord,
    CustodyCheckpointRecord,
    CustodyCheckpointSignatureRecord,
    CustodyEventRecord,
    Database,
)

CHECKPOINT_SCHEMA_VERSION = "1.0.0"
MAX_CERTIFICATE_PEM_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024


class CustodyCheckpointError(CaseInvalidStateError):
    code = "CUSTODY_CHECKPOINT_INVALID"


class CustodyCheckpointNotFoundError(CustodyCheckpointError):
    code = "CUSTODY_CHECKPOINT_NOT_FOUND"


class CustodyCheckpointIntegrityError(CustodyCheckpointError):
    code = "CUSTODY_CHECKPOINT_INTEGRITY_FAILED"


@dataclass(frozen=True, slots=True)
class CustodyCheckpointContent:
    record: CustodyCheckpointRecord
    path: Path


class CustodyCheckpointService:
    """Seal a verified point-in-time chain snapshot without claiming external anchoring."""

    def create(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
    ) -> CustodyCheckpointRecord:
        self._require_export_permission(principal)
        checkpoint_id = str(uuid4())
        created_at = datetime.now(UTC)
        with database.session() as session:
            case = CaseService().get(session, principal, case_id)
            custody_valid, custody_broken = CustodyService().verify_chain(
                session, principal, case_id
            )
            audit_valid, audit_broken = AuditService().verify(session, principal)
            if not custody_valid:
                raise CustodyCheckpointIntegrityError(
                    f"Custody chain verification failed at sequence {custody_broken}."
                )
            if not audit_valid:
                raise CustodyCheckpointIntegrityError(
                    f"Audit chain verification failed at sequence {audit_broken}."
                )
            custody = CustodyService().list(session, principal, case_id)
            audits = AuditService().list(session, principal, limit=None)
            case_audits = [item for item in audits if item.case_id == case_id]
            audit_head = audits[-1] if audits else None
            payload = {
                "anchor_status": "not_externally_anchored",
                "audit_checkpoint": {
                    "case_entries": [_audit_payload(item) for item in case_audits],
                    "global_head_hash": audit_head.entry_hash if audit_head else None,
                    "global_sequence": audit_head.sequence if audit_head else 0,
                    "verified_before_export": True,
                },
                "case": {
                    "case_number": case.case_number,
                    "id": case.id,
                    "status": case.status,
                    "title": case.title,
                },
                "checkpoint_id": checkpoint_id,
                "created_at": _iso(created_at),
                "created_by": principal.user_id,
                "custody_chain": {
                    "events": [_custody_payload(item) for item in custody],
                    "head_hash": custody[-1].event_hash if custody else None,
                    "record_count": len(custody),
                    "verified_before_export": True,
                },
                "limitations": [
                    "This file is hash sealed but has not been externally timestamped or signed.",
                    "The audit head predates the audit event recording this export.",
                    "Independent preservation or publication of the SHA-256 is required "
                    "for anchoring.",
                ],
                "schema_version": CHECKPOINT_SCHEMA_VERSION,
                "tool": {"name": "ForensiX", "version": __version__},
            }
            content = _canonical_bytes(payload)
            safe_case = re.sub(r"[^A-Za-z0-9._-]", "_", case.case_number)
            filename = f"ForensiX_{safe_case}_CustodyCheckpoint_{checkpoint_id[:8]}.json"
            store = EvidenceStore(database.data_dir / "evidence")
            with store.open_writer(
                f"custody-checkpoints/{case_id}/{checkpoint_id}/checkpoint.json"
            ) as writer:
                writer.write(content)
                stored = writer.seal()
            record = CustodyCheckpointRecord(
                id=checkpoint_id,
                case_id=case_id,
                created_by=principal.user_id,
                custody_record_count=len(custody),
                custody_head_hash=custody[-1].event_hash if custody else None,
                audit_sequence=audit_head.sequence if audit_head else 0,
                audit_head_hash=audit_head.entry_hash if audit_head else None,
                filename=filename,
                storage_key=stored.storage_key,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
                schema_version=CHECKPOINT_SCHEMA_VERSION,
                created_at=created_at,
            )
            session.add(record)
            session.flush()
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="custody_checkpoint.created",
                object_type="custody_checkpoint",
                object_id=checkpoint_id,
                detail={
                    "anchor_status": "not_externally_anchored",
                    "audit_head_hash": record.audit_head_hash,
                    "audit_sequence": record.audit_sequence,
                    "custody_head_hash": record.custody_head_hash,
                    "sha256": record.sha256,
                },
                created_at=created_at,
            )
            session.flush()
            return record

    def list(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
    ) -> list[CustodyCheckpointRecord]:
        self._require_export_permission(principal)
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            return list(
                session.scalars(
                    select(CustodyCheckpointRecord)
                    .where(CustodyCheckpointRecord.case_id == case_id)
                    .order_by(
                        CustodyCheckpointRecord.created_at.desc(),
                        CustodyCheckpointRecord.id.desc(),
                    )
                )
            )

    def create_anchor(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        checkpoint_id: str,
        *,
        anchor_type: str,
        anchor_provider: str,
        anchor_reference: str,
        anchored_at: datetime,
        checkpoint_sha256: str,
        receipt_sha256: str | None = None,
        notes: str | None = None,
    ) -> CustodyCheckpointAnchorRecord:
        self._require_export_permission(principal)
        recorded_at = datetime.now(UTC)
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            record = session.get(CustodyCheckpointRecord, checkpoint_id)
            if record is None or record.case_id != case_id:
                raise CustodyCheckpointNotFoundError(
                    "The requested custody checkpoint does not exist in this case."
                )
            if checkpoint_sha256 != record.sha256:
                raise CustodyCheckpointIntegrityError(
                    "The acknowledged checkpoint SHA-256 does not match the sealed checkpoint."
                )
            store = EvidenceStore(database.data_dir / "evidence")
            if not store.verify(record.storage_key, record.sha256):
                raise CustodyCheckpointIntegrityError(
                    "The custody checkpoint no longer matches its recorded SHA-256."
                )
            canonical = {
                "anchor_provider": anchor_provider,
                "anchor_reference": anchor_reference,
                "anchor_type": anchor_type,
                "anchored_at": _iso(anchored_at),
                "case_id": case_id,
                "checkpoint_id": checkpoint_id,
                "checkpoint_sha256": checkpoint_sha256,
                "notes": notes,
                "receipt_sha256": receipt_sha256,
                "recorded_by": principal.user_id,
                "schema_version": "1.0.0",
            }
            anchor = CustodyCheckpointAnchorRecord(
                case_id=case_id,
                checkpoint_id=checkpoint_id,
                recorded_by=principal.user_id,
                anchor_type=anchor_type,
                anchor_provider=anchor_provider,
                anchor_reference=anchor_reference,
                anchored_at=anchored_at,
                checkpoint_sha256=checkpoint_sha256,
                receipt_sha256=receipt_sha256,
                notes=notes,
                anchor_hash=sha256(_canonical_bytes(canonical)).hexdigest(),
                created_at=recorded_at,
            )
            session.add(anchor)
            session.flush()
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="custody_checkpoint.anchor_recorded",
                object_type="custody_checkpoint",
                object_id=checkpoint_id,
                detail={
                    "anchor_hash": anchor.anchor_hash,
                    "anchor_provider": anchor.anchor_provider,
                    "anchor_type": anchor.anchor_type,
                    "checkpoint_sha256": anchor.checkpoint_sha256,
                    "receipt_sha256": anchor.receipt_sha256,
                },
                created_at=recorded_at,
            )
            session.flush()
            return anchor

    def list_anchors(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        checkpoint_id: str,
    ) -> Sequence[CustodyCheckpointAnchorRecord]:
        self._require_export_permission(principal)
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            record = session.get(CustodyCheckpointRecord, checkpoint_id)
            if record is None or record.case_id != case_id:
                raise CustodyCheckpointNotFoundError(
                    "The requested custody checkpoint does not exist in this case."
                )
            return list(
                session.scalars(
                    select(CustodyCheckpointAnchorRecord)
                    .where(CustodyCheckpointAnchorRecord.checkpoint_id == checkpoint_id)
                    .order_by(
                        CustodyCheckpointAnchorRecord.created_at.desc(),
                        CustodyCheckpointAnchorRecord.id.desc(),
                    )
                )
            )

    def verify_signature(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        checkpoint_id: str,
        *,
        signature_algorithm: str,
        certificate_pem: str,
        signature_base64: str,
        signed_at: datetime,
        checkpoint_sha256: str,
    ) -> CustodyCheckpointSignatureRecord:
        self._require_export_permission(principal)
        verified_at = datetime.now(UTC)
        normalized_signed_at = _utc(signed_at)
        certificate_bytes = certificate_pem.encode("utf-8")
        if not certificate_bytes or len(certificate_bytes) > MAX_CERTIFICATE_PEM_BYTES:
            raise CustodyCheckpointError("The signer certificate exceeds the 16 KiB limit.")
        try:
            signature = b64decode(signature_base64, validate=True)
        except (Base64Error, ValueError) as error:
            raise CustodyCheckpointError("The detached signature is not valid base64.") from error
        if not signature or len(signature) > MAX_SIGNATURE_BYTES:
            raise CustodyCheckpointError("The detached signature exceeds the 4 KiB limit.")
        try:
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
        except ValueError as error:
            raise CustodyCheckpointError(
                "The signer certificate is not valid PEM X.509."
            ) from error
        if not (
            certificate.not_valid_before_utc
            <= normalized_signed_at
            <= certificate.not_valid_after_utc
        ):
            raise CustodyCheckpointError(
                "The signer certificate was not valid at the declared signing time."
            )
        try:
            key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            key_usage = None
        if key_usage is not None and not key_usage.digital_signature:
            raise CustodyCheckpointError(
                "The signer certificate does not permit digital signatures."
            )

        with database.session() as session:
            CaseService().get(session, principal, case_id)
            record = session.get(CustodyCheckpointRecord, checkpoint_id)
            if record is None or record.case_id != case_id:
                raise CustodyCheckpointNotFoundError(
                    "The requested custody checkpoint does not exist in this case."
                )
            if checkpoint_sha256 != record.sha256:
                raise CustodyCheckpointIntegrityError(
                    "The signed checkpoint SHA-256 does not match the sealed checkpoint."
                )
            store = EvidenceStore(database.data_dir / "evidence")
            if not store.verify(record.storage_key, record.sha256):
                raise CustodyCheckpointIntegrityError(
                    "The custody checkpoint no longer matches its recorded SHA-256."
                )
            _verify_detached_signature(
                certificate,
                signature,
                bytes.fromhex(record.sha256),
                signature_algorithm,
            )
            certificate_sha256 = certificate.fingerprint(hashes.SHA256()).hex()
            signature_sha256 = sha256(signature).hexdigest()
            canonical = {
                "case_id": case_id,
                "certificate_serial": format(certificate.serial_number, "x"),
                "certificate_sha256": certificate_sha256,
                "checkpoint_id": checkpoint_id,
                "checkpoint_sha256": record.sha256,
                "schema_version": "1.0.0",
                "signature_algorithm": signature_algorithm,
                "signature_sha256": signature_sha256,
                "signed_at": _iso(normalized_signed_at),
                "signer_issuer": certificate.issuer.rfc4514_string(),
                "signer_subject": certificate.subject.rfc4514_string(),
                "verified_at": _iso(verified_at),
                "verified_by": principal.user_id,
            }
            verification = CustodyCheckpointSignatureRecord(
                checkpoint_id=checkpoint_id,
                case_id=case_id,
                verified_by=principal.user_id,
                signature_algorithm=signature_algorithm,
                signer_subject=canonical["signer_subject"],
                signer_issuer=canonical["signer_issuer"],
                certificate_serial=canonical["certificate_serial"],
                certificate_sha256=certificate_sha256,
                certificate_pem=certificate_pem,
                signature_sha256=signature_sha256,
                signature_base64=signature_base64,
                signed_at=normalized_signed_at,
                certificate_not_before=certificate.not_valid_before_utc,
                certificate_not_after=certificate.not_valid_after_utc,
                checkpoint_sha256=record.sha256,
                verification_hash=sha256(_canonical_bytes(canonical)).hexdigest(),
                created_at=verified_at,
            )
            session.add(verification)
            session.flush()
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="custody_checkpoint.signature_verified",
                object_type="custody_checkpoint",
                object_id=checkpoint_id,
                detail={
                    "certificate_sha256": certificate_sha256,
                    "checkpoint_sha256": record.sha256,
                    "signature_algorithm": signature_algorithm,
                    "signature_sha256": signature_sha256,
                    "verification_hash": verification.verification_hash,
                },
                created_at=verified_at,
            )
            session.flush()
            return verification

    def list_signatures(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        checkpoint_id: str,
    ) -> Sequence[CustodyCheckpointSignatureRecord]:
        self._require_export_permission(principal)
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            record = session.get(CustodyCheckpointRecord, checkpoint_id)
            if record is None or record.case_id != case_id:
                raise CustodyCheckpointNotFoundError(
                    "The requested custody checkpoint does not exist in this case."
                )
            return list(
                session.scalars(
                    select(CustodyCheckpointSignatureRecord)
                    .where(CustodyCheckpointSignatureRecord.checkpoint_id == checkpoint_id)
                    .order_by(
                        CustodyCheckpointSignatureRecord.created_at.desc(),
                        CustodyCheckpointSignatureRecord.id.desc(),
                    )
                )
            )

    def content(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        checkpoint_id: str,
    ) -> CustodyCheckpointContent:
        self._require_export_permission(principal)
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            record = session.get(CustodyCheckpointRecord, checkpoint_id)
            if record is None or record.case_id != case_id:
                raise CustodyCheckpointNotFoundError(
                    "The requested custody checkpoint does not exist in this case."
                )
            store = EvidenceStore(database.data_dir / "evidence")
            if not store.verify(record.storage_key, record.sha256):
                raise CustodyCheckpointIntegrityError(
                    "The custody checkpoint no longer matches its recorded SHA-256."
                )
            path = store.resolve(record.storage_key, require_file=True)
            AuditService().append(
                session,
                case_id=case_id,
                actor_id=principal.user_id,
                event_type="custody_checkpoint.downloaded",
                object_type="custody_checkpoint",
                object_id=checkpoint_id,
                detail={"sha256": record.sha256},
                created_at=datetime.now(UTC),
            )
            return CustodyCheckpointContent(record=record, path=path)

    @staticmethod
    def _require_export_permission(principal: Principal) -> None:
        if not (principal.can(Permission.CUSTODY_REVIEW) and principal.can(Permission.AUDIT_VIEW)):
            raise CaseAccessDeniedError(
                "Custody checkpoint export requires custody-review and audit-view permissions."
            )


def _custody_payload(record: CustodyEventRecord) -> dict[str, Any]:
    return {
        "actor_id": record.actor_id,
        "case_id": record.case_id,
        "created_at": _iso(record.created_at),
        "event_hash": record.event_hash,
        "event_type": record.event_type,
        "evidence_file_id": record.evidence_file_id,
        "evidence_source_id": record.evidence_source_id,
        "from_custodian": record.from_custodian,
        "id": record.id,
        "location": record.location,
        "notes": record.notes,
        "parser_run_id": record.parser_run_id,
        "previous_hash": record.previous_hash,
        "purpose": record.purpose,
        "related_event_id": record.related_event_id,
        "report_id": record.report_id,
        "sequence": record.sequence,
        "to_custodian": record.to_custodian,
    }


def _audit_payload(record: AuditLogRecord) -> dict[str, Any]:
    return {
        "actor_id": record.actor_id,
        "case_id": record.case_id,
        "created_at": _iso(record.created_at),
        "detail": json.loads(record.detail_json),
        "entry_hash": record.entry_hash,
        "event_type": record.event_type,
        "id": record.id,
        "object_id": record.object_id,
        "object_type": record.object_type,
        "previous_hash": record.previous_hash,
        "sequence": record.sequence,
    }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _iso(value: datetime) -> str:
    return _utc(value).isoformat()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _verify_detached_signature(
    certificate: x509.Certificate,
    signature: bytes,
    checkpoint_digest: bytes,
    signature_algorithm: str,
) -> None:
    public_key = certificate.public_key()
    try:
        if signature_algorithm == "rsa_pkcs1v15_sha256" and isinstance(
            public_key, rsa.RSAPublicKey
        ):
            public_key.verify(
                signature,
                checkpoint_digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
        elif signature_algorithm == "rsa_pss_sha256" and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                checkpoint_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
        elif signature_algorithm == "ecdsa_sha256" and isinstance(
            public_key, ec.EllipticCurvePublicKey
        ):
            public_key.verify(
                signature,
                checkpoint_digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        else:
            raise CustodyCheckpointError(
                "The selected signature algorithm does not match the certificate public key."
            )
    except InvalidSignature as error:
        raise CustodyCheckpointIntegrityError(
            "The detached signature does not verify against the sealed checkpoint."
        ) from error
