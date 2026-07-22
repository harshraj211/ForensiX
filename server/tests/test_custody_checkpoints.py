import json
from base64 import b64encode
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

from forensix_server.auth import Principal, RoleName
from forensix_server.auth.domain import ROLE_PERMISSIONS
from forensix_server.cases import CaseService
from forensix_server.custody_exports import (
    CustodyCheckpointIntegrityError,
    CustodyCheckpointNotFoundError,
    CustodyCheckpointService,
)
from forensix_server.db import Database, UserRecord


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    active = Database(f"sqlite:///{(tmp_path / 'checkpoint.db').as_posix()}", tmp_path)
    active.initialize()
    yield active
    active.dispose()


def _principal_and_case(database: Database) -> tuple[Principal, str]:
    with database.session() as session:
        user = UserRecord(
            username="checkpoint.supervisor",
            display_name="Checkpoint Supervisor",
            password_hash="$argon2id$test-placeholder",
        )
        session.add(user)
        session.flush()
        principal = Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            roles=frozenset({RoleName.ADMINISTRATOR}),
            permissions=ROLE_PERMISSIONS[RoleName.ADMINISTRATOR],
        )
        case = CaseService().create(session, principal, title="Checkpoint known-answer case")
        return principal, case.id


def test_checkpoint_is_sealed_and_refuses_tampered_download(database: Database) -> None:
    principal, case_id = _principal_and_case(database)
    service = CustodyCheckpointService()

    record = service.create(database, principal, case_id)
    content = service.content(database, principal, case_id, record.id)
    payload = json.loads(content.path.read_text(encoding="utf-8"))

    assert record.custody_record_count == 0
    assert record.audit_sequence == 0
    assert record.audit_head_hash is None
    assert len(record.sha256) == 64
    assert payload["checkpoint_id"] == record.id
    assert payload["anchor_status"] == "not_externally_anchored"
    assert payload["audit_checkpoint"]["global_head_hash"] == record.audit_head_hash
    assert payload["custody_chain"]["events"] == []

    content.path.write_bytes(b"tampered checkpoint")
    with pytest.raises(CustodyCheckpointIntegrityError, match="SHA-256"):
        service.content(database, principal, case_id, record.id)


def test_checkpoint_anchor_receipt_requires_matching_hash(database: Database) -> None:
    principal, case_id = _principal_and_case(database)
    service = CustodyCheckpointService()
    record = service.create(database, principal, case_id)

    anchor = service.create_anchor(
        database,
        principal,
        case_id,
        record.id,
        anchor_type="evidence_vault",
        anchor_provider="Controlled evidence vault",
        anchor_reference="VAULT-2026-0001",
        anchored_at=datetime(2026, 7, 20, 4, 0, tzinfo=UTC),
        checkpoint_sha256=record.sha256,
        receipt_sha256="f" * 64,
        notes="Preserved by controlled validation workflow.",
    )
    anchors = service.list_anchors(database, principal, case_id, record.id)

    assert [item.id for item in anchors] == [anchor.id]
    assert anchor.anchor_type == "evidence_vault"
    assert anchor.checkpoint_sha256 == record.sha256
    assert len(anchor.anchor_hash) == 64

    with pytest.raises(CustodyCheckpointIntegrityError, match="acknowledged"):
        service.create_anchor(
            database,
            principal,
            case_id,
            record.id,
            anchor_type="other",
            anchor_provider="Mismatch test",
            anchor_reference="MISMATCH",
            anchored_at=datetime(2026, 7, 20, 4, 5, tzinfo=UTC),
            checkpoint_sha256="0" * 64,
        )
    with pytest.raises(CustodyCheckpointNotFoundError):
        service.list_anchors(database, principal, case_id, "missing-checkpoint")


def test_checkpoint_detached_signature_is_verified_and_persisted(database: Database) -> None:
    principal, case_id = _principal_and_case(database)
    service = CustodyCheckpointService()
    record = service.create(database, principal, case_id)
    signed_at = datetime(2026, 7, 22, 2, 0, tzinfo=UTC)
    private_key, certificate_pem = _signer_certificate(signed_at)
    signature = private_key.sign(
        bytes.fromhex(record.sha256),
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )

    verification = service.verify_signature(
        database,
        principal,
        case_id,
        record.id,
        signature_algorithm="rsa_pkcs1v15_sha256",
        certificate_pem=certificate_pem,
        signature_base64=b64encode(signature).decode("ascii"),
        signed_at=signed_at,
        checkpoint_sha256=record.sha256,
    )
    signatures = service.list_signatures(database, principal, case_id, record.id)

    assert [item.id for item in signatures] == [verification.id]
    assert verification.signer_subject == "CN=ForensiX Controlled Signer"
    assert verification.checkpoint_sha256 == record.sha256
    assert len(verification.certificate_sha256) == 64
    assert len(verification.signature_sha256) == 64
    assert len(verification.verification_hash) == 64

    invalid_signature = bytearray(signature)
    invalid_signature[-1] ^= 1
    with pytest.raises(CustodyCheckpointIntegrityError, match="does not verify"):
        service.verify_signature(
            database,
            principal,
            case_id,
            record.id,
            signature_algorithm="rsa_pkcs1v15_sha256",
            certificate_pem=certificate_pem,
            signature_base64=b64encode(invalid_signature).decode("ascii"),
            signed_at=signed_at,
            checkpoint_sha256=record.sha256,
        )


def _signer_certificate(signed_at: datetime) -> tuple[rsa.RSAPrivateKey, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ForensiX Controlled Signer")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(signed_at - timedelta(days=1))
        .not_valid_after(signed_at + timedelta(days=30))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return private_key, certificate_pem
