"""Deterministic, case-scoped correlation graph from normalized evidence metadata."""

import json
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.db import (
    ArtifactRecord,
    CaseDeviceRecord,
    EvidenceSourceArtifactRecord,
    EvidenceSourceRecord,
)

CORRELATION_BUILDER_VERSION = "1.0.0"
MAX_GRAPH_ARTIFACTS = 200
MAX_GRAPH_NODES = 500


@dataclass(frozen=True, slots=True)
class CorrelationNode:
    id: str
    node_type: str
    label: str
    subtitle: str | None
    confidence: str
    artifact_id: str | None = None
    source_artifact_id: str | None = None
    evidence_source_id: str | None = None


@dataclass(frozen=True, slots=True)
class CorrelationEdge:
    id: str
    source: str
    target: str
    relation: str
    confidence: str
    evidence_count: int


@dataclass(frozen=True, slots=True)
class CorrelationGraph:
    case_id: str
    nodes: tuple[CorrelationNode, ...]
    edges: tuple[CorrelationEdge, ...]
    graph_hash: str
    builder_version: str
    truncated: bool
    warnings: tuple[str, ...]


class CorrelationService:
    """Builds explainable links without inferring identities absent from source metadata."""

    def build(self, session: Session, principal: Principal, case_id: str) -> CorrelationGraph:
        CaseService().get(session, principal, case_id)
        if not principal.can(Permission.EVIDENCE_ANALYZE):
            raise CaseAccessDeniedError("The current user cannot analyze evidence correlations.")

        file_artifacts = list(
            session.scalars(
                select(ArtifactRecord)
                .where(ArtifactRecord.case_id == case_id)
                .order_by(ArtifactRecord.created_at, ArtifactRecord.id)
                .limit(MAX_GRAPH_ARTIFACTS + 1)
            )
        )
        source_artifacts = list(
            session.scalars(
                select(EvidenceSourceArtifactRecord)
                .where(EvidenceSourceArtifactRecord.case_id == case_id)
                .order_by(
                    EvidenceSourceArtifactRecord.created_at,
                    EvidenceSourceArtifactRecord.id,
                )
                .limit(MAX_GRAPH_ARTIFACTS + 1)
            )
        )
        truncated = len(file_artifacts) > MAX_GRAPH_ARTIFACTS or len(source_artifacts) > (
            MAX_GRAPH_ARTIFACTS
        )
        file_artifacts = file_artifacts[:MAX_GRAPH_ARTIFACTS]
        source_artifacts = source_artifacts[:MAX_GRAPH_ARTIFACTS]

        device_ids = {item.device_id for item in file_artifacts}
        source_ids = {item.evidence_source_id for item in source_artifacts}
        sources = (
            {
                item.id: item
                for item in session.scalars(
                    select(EvidenceSourceRecord).where(EvidenceSourceRecord.id.in_(source_ids))
                )
            }
            if source_ids
            else {}
        )
        device_ids.update(item.device_id for item in sources.values() if item.device_id is not None)
        devices = (
            {
                item.id: item
                for item in session.scalars(
                    select(CaseDeviceRecord).where(CaseDeviceRecord.id.in_(device_ids))
                )
            }
            if device_ids
            else {}
        )

        nodes: dict[str, CorrelationNode] = {}
        edge_counts: dict[tuple[str, str, str, str], int] = {}
        for device in devices.values():
            node_id = f"device:{device.id}"
            nodes[node_id] = CorrelationNode(
                id=node_id,
                node_type="device",
                label=_label(f"{device.manufacturer or ''} {device.model or 'Android device'}"),
                subtitle=f"Serial ending {device.serial_suffix}",
                confidence="high",
            )
        for source in sources.values():
            source_node = f"source:{source.id}"
            nodes[source_node] = CorrelationNode(
                id=source_node,
                node_type="source",
                label=_label(source.display_name),
                subtitle=source.source_type,
                confidence="high",
                evidence_source_id=source.id,
            )
            if source.device_id is not None and f"device:{source.device_id}" in nodes:
                _edge(edge_counts, f"device:{source.device_id}", source_node, "contains", "high")

        for artifact in file_artifacts:
            artifact_node = f"artifact:{artifact.id}"
            parent = f"device:{artifact.device_id}"
            nodes[artifact_node] = CorrelationNode(
                id=artifact_node,
                node_type="artifact",
                label=_label(artifact.title),
                subtitle=artifact.category,
                confidence=artifact.timestamp_confidence,
                artifact_id=artifact.id,
            )
            if parent in nodes:
                _edge(edge_counts, parent, artifact_node, "contains", "high")
            _add_entities(
                nodes,
                edge_counts,
                artifact_node,
                _json_object(artifact.metadata_json),
                artifact.title if artifact.category == "other" else None,
                artifact.timestamp_confidence,
            )

        for source_artifact in source_artifacts:
            artifact_node = f"source-artifact:{source_artifact.id}"
            parent = f"source:{source_artifact.evidence_source_id}"
            nodes[artifact_node] = CorrelationNode(
                id=artifact_node,
                node_type="artifact",
                label=_label(source_artifact.title),
                subtitle=source_artifact.subtype,
                confidence=source_artifact.confidence,
                source_artifact_id=source_artifact.id,
                evidence_source_id=source_artifact.evidence_source_id,
            )
            if parent in nodes:
                _edge(edge_counts, parent, artifact_node, "derived_from", "high")
            metadata = _json_object(source_artifact.metadata_json)
            identity_hint = source_artifact.title if source_artifact.category == "contact" else None
            _add_entities(
                nodes,
                edge_counts,
                artifact_node,
                metadata,
                identity_hint,
                source_artifact.confidence,
            )

        ordered_nodes = tuple(sorted(nodes.values(), key=lambda item: item.id)[:MAX_GRAPH_NODES])
        retained_ids = {item.id for item in ordered_nodes}
        edges = tuple(
            CorrelationEdge(
                id=sha256("|".join(key).encode()).hexdigest()[:24],
                source=key[0],
                target=key[1],
                relation=key[2],
                confidence=key[3],
                evidence_count=count,
            )
            for key, count in sorted(edge_counts.items())
            if key[0] in retained_ids and key[1] in retained_ids
        )
        truncated = truncated or len(nodes) > MAX_GRAPH_NODES
        warnings = (
            "Links reflect explicit normalized fields only; shared values do not prove identity.",
            "Parser confidence is preserved and no missing relationship is inferred.",
        )
        payload = {
            "builder_version": CORRELATION_BUILDER_VERSION,
            "case_id": case_id,
            "edges": [asdict(item) for item in edges],
            "nodes": [asdict(item) for item in ordered_nodes],
            "truncated": truncated,
            "warnings": warnings,
        }
        return CorrelationGraph(
            case_id=case_id,
            nodes=ordered_nodes,
            edges=edges,
            graph_hash=sha256(_canonical_json(payload).encode()).hexdigest(),
            builder_version=CORRELATION_BUILDER_VERSION,
            truncated=truncated,
            warnings=warnings,
        )


def _add_entities(
    nodes: dict[str, CorrelationNode],
    edge_counts: dict[tuple[str, str, str, str], int],
    artifact_node: str,
    metadata: dict[str, Any],
    identity_hint: str | None,
    confidence: str,
) -> None:
    entities = _extract_entities(metadata)
    if identity_hint:
        entities.add(("identity", identity_hint))
    for kind, value in sorted(entities):
        if not value:
            continue
        normalized = value.casefold().strip()
        entity_id = f"{kind}:{sha256(normalized.encode()).hexdigest()[:20]}"
        nodes.setdefault(
            entity_id,
            CorrelationNode(
                id=entity_id,
                node_type=kind,
                label=_label(value),
                subtitle="Explicit normalized field",
                confidence=confidence,
            ),
        )
        _edge(edge_counts, artifact_node, entity_id, "mentions", confidence)


def _extract_entities(metadata: dict[str, Any]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    application = _text(metadata.get("application")) or _text(metadata.get("package"))
    if application:
        found.add(("application", application))
    for key in ("address", "number", "phone_account_address", "via_number"):
        if value := _text(metadata.get(key)):
            found.add(("phone", value))
    for key in ("display_name", "sender_name"):
        if value := _text(metadata.get(key)):
            found.add(("identity", value))
    for key in ("thread_id", "dialog_id"):
        if value := _text(metadata.get(key)):
            found.add(("conversation", f"{key} {value}"))
    if url := _text(metadata.get("url")):
        domain = urlparse(url).hostname
        found.add(("domain", domain or url))
    if ssid := _text(metadata.get("ssid")):
        found.add(("network", ssid))
    latitude = _text(metadata.get("latitude"))
    longitude = _text(metadata.get("longitude"))
    if latitude and longitude:
        found.add(("location", f"{latitude}, {longitude}"))
    for phone in _dict_list(metadata.get("phones")):
        if value := _text(phone.get("number")):
            found.add(("phone", value))
    for email in _dict_list(metadata.get("emails")):
        if value := _text(email.get("address")):
            found.add(("email", value))
    for address in _dict_list(metadata.get("addresses")):
        if value := _text(address.get("address")):
            found.add(("phone", value))
    return found


def _edge(
    counts: dict[tuple[str, str, str, str], int],
    source: str,
    target: str,
    relation: str,
    confidence: str,
) -> None:
    key = (source, target, relation, confidence)
    counts[key] = counts.get(key, 0) + 1


def _json_object(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _text(value: object) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    normalized = str(value).strip()
    return normalized[:256] if normalized else None


def _label(value: str) -> str:
    normalized = " ".join(value.split())
    return (normalized or "Unnamed evidence")[:96]


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
