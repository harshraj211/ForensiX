"""Deterministic, report-ready investigation narrative assembled from verified records."""

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy.orm import Session

from forensix_server.auth import Principal
from forensix_server.db import EvidenceSourceTimelineEventRecord, TimelineEventRecord
from forensix_server.evidence import (
    CorrelationGraph,
    CorrelationService,
    KeyEvidenceItem,
    KeyEvidenceService,
    TimelineService,
)

STORYBOARD_BUILDER_VERSION = "1.0.0"
MAX_STORYBOARD_MOMENTS = 16
MAX_STORYBOARD_LEADS = 12


@dataclass(frozen=True, slots=True)
class StoryboardMetrics:
    key_findings: int
    critical_findings: int
    high_findings: int
    evidence_categories: int
    timeline_claims: int
    linked_moments: int
    relationship_leads: int


@dataclass(frozen=True, slots=True)
class StoryboardFinding:
    id: str
    target_type: str
    target_id: str
    priority: str
    category: str
    subtype: str
    title: str
    summary: str
    rationale: str | None
    confidence: str
    event_time: datetime | None
    source_locator: str
    integrity_hash: str
    parser_id: str
    timeline_event_ids: tuple[str, ...]
    related_entities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StoryboardMoment:
    id: str
    event_time: datetime
    summary: str
    category: str
    confidence: str
    timestamp_type: str
    timezone_basis: str
    event_hash: str
    finding_ids: tuple[str, ...]
    key_evidence_linked: bool


@dataclass(frozen=True, slots=True)
class StoryboardLead:
    id: str
    entity_type: str
    label: str
    confidence: str
    evidence_count: int
    finding_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StoryboardSection:
    id: str
    title: str
    summary: str
    finding_ids: tuple[str, ...]
    critical_count: int
    high_count: int
    latest_event_time: datetime | None


@dataclass(frozen=True, slots=True)
class StoryboardGap:
    code: str
    severity: str
    title: str
    detail: str
    action_path: str


@dataclass(frozen=True, slots=True)
class InvestigationStoryboard:
    case_id: str
    overview: str
    metrics: StoryboardMetrics
    sections: tuple[StoryboardSection, ...]
    findings: tuple[StoryboardFinding, ...]
    moments: tuple[StoryboardMoment, ...]
    leads: tuple[StoryboardLead, ...]
    gaps: tuple[StoryboardGap, ...]
    limitations: tuple[str, ...]
    source_hashes: dict[str, str]
    builder_version: str
    snapshot_hash: str


class InvestigationStoryboardService:
    """Build a reproducible narrative without inferring facts absent from evidence."""

    def build(
        self,
        session: Session,
        principal: Principal,
        case_id: str,
    ) -> InvestigationStoryboard:
        key_evidence = KeyEvidenceService().list(session, principal, case_id)
        timeline = TimelineService().search(
            session,
            principal,
            case_id,
            offset=0,
            limit=200,
        )
        graph = CorrelationService().build(session, principal, case_id)

        finding_by_target = {
            (item.target_type, item.target_id): item for item in key_evidence.items
        }
        event_findings: dict[str, tuple[str, ...]] = {}
        finding_timeline_ids: dict[str, list[str]] = {
            item.id: [] for item in key_evidence.items
        }
        for event in timeline.items:
            if isinstance(event, TimelineEventRecord):
                finding = finding_by_target.get(("artifact", event.artifact_id))
            else:
                finding = finding_by_target.get(
                    ("source_artifact", event.source_artifact_id)
                )
            finding_ids = (finding.id,) if finding else ()
            event_findings[event.id] = finding_ids
            if finding:
                finding_timeline_ids[finding.id].append(event.id)

        leads, finding_entities = _relationship_leads(key_evidence.items, graph)
        findings = tuple(
            _finding(
                item,
                finding_timeline_ids[item.id],
                finding_entities.get(item.id, set()),
            )
            for item in key_evidence.items
        )
        moments = _moments(timeline.items, event_findings)
        sections = _sections(key_evidence.items)
        linked_moments = sum(item.key_evidence_linked for item in moments)
        metrics = StoryboardMetrics(
            key_findings=key_evidence.total,
            critical_findings=key_evidence.priority_counts["critical"],
            high_findings=key_evidence.priority_counts["high"],
            evidence_categories=len(key_evidence.category_facets),
            timeline_claims=timeline.total,
            linked_moments=linked_moments,
            relationship_leads=len(leads),
        )
        overview = _overview(metrics)
        gaps = _gaps(case_id, findings, timeline.total, linked_moments, leads, graph.truncated)
        limitations = tuple(
            dict.fromkeys(
                (
                    "This storyboard organizes recorded evidence; it does not determine guilt, "
                    "identity, intent, or legal relevance.",
                    "Only explicit timestamp claims are shown. Missing events are not evidence "
                    "that an activity did not occur.",
                    *graph.warnings,
                    "Priority and rationale are examiner judgments and remain separately "
                    "auditable from source evidence.",
                )
            )
        )
        source_hashes = {
            "correlation_graph": graph.graph_hash,
            "key_evidence": _key_evidence_hash(key_evidence.items),
            "timeline": _timeline_hash(timeline.items),
        }
        payload = {
            "builder_version": STORYBOARD_BUILDER_VERSION,
            "case_id": case_id,
            "findings": [asdict(item) for item in findings],
            "gaps": [asdict(item) for item in gaps],
            "leads": [asdict(item) for item in leads],
            "limitations": limitations,
            "metrics": asdict(metrics),
            "moments": [asdict(item) for item in moments],
            "overview": overview,
            "sections": [asdict(item) for item in sections],
            "source_hashes": source_hashes,
        }
        return InvestigationStoryboard(
            case_id=case_id,
            overview=overview,
            metrics=metrics,
            sections=sections,
            findings=findings,
            moments=moments,
            leads=leads,
            gaps=gaps,
            limitations=limitations,
            source_hashes=source_hashes,
            builder_version=STORYBOARD_BUILDER_VERSION,
            snapshot_hash=sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
        )


def _finding(
    item: KeyEvidenceItem,
    timeline_event_ids: list[str],
    related_entities: set[str],
) -> StoryboardFinding:
    return StoryboardFinding(
        id=item.id,
        target_type=item.target_type,
        target_id=item.target_id,
        priority=item.priority,
        category=item.category,
        subtype=item.subtype,
        title=item.title,
        summary=item.summary,
        rationale=item.reason,
        confidence=item.confidence,
        event_time=item.event_time,
        source_locator=item.source_locator,
        integrity_hash=item.integrity_hash,
        parser_id=item.parser_id,
        timeline_event_ids=tuple(sorted(timeline_event_ids)),
        related_entities=tuple(sorted(related_entities)),
    )


def _moments(
    events: list[TimelineEventRecord | EvidenceSourceTimelineEventRecord],
    finding_ids: dict[str, tuple[str, ...]],
) -> tuple[StoryboardMoment, ...]:
    linked = [event for event in events if finding_ids.get(str(event.id))]
    context = [
        event
        for event in events
        if not finding_ids.get(str(event.id)) and str(event.confidence) == "high"
    ]
    selected = (linked + context)[:MAX_STORYBOARD_MOMENTS]
    selected.sort(key=lambda item: (_aware_utc(item.event_time), str(item.id)))
    return tuple(
        StoryboardMoment(
            id=str(event.id),
            event_time=_aware_utc(event.event_time),
            summary=str(event.summary),
            category=str(event.category),
            confidence=str(event.confidence),
            timestamp_type=str(event.timestamp_type),
            timezone_basis=str(event.timezone_basis),
            event_hash=str(event.event_hash),
            finding_ids=finding_ids.get(str(event.id), ()),
            key_evidence_linked=bool(finding_ids.get(str(event.id))),
        )
        for event in selected
    )


def _relationship_leads(
    findings: list[KeyEvidenceItem],
    graph: CorrelationGraph,
) -> tuple[tuple[StoryboardLead, ...], dict[str, set[str]]]:
    finding_nodes: dict[str, str] = {}
    for finding in findings:
        for node in graph.nodes:
            if (
                finding.target_type == "artifact"
                and node.artifact_id == finding.target_id
            ) or (
                finding.target_type == "source_artifact"
                and node.source_artifact_id == finding.target_id
            ):
                finding_nodes[node.id] = finding.id
                break
    nodes = {node.id: node for node in graph.nodes}
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    finding_entities: dict[str, set[str]] = {}
    for edge in graph.edges:
        finding_id = finding_nodes.get(edge.source) or finding_nodes.get(edge.target)
        if finding_id is None:
            continue
        other_id = edge.target if edge.source in finding_nodes else edge.source
        other = nodes.get(other_id)
        if other is None or other.node_type in {"artifact", "device", "source"}:
            continue
        key = (other.node_type, other.label)
        entry = grouped.setdefault(
            key,
            {
                "confidence": other.confidence,
                "evidence_count": 0,
                "finding_ids": set(),
                "node_id": other.id,
            },
        )
        entry["evidence_count"] = int(entry["evidence_count"]) + edge.evidence_count
        finding_id_set = entry["finding_ids"]
        if isinstance(finding_id_set, set):
            finding_id_set.add(finding_id)
        finding_entities.setdefault(finding_id, set()).add(
            f"{other.node_type}: {other.label}"
        )
    leads = [
        StoryboardLead(
            id=str(value["node_id"]),
            entity_type=kind,
            label=label,
            confidence=str(value["confidence"]),
            evidence_count=int(value["evidence_count"]),
            finding_ids=tuple(sorted(value["finding_ids"])),
        )
        for (kind, label), value in grouped.items()
    ]
    leads.sort(key=lambda item: (-item.evidence_count, item.entity_type, item.label.casefold()))
    return tuple(leads[:MAX_STORYBOARD_LEADS]), finding_entities


def _sections(findings: list[KeyEvidenceItem]) -> tuple[StoryboardSection, ...]:
    grouped: dict[str, list[KeyEvidenceItem]] = {}
    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)
    sections: list[StoryboardSection] = []
    for category, items in sorted(grouped.items()):
        critical = sum(item.priority == "critical" for item in items)
        high = sum(item.priority == "high" for item in items)
        event_times = [_aware_utc(item.event_time) for item in items if item.event_time]
        priority_text = f"{critical} critical and {high} high-priority"
        sections.append(
            StoryboardSection(
                id=category,
                title=f"{category.replace('_', ' ').title()} evidence",
                summary=(
                    f"{len(items)} examiner-curated finding(s), including "
                    f"{priority_text} item(s)."
                ),
                finding_ids=tuple(item.id for item in items),
                critical_count=critical,
                high_count=high,
                latest_event_time=max(event_times) if event_times else None,
            )
        )
    return tuple(sections)


def _overview(metrics: StoryboardMetrics) -> str:
    material = metrics.critical_findings + metrics.high_findings
    return (
        f"Examiners selected {metrics.key_findings} key finding(s) across "
        f"{metrics.evidence_categories} evidence category or categories. "
        f"{material} finding(s) are marked critical or high priority. "
        f"{metrics.linked_moments} directly linked timeline moment(s) and "
        f"{metrics.relationship_leads} explicit relationship lead(s) are available."
    )


def _gaps(
    case_id: str,
    findings: tuple[StoryboardFinding, ...],
    timeline_count: int,
    linked_moments: int,
    leads: tuple[StoryboardLead, ...],
    graph_truncated: bool,
) -> tuple[StoryboardGap, ...]:
    gaps: list[StoryboardGap] = []
    if not findings:
        gaps.append(
            StoryboardGap(
                code="NO_KEY_EVIDENCE",
                severity="critical",
                title="No key evidence has been selected",
                detail=(
                    "Promote relevant acquired files or parsed artifacts before "
                    "drafting conclusions."
                ),
                action_path=f"/cases/{case_id}/key-evidence",
            )
        )
    if timeline_count == 0:
        gaps.append(
            StoryboardGap(
                code="NO_TIMELINE_CLAIMS",
                severity="warning",
                title="No timestamp claims are available",
                detail="Run compatible parsers or acquire timestamp-bearing evidence.",
                action_path=f"/cases/{case_id}/timeline",
            )
        )
    elif findings and linked_moments == 0:
        gaps.append(
            StoryboardGap(
                code="KEY_EVIDENCE_NOT_TIMELINE_LINKED",
                severity="info",
                title="Key findings have no direct timeline link",
                detail=(
                    "This can be legitimate, but the report should state that "
                    "chronology is unavailable."
                ),
                action_path=f"/cases/{case_id}/timeline",
            )
        )
    if findings and not leads:
        gaps.append(
            StoryboardGap(
                code="NO_EXPLICIT_RELATIONSHIP_LEADS",
                severity="info",
                title="No explicit identifier relationships were found",
                detail="The absence of a graph lead does not disprove a relationship.",
                action_path=f"/cases/{case_id}/correlations",
            )
        )
    if any(item.confidence == "low" for item in findings):
        gaps.append(
            StoryboardGap(
                code="LOW_CONFIDENCE_KEY_EVIDENCE",
                severity="warning",
                title="Some key evidence has low parser confidence",
                detail="Corroborate low-confidence findings before relying on them in a report.",
                action_path=f"/cases/{case_id}/key-evidence",
            )
        )
    if graph_truncated:
        gaps.append(
            StoryboardGap(
                code="CORRELATION_GRAPH_TRUNCATED",
                severity="warning",
                title="Relationship graph reached its safety limit",
                detail=(
                    "Review the full artifact set with narrower filters before "
                    "finalizing the report."
                ),
                action_path=f"/cases/{case_id}/correlations",
            )
        )
    return tuple(gaps)


def _key_evidence_hash(items: list[KeyEvidenceItem]) -> str:
    return sha256(
        _canonical_json(
            [
                {
                    "id": item.id,
                    "integrity_hash": item.integrity_hash,
                    "priority": item.priority,
                    "reason": item.reason,
                    "target_id": item.target_id,
                    "updated_at": _aware_utc(item.updated_at),
                }
                for item in items
            ]
        ).encode("utf-8")
    ).hexdigest()


def _timeline_hash(
    events: list[TimelineEventRecord | EvidenceSourceTimelineEventRecord],
) -> str:
    return sha256(
        _canonical_json([str(event.event_hash) for event in events]).encode("utf-8")
    ).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        default=_json_default,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _json_default(value: object) -> object:
    if isinstance(value, datetime):
        return _aware_utc(value).isoformat()
    raise TypeError(f"Cannot serialize {type(value).__name__}.")
