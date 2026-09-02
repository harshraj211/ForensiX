import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from forensix_server.auth import Principal
from forensix_server.cases import CaseService
from forensix_server.db import EvidenceSourceArtifactRecord


@dataclass(frozen=True, slots=True)
class GeoPoint:
    id: str
    latitude: float
    longitude: float
    timestamp: str | None
    title: str
    summary: str
    source_type: str
    application: str
    confidence: str
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class GeoLocationAnalyticsResult:
    case_id: str
    total_points: int
    bounding_box: dict[str, float] | None
    points: list[dict[str, Any]]
    clusters_summary: list[dict[str, Any]]
    providers_summary: dict[str, int]


@dataclass(frozen=True, slots=True)
class SocialGraphNode:
    id: str
    label: str
    total_interactions: int
    incoming_count: int
    outgoing_count: int
    applications: list[str]


@dataclass(frozen=True, slots=True)
class SocialGraphEdge:
    id: str
    source: str
    target: str
    weight: int
    message_count: int
    call_count: int
    first_seen: str | None
    last_seen: str | None
    applications: list[str]


@dataclass(frozen=True, slots=True)
class SocialGraphAnalyticsResult:
    case_id: str
    total_nodes: int
    total_edges: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    top_identities: list[dict[str, Any]]
    channels_summary: dict[str, int]


class GeoLocationAnalyticsService:
    """Consolidates all spatial coordinates and geolocation trails across evidence artifacts."""

    def __init__(self, session: Session, principal: Principal) -> None:
        self._session = session
        self._principal = principal

    def get_case_geolocation(self, case_id: str) -> GeoLocationAnalyticsResult:
        CaseService().get(self._session, self._principal, case_id)

        # Query all location and spatial artifacts in the case
        stmt = (
            select(EvidenceSourceArtifactRecord)
            .where(
                EvidenceSourceArtifactRecord.case_id == case_id,
                or_(
                    EvidenceSourceArtifactRecord.category.in_(
                        ["location", "file", "media", "system"]
                    ),
                    EvidenceSourceArtifactRecord.subtype.in_(
                        [
                            "location_observation",
                            "maps_search",
                            "wifi_profile",
                            "cell_tower_observation",
                            "exif_metadata",
                        ]
                    ),
                ),
            )
            .order_by(EvidenceSourceArtifactRecord.event_time.asc())
        )
        artifacts = list(self._session.scalars(stmt).all())

        points: list[GeoPoint] = []
        providers_count: dict[str, int] = {}

        for rec in artifacts:
            meta: dict[str, Any] = {}
            if rec.metadata_json:
                try:
                    meta = json.loads(rec.metadata_json)
                except Exception:
                    meta = {}
            lat_raw = meta.get("latitude") or meta.get("lat") or meta.get("result_lat")
            lng_raw = (
                meta.get("longitude")
                or meta.get("lng")
                or meta.get("lon")
                or meta.get("result_lng")
            )

            if lat_raw is None or lng_raw is None:
                continue

            try:
                lat = float(lat_raw)
                lng = float(lng_raw)
            except (TypeError, ValueError):
                continue

            if not (-90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0):
                continue
            if lat == 0.0 and lng == 0.0:
                continue

            app = str(meta.get("application") or rec.subtype or "location")
            providers_count[app] = providers_count.get(app, 0) + 1

            ts = rec.event_time.isoformat() if isinstance(rec.event_time, datetime) else None

            points.append(
                GeoPoint(
                    id=str(rec.id),
                    latitude=lat,
                    longitude=lng,
                    timestamp=ts,
                    title=rec.title or f"Location point ({lat:.4f}, {lng:.4f})",
                    summary=rec.summary or f"{app} coordinate",
                    source_type=rec.subtype or "location",
                    application=app,
                    confidence=rec.confidence or "medium",
                    metadata=meta,
                )
            )

        bounding_box = None
        if points:
            lats = [p.latitude for p in points]
            lngs = [p.longitude for p in points]
            bounding_box = {
                "min_lat": min(lats),
                "max_lat": max(lats),
                "min_lng": min(lngs),
                "max_lng": max(lngs),
            }

        # Cluster points coarsely by 2 decimal places (~1.1km)
        clusters_map: dict[str, list[GeoPoint]] = {}
        for p in points:
            key = f"{p.latitude:.2f},{p.longitude:.2f}"
            clusters_map.setdefault(key, []).append(p)

        clusters_summary = [
            {
                "cluster_center": {
                    "latitude": sum(p.latitude for p in plist) / len(plist),
                    "longitude": sum(p.longitude for p in plist) / len(plist),
                },
                "point_count": len(plist),
                "earliest_time": min((p.timestamp for p in plist if p.timestamp), default=None),
                "latest_time": max((p.timestamp for p in plist if p.timestamp), default=None),
            }
            for key, plist in clusters_map.items()
        ]
        clusters_summary.sort(key=lambda c: int(str(c["point_count"])), reverse=True)

        return GeoLocationAnalyticsResult(
            case_id=case_id,
            total_points=len(points),
            bounding_box=bounding_box,
            points=[
                {
                    "id": p.id,
                    "latitude": p.latitude,
                    "longitude": p.longitude,
                    "timestamp": p.timestamp,
                    "title": p.title,
                    "summary": p.summary,
                    "source_type": p.source_type,
                    "application": p.application,
                    "confidence": p.confidence,
                    "metadata": p.metadata,
                }
                for p in points
            ],
            clusters_summary=clusters_summary[:20],
            providers_summary=providers_count,
        )


class SocialGraphAnalyticsService:
    """Builds interactive relationship graphs from all communication and messaging artifacts."""

    def __init__(self, session: Session, principal: Principal) -> None:
        self._session = session
        self._principal = principal

    def get_case_social_graph(self, case_id: str) -> SocialGraphAnalyticsResult:
        CaseService().get(self._session, self._principal, case_id)

        # Select all communication artifacts
        stmt = (
            select(EvidenceSourceArtifactRecord)
            .where(
                EvidenceSourceArtifactRecord.case_id == case_id,
                or_(
                    EvidenceSourceArtifactRecord.category.in_(["communication", "message", "call"]),
                    EvidenceSourceArtifactRecord.subtype.in_(
                        [
                            "whatsapp_message",
                            "signal_message",
                            "telegram_message",
                            "sms_message",
                            "mms_message",
                            "call_record",
                            "discord_message",
                            "wechat_message",
                            "meta_message",
                            "gmail_message",
                        ]
                    ),
                ),
            )
            .order_by(EvidenceSourceArtifactRecord.event_time.asc())
        )
        artifacts = list(self._session.scalars(stmt).all())

        # Primary suspect device identity
        target_node = "Device Owner"
        nodes: dict[str, dict[str, Any]] = {
            target_node: {
                "id": target_node,
                "label": target_node,
                "total_interactions": 0,
                "incoming_count": 0,
                "outgoing_count": 0,
                "applications": set(),
            }
        }
        edges: dict[tuple[str, str], dict[str, Any]] = {}
        channels_summary: dict[str, int] = {}

        for rec in artifacts:
            meta: dict[str, Any] = {}
            if rec.metadata_json:
                try:
                    meta = json.loads(rec.metadata_json)
                except Exception:
                    meta = {}
            app = str(meta.get("application") or rec.subtype or "messaging")
            channels_summary[app] = channels_summary.get(app, 0) + 1

            # Determine contact identity
            direction = str(meta.get("direction") or "incoming")
            is_outgoing = (
                direction.startswith("out")
                or meta.get("from_me") == 1
                or meta.get("isSend") == 1
            )

            peer = (
                meta.get("resolved_sender")
                or meta.get("resolved_chat")
                or meta.get("address")
                or meta.get("phone_number")
                or meta.get("talker")
                or meta.get("author_name")
                or meta.get("sender")
                or meta.get("fromAddress")
                or meta.get("key_remote_jid")
            )
            if not peer:
                # Extract peer from title if possible
                peer = rec.title.split(":", 1)[1].strip() if ":" in rec.title else "Unknown Contact"

            peer = str(peer).strip()
            if not peer or peer == target_node:
                continue

            if peer not in nodes:
                nodes[peer] = {
                    "id": peer,
                    "label": peer,
                    "total_interactions": 0,
                    "incoming_count": 0,
                    "outgoing_count": 0,
                    "applications": set(),
                }

            nodes[peer]["total_interactions"] += 1
            nodes[peer]["applications"].add(app)
            nodes[target_node]["total_interactions"] += 1
            nodes[target_node]["applications"].add(app)

            if is_outgoing:
                nodes[peer]["incoming_count"] += 1
                nodes[target_node]["outgoing_count"] += 1
                edge_key = (target_node, peer)
            else:
                nodes[peer]["outgoing_count"] += 1
                nodes[target_node]["incoming_count"] += 1
                edge_key = (peer, target_node)

            if edge_key not in edges:
                edges[edge_key] = {
                    "id": f"{edge_key[0]}->{edge_key[1]}",
                    "source": edge_key[0],
                    "target": edge_key[1],
                    "weight": 0,
                    "message_count": 0,
                    "call_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "applications": set(),
                }

            edge = edges[edge_key]
            edge["weight"] += 1
            edge["applications"].add(app)
            if "call" in rec.subtype or "call" in app:
                edge["call_count"] += 1
            else:
                edge["message_count"] += 1

            ts = rec.event_time.isoformat() if isinstance(rec.event_time, datetime) else None
            if ts:
                if edge["first_seen"] is None or ts < edge["first_seen"]:
                    edge["first_seen"] = ts
                if edge["last_seen"] is None or ts > edge["last_seen"]:
                    edge["last_seen"] = ts

        # Format nodes and edges for client
        formatted_nodes = [
            {
                "id": n["id"],
                "label": n["label"],
                "total_interactions": n["total_interactions"],
                "incoming_count": n["incoming_count"],
                "outgoing_count": n["outgoing_count"],
                "applications": sorted(list(n["applications"])),
            }
            for n in nodes.values()
        ]
        formatted_nodes.sort(key=lambda x: x["total_interactions"], reverse=True)

        formatted_edges = [
            {
                "id": e["id"],
                "source": e["source"],
                "target": e["target"],
                "weight": e["weight"],
                "message_count": e["message_count"],
                "call_count": e["call_count"],
                "first_seen": e["first_seen"],
                "last_seen": e["last_seen"],
                "applications": sorted(list(e["applications"])),
            }
            for e in edges.values()
        ]
        formatted_edges.sort(key=lambda x: x["weight"], reverse=True)

        return SocialGraphAnalyticsResult(
            case_id=case_id,
            total_nodes=len(formatted_nodes),
            total_edges=len(formatted_edges),
            nodes=formatted_nodes,
            edges=formatted_edges,
            top_identities=formatted_nodes[1:11],  # Exclude target_node
            channels_summary=channels_summary,
        )
