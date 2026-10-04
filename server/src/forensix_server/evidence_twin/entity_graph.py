"""Cross-source entity correlation and link analysis graph service."""

import contextlib
import json
import re
from typing import Any
from xml.sax.saxutils import escape

from sqlalchemy import select

from forensix_server.auth import Permission, Principal
from forensix_server.cases import CaseAccessDeniedError, CaseService
from forensix_server.db import Database, EvidenceSourceArtifactRecord


def _clean_phone(raw: str) -> str:
    """Extract canonical phone identifier (last 10 digits when available)."""
    raw_str = raw.strip()
    digits = re.sub(r"\D", "", raw_str)
    if not digits or len(digits) < 4:
        clean = re.sub(r"[^\d+]", "", raw_str)
        return clean or raw_str
    return digits[-10:] if len(digits) >= 10 else digits


def _phone_display(raw: str) -> str:
    """Format phone number for readable UI display."""
    raw_str = raw.strip()
    clean = re.sub(r"[^\d+]", "", raw_str)
    return clean if len(clean) >= 4 else raw_str


class EntityGraphService:
    """Extracts correlated identity nodes and communication edges across artifacts."""

    def build_graph(
        self,
        database: Database,
        principal: Principal,
        case_id: str,
        *,
        max_artifacts: int = 10_000,
    ) -> dict[str, Any]:
        with database.session() as session:
            CaseService().get(session, principal, case_id)
            if not principal.can(Permission.EVIDENCE_ANALYZE):
                raise CaseAccessDeniedError("Current user cannot analyze evidence entity graphs.")

            records = (
                session.execute(
                    select(EvidenceSourceArtifactRecord)
                    .where(EvidenceSourceArtifactRecord.case_id == case_id)
                    .order_by(EvidenceSourceArtifactRecord.created_at)
                    .limit(max_artifacts)
                )
                .scalars()
                .all()
            )

        nodes_map: dict[str, dict[str, Any]] = {}
        edges_map: dict[tuple[str, str, str], dict[str, Any]] = {}

        def add_node(
            node_id: str, label: str, node_type: str, extra: dict[str, Any] | None = None
        ) -> None:
            if not node_id:
                return
            if node_id in nodes_map:
                nodes_map[node_id]["count"] += 1
                if extra:
                    nodes_map[node_id]["metadata"].update(extra)
            else:
                nodes_map[node_id] = {
                    "id": node_id,
                    "label": label or node_id,
                    "node_type": node_type,
                    "count": 1,
                    "metadata": extra or {},
                }

        def add_edge(
            src: str,
            dst: str,
            relation: str,
            channel: str | None = None,
            event_time: str | None = None,
        ) -> None:
            if not src or not dst or src == dst:
                return
            key = (src, dst, relation)
            rev_key = (dst, src, relation)
            active_key = key if key in edges_map or rev_key not in edges_map else rev_key
            ch = channel or "unknown"
            if active_key in edges_map:
                edge = edges_map[active_key]
                edge["weight"] += 1
                if ch not in edge["channels"]:
                    edge["channels"].append(ch)
                if event_time:
                    if not edge.get("first_seen") or event_time < edge["first_seen"]:
                        edge["first_seen"] = event_time
                    if not edge.get("last_seen") or event_time > edge["last_seen"]:
                        edge["last_seen"] = event_time
            else:
                edges_map[active_key] = {
                    "source": src,
                    "target": dst,
                    "relation": relation,
                    "weight": 1,
                    "channel": ch,
                    "channels": [ch],
                    "first_seen": event_time,
                    "last_seen": event_time,
                    "metadata": {},
                }

        for record in records:
            meta: dict[str, Any] = {}
            with contextlib.suppress(Exception):
                meta = json.loads(record.metadata_json)

            category = record.category
            subtype = record.subtype
            event_iso = record.event_time.isoformat() if record.event_time else None

            if category == "contact":
                person_id = f"person:{record.title}"
                add_node(person_id, record.title, "person")

                # Handle phones in contact
                phones = meta.get("phones") or []
                if isinstance(phones, list):
                    for p in phones:
                        raw_num = str(p.get("number") if isinstance(p, dict) else p)
                        clean_num = _clean_phone(raw_num)
                        disp_num = _phone_display(raw_num)
                        if clean_num:
                            phone_id = f"phone:{clean_num}"
                            add_node(phone_id, disp_num, "phone")
                            add_edge(person_id, phone_id, "HAS_PHONE", channel="contacts")

                # Handle emails in contact
                emails = meta.get("emails") or []
                if isinstance(emails, list):
                    for e in emails:
                        addr = str(e.get("address") if isinstance(e, dict) else e).strip()
                        if addr and "@" in addr:
                            email_id = f"email:{addr.lower()}"
                            add_node(email_id, addr, "email")
                            add_edge(person_id, email_id, "HAS_EMAIL", channel="contacts")

            elif category == "communication":
                # Check for carved phone numbers
                if "phone_number" in subtype or subtype == "carved_phone_number":
                    raw_val = record.title.replace("Recovered (phone_number):", "").strip()
                    phone_val = _clean_phone(raw_val)
                    if phone_val:
                        phone_id = f"phone:{phone_val}"
                        add_node(
                            phone_id,
                            _phone_display(raw_val),
                            "phone",
                            extra={"status": record.status},
                        )
                    continue

                direction = str(meta.get("direction", "")).lower()
                addr_field = meta.get("address") or meta.get("number") or meta.get("phone")

                sender_str = ""
                recipient_str = ""

                if direction in {"inbox", "incoming", "missed", "received", "rejected"}:
                    sender_str = str(meta.get("sender") or meta.get("from") or addr_field or "")
                    recipient_str = str(meta.get("recipient") or meta.get("to") or "Device User")
                elif direction in {"sent", "outgoing", "outbox", "draft"}:
                    sender_str = str(meta.get("sender") or meta.get("from") or "Device User")
                    recipient_str = str(meta.get("recipient") or meta.get("to") or addr_field or "")
                else:
                    sender_str = str(meta.get("sender") or meta.get("from") or "")
                    recipient_str = str(meta.get("recipient") or meta.get("to") or addr_field or "")

                def resolve_entity_node(val: str) -> tuple[str, str, str]:
                    """Returns (node_id, label, node_type)."""
                    val = val.strip()
                    if not val:
                        return ("", "", "")
                    if val.lower() in {"device user", "device owner", "local_device", "me"}:
                        return ("entity:device_user", "Device User", "person")
                    if "@" in val and not val.startswith("+"):
                        return (f"email:{val.lower()}", val, "email")
                    cleaned = _clean_phone(val)
                    if any(c.isdigit() for c in cleaned) and len(cleaned) >= 4:
                        return (f"phone:{cleaned}", _phone_display(val), "phone")
                    return (f"account:{val.lower()}", val, "account")

                src_id, src_label, src_type = resolve_entity_node(sender_str)
                dst_id, dst_label, dst_type = resolve_entity_node(recipient_str)

                if src_id:
                    add_node(src_id, src_label, src_type)
                if dst_id:
                    add_node(dst_id, dst_label, dst_type)

                if src_id and dst_id:
                    add_edge(
                        src_id,
                        dst_id,
                        "COMMUNICATED_WITH",
                        channel=subtype,
                        event_time=event_iso,
                    )

            elif category in {"location", "system"}:
                ssid = meta.get("ssid")
                bssid = meta.get("bssid")
                if ssid or bssid:
                    wifi_name = str(ssid or bssid)
                    wifi_id = f"wifi:{wifi_name}"
                    add_node(wifi_id, wifi_name, "wifi", extra={"bssid": bssid, "ssid": ssid})
                    add_edge("entity:device_user", wifi_id, "CONNECTED_TO", channel="wifi")
                    add_node("entity:device_user", "Device User", "person")

        nodes = list(nodes_map.values())
        edges = list(edges_map.values())

        return {
            "case_id": case_id,
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        }

    def to_graphml(self, graph_data: dict[str, Any]) -> str:
        """Export the entity graph to standard XML GraphML format for Gephi and Maltego."""
        case_id = escape(str(graph_data.get("case_id", "case")))
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="count" for="node" attr.name="count" attr.type="int"/>',
            '  <key id="relation" for="edge" attr.name="relation" attr.type="string"/>',
            '  <key id="weight" for="edge" attr.name="weight" attr.type="int"/>',
            '  <key id="channels" for="edge" attr.name="channels" attr.type="string"/>',
            '  <key id="first_seen" for="edge" attr.name="first_seen" attr.type="string"/>',
            '  <key id="last_seen" for="edge" attr.name="last_seen" attr.type="string"/>',
            f'  <graph id="ForensiX_{case_id}" edgedefault="undirected">',
        ]

        for node in graph_data.get("nodes", []):
            nid = escape(str(node.get("id", "")))
            lbl = escape(str(node.get("label", "")))
            ntype = escape(str(node.get("node_type", "unknown")))
            cnt = int(node.get("count", 1))
            lines.append(f'    <node id="{nid}">')
            lines.append(f'      <data key="label">{lbl}</data>')
            lines.append(f'      <data key="type">{ntype}</data>')
            lines.append(f'      <data key="count">{cnt}</data>')
            lines.append("    </node>")

        for idx, edge in enumerate(graph_data.get("edges", [])):
            src = escape(str(edge.get("source", "")))
            tgt = escape(str(edge.get("target", "")))
            rel = escape(str(edge.get("relation", "LINKED")))
            wt = int(edge.get("weight", 1))
            chs = escape(", ".join(edge.get("channels", [edge.get("channel", "unknown")])))
            fs = escape(str(edge.get("first_seen") or ""))
            ls = escape(str(edge.get("last_seen") or ""))
            lines.append(f'    <edge id="e{idx}" source="{src}" target="{tgt}">')
            lines.append(f'      <data key="relation">{rel}</data>')
            lines.append(f'      <data key="weight">{wt}</data>')
            lines.append(f'      <data key="channels">{chs}</data>')
            if fs:
                lines.append(f'      <data key="first_seen">{fs}</data>')
            if ls:
                lines.append(f'      <data key="last_seen">{ls}</data>')
            lines.append("    </edge>")

        lines.append("  </graph>")
        lines.append("</graphml>")
        return "\n".join(lines)
