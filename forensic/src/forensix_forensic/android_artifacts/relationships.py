"""Normalized Forensic Entity & Relationship Model.

Establishes traceable entity nodes and directed relationships between:
Person ↕ Contact ↕ Account ↕ Conversation ↕ Message ↕ Media ↕ Artifact
"""

# ruff: noqa: E501


from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RelationshipType(StrEnum):
    SENDER = "sender"
    RECIPIENT = "recipient"
    MEMBER_OF = "member_of"
    ATTACHED_TO = "attached_to"
    QUOTED_BY = "quoted_by"
    BELONGS_TO = "belongs_to"
    ASSOCIATED_WITH = "associated_with"


@dataclass(frozen=True, slots=True)
class ForensicNode:
    entity_id: str
    entity_type: str  # person, contact, account, conversation, message, media, artifact
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ForensicPerson(ForensicNode):
    pass


@dataclass(frozen=True, slots=True)
class ForensicContact(ForensicNode):
    pass


@dataclass(frozen=True, slots=True)
class ForensicAccount(ForensicNode):
    pass


@dataclass(frozen=True, slots=True)
class ForensicConversation(ForensicNode):
    pass


@dataclass(frozen=True, slots=True)
class ForensicMessage(ForensicNode):
    pass


@dataclass(frozen=True, slots=True)
class ForensicMedia(ForensicNode):
    pass


def create_contact_node(contact_id: str, display_name: str, phone: str | None = None) -> ForensicContact:
    meta = {}
    if phone:
        meta["phone"] = phone
    return ForensicContact(
        entity_id=contact_id,
        entity_type="contact",
        label=display_name,
        metadata=meta,
    )


def create_message_node(message_id: str, summary: str, timestamp_utc: str | None = None) -> ForensicMessage:
    meta = {}
    if timestamp_utc:
        meta["timestamp_utc"] = timestamp_utc
    return ForensicMessage(
        entity_id=message_id,
        entity_type="message",
        label=summary[:50],
        metadata=meta,
    )


@dataclass(frozen=True, slots=True)
class ForensicRelationship:
    source_entity: str
    target_entity: str
    relationship_type: RelationshipType | str
    confidence: str = "high"
    source_database: str = ""
    source_table: str = ""
    source_row_id: str | int | None = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
