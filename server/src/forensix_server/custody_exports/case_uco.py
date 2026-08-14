"""Cyber-investigation Analysis Standard Expression (CASE) exporter."""

import json
from datetime import datetime
from uuid import uuid4

from sqlalchemy.orm import Session

from forensix_server.cases import CaseService
from forensix_server.db import ArtifactRecord, TimelineEventRecord
from forensix_server.auth import Principal

def _uco_uuid() -> str:
    return f"kb:{uuid4()}"

class CaseUcoExporter:
    """Exports case data to CASE/UCO JSON-LD format."""
    
    def __init__(self, session: Session, principal: Principal, case_id: str):
        self.session = session
        self.principal = principal
        self.case_id = case_id
        # Will raise if access denied
        self.case = CaseService().get(session, principal, case_id)

    def export(self) -> dict:
        """Generate a complete CASE/UCO JSON-LD document."""
        graph = []
        
        # 1. Identity (The investigator)
        investigator_id = _uco_uuid()
        graph.append({
            "@id": investigator_id,
            "@type": "uco-identity:Person",
            "uco-core:name": self.principal.username
        })

        # 2. Investigation (The case)
        investigation_id = _uco_uuid()
        graph.append({
            "@id": investigation_id,
            "@type": "case-investigation:Investigation",
            "uco-core:name": self.case.title,
            "uco-core:description": self.case.description or "",
            "case-investigation:focus": self.case.case_number,
            "case-investigation:investigator": {"@id": investigator_id}
        })
        
        # 3. Artifacts (Digital Evidence)
        artifacts = self.session.query(ArtifactRecord).filter(
            ArtifactRecord.case_id == self.case_id
        ).all()
        
        artifact_map = {}
        for artifact in artifacts:
            file_id = _uco_uuid()
            artifact_map[artifact.id] = file_id
            graph.append({
                "@id": file_id,
                "@type": "uco-observable:File",
                "uco-core:name": artifact.title,
                "uco-observable:sizeInBytes": artifact.size_bytes,
                "uco-observable:mimeType": artifact.detected_mime,
                "uco-observable:hash": {
                    "@type": "uco-types:Hash",
                    "uco-types:hashMethod": "SHA-256",
                    "uco-types:hashValue": artifact.primary_sha256
                }
            })

        # 4. Timeline Events (Actions/Observations)
        events = self.session.query(TimelineEventRecord).filter(
            TimelineEventRecord.case_id == self.case_id
        ).all()
        
        for event in events:
            event_id = _uco_uuid()
            observable_id = artifact_map.get(event.artifact_id)
            
            event_node = {
                "@id": event_id,
                "@type": "uco-observable:ObservableAction",
                "uco-core:description": event.summary,
                "uco-observable:startTime": event.event_time.isoformat(),
                "uco-observable:actionStatus": "Completed",
            }
            if observable_id:
                event_node["uco-observable:object"] = {"@id": observable_id}
                
            graph.append(event_node)

        # Build JSON-LD envelope
        return {
            "@context": {
                "case-investigation": "https://ontology.caseontology.org/case/investigation/",
                "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
                "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
                "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
                "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
                "kb": "http://example.org/kb/"
            },
            "@graph": graph
        }
