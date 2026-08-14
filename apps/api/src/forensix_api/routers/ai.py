"""AI-powered case narrative generation via Groq Cloud API."""

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from forensix_api.dependencies import get_authenticated_session, get_database, get_settings
from forensix_api.schemas import AiNarrativeResponse
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings
from forensix_server.db import Database
from forensix_server.evidence import KeyEvidenceService, TimelineService
from forensix_server.investigation.ai_narrative import GroqNarrativeService
from forensix_server.cases import CaseService

router = APIRouter(prefix="/api/v1/cases", tags=["ai"])


@router.post("/{case_id}/ai/narrative", response_model=AiNarrativeResponse)
def generate_case_narrative(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    database: Annotated[Database, Depends(get_database)],
) -> AiNarrativeResponse:
    """Generate an AI-backed case narrative using Groq Cloud (llama-3.1-8b-instant).

    Fetches up to 20 key evidence items and 30 timeline events for the case,
    sends them to the Groq API, and returns a structured narrative response.
    Requires FORENSIX_GROQ_API_KEY to be configured.
    """
    if not settings.groq_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "AI narrative is not available: FORENSIX_GROQ_API_KEY is not configured. "
                "Add it to your .env file."
            ),
        )

    with database.session() as session:
        case = CaseService().get(session, authenticated.principal, case_id)
        key_result = KeyEvidenceService().list(
            session,
            authenticated.principal,
            case_id,
        )
        timeline_result = TimelineService().search(
            session,
            authenticated.principal,
            case_id,
            offset=0,
            limit=30,
        )

    key_evidence = [
        {
            "title": item.title,
            "reason": getattr(item, "reason", ""),
            "category": getattr(item, "category", ""),
        }
        for item in key_result.items[:20]
    ]
    timeline_events = [
        {
            "event_time": event.event_time.isoformat() if event.event_time else None,
            "summary": event.summary,
            "category": event.category,
            "confidence": event.confidence,
        }
        for event in timeline_result.items
    ]

    service = GroqNarrativeService(api_key=settings.groq_api_key)
    try:
        result = service.generate_case_narrative(
            case_title=case.title,
            case_number=case.case_number,
            key_evidence_items=key_evidence,
            timeline_events=timeline_events,
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return AiNarrativeResponse(
        narrative=result.narrative,
        model=result.model,
        generated_at=result.generated_at,
        evidence_item_count=result.evidence_item_count,
    )
