"""FastAPI router for ForensiX Centralized AI Gateway & Multimodal Suite."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from forensix_api.dependencies import get_authenticated_session, get_settings
from forensix_forensic.extractors.ai_media_intelligence import AiMediaIntelligenceExtractor
from forensix_server.ai import get_ai_gateway_service
from forensix_server.auth import AuthenticatedSession
from forensix_server.config import Settings

router = APIRouter(prefix="/api/v1/cases/{case_id}/ai-gateway", tags=["ai-gateway"])


class CopilotQueryRequest(BaseModel):
    query_text: str = Field(..., max_length=1000)


class ScanMediaRequest(BaseModel):
    file_names: list[str] | None = None


@router.get("/status")
def get_ai_gateway_status(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Returns AI Gateway status, API key configuration, and capabilities."""
    gateway = get_ai_gateway_service()
    return gateway.get_status(settings)


@router.post("/scan-media")
def scan_media_intelligence(
    case_id: str,
    payload: ScanMediaRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Executes batch visual intelligence scanning on case media files."""
    extractor = AiMediaIntelligenceExtractor(settings)
    items = extractor.run_media_batch_scan(
        case_id=case_id,
        operator_id=authenticated.principal.user_id,
        sample_file_names=payload.file_names,
    )

    formatted_items = [
        {
            "item_id": item.item_id,
            "file_name": item.file_name,
            "category": item.category,
            "confidence": item.confidence,
            "detected_labels": item.detected_labels,
            "extracted_text": item.extracted_text,
            "sha256_hash": item.sha256_hash,
            "risk_level": item.risk_level,
        }
        for item in items
    ]

    return {
        "case_id": case_id,
        "total_scanned": len(formatted_items),
        "items": formatted_items,
    }


@router.post("/copilot-query")
def copilot_query(
    case_id: str,
    payload: CopilotQueryRequest,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Executes natural language queries over case evidence using AI reasoning."""
    if not payload.query_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query text cannot be empty",
        )

    gateway = get_ai_gateway_service()
    answer = gateway.copilot_query(
        case_id=case_id,
        query_text=payload.query_text,
        operator_id=authenticated.principal.user_id,
        settings=settings,
    )

    return {
        "case_id": case_id,
        "answer": answer.answer,
        "model_used": answer.model_used,
        "referenced_artifacts": answer.referenced_artifacts,
        "confidence_score": answer.confidence_score,
        "timestamp": answer.timestamp,
    }


@router.get("/audit-logs")
def get_ai_audit_logs(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
) -> dict[str, Any]:
    """Returns AI chain-of-custody audit logs for legal compliance."""
    gateway = get_ai_gateway_service()
    logs = gateway.list_audit_logs(case_id=case_id)

    formatted_logs = [
        {
            "audit_id": log.audit_id,
            "case_id": log.case_id,
            "operator_id": log.operator_id,
            "timestamp": log.timestamp,
            "model_name": log.model_name,
            "provider": log.provider,
            "input_sha256": log.input_sha256,
            "response_sha256": log.response_sha256,
            "prompt_summary": log.prompt_summary,
            "court_admissible_signature": log.court_admissible_signature,
        }
        for log in logs
    ]

    return {
        "case_id": case_id,
        "total_audit_records": len(formatted_logs),
        "audit_logs": formatted_logs,
    }
