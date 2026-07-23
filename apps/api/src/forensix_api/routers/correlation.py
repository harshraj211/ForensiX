"""Case-scoped, explainable evidence-correlation graph."""

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_api.schemas import (
    CorrelationEdgeResponse,
    CorrelationGraphResponse,
    CorrelationNodeResponse,
)
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database
from forensix_server.evidence import CorrelationService

router = APIRouter(prefix="/api/v1/cases/{case_id}/correlations", tags=["correlations"])


@router.get("", response_model=CorrelationGraphResponse)
def get_correlation_graph(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> CorrelationGraphResponse:
    with database.session() as session:
        graph = CorrelationService().build(session, authenticated.principal, case_id)
    return CorrelationGraphResponse(
        case_id=graph.case_id,
        nodes=[CorrelationNodeResponse(**asdict(item)) for item in graph.nodes],
        edges=[CorrelationEdgeResponse(**asdict(item)) for item in graph.edges],
        graph_hash=graph.graph_hash,
        builder_version=graph.builder_version,
        truncated=graph.truncated,
        warnings=list(graph.warnings),
    )
