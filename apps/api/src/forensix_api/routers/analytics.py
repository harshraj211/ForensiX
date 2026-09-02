"""Case-scoped intelligence analytics: Geo-Location trails and Social Link Graph."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from forensix_api.dependencies import get_authenticated_session, get_database
from forensix_server.auth import AuthenticatedSession
from forensix_server.db import Database
from forensix_server.investigation import (
    GeoLocationAnalyticsService,
    SocialGraphAnalyticsService,
)

router = APIRouter(prefix="/api/v1/cases/{case_id}/analytics", tags=["analytics"])


class GeoLocationResponse(BaseModel):
    case_id: str
    total_points: int
    bounding_box: dict[str, float] | None
    points: list[dict[str, Any]]
    clusters_summary: list[dict[str, Any]]
    providers_summary: dict[str, int]


class SocialGraphResponse(BaseModel):
    case_id: str
    total_nodes: int
    total_edges: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    top_identities: list[dict[str, Any]]
    channels_summary: dict[str, int]


@router.get("/geolocation", response_model=GeoLocationResponse)
def get_case_geolocation(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> GeoLocationResponse:
    """Retrieve all spatial geolocation observations, EXIF locations, and map searches."""
    with database.session() as session:
        result = GeoLocationAnalyticsService(session, authenticated.principal).get_case_geolocation(
            case_id
        )
    return GeoLocationResponse(
        case_id=result.case_id,
        total_points=result.total_points,
        bounding_box=result.bounding_box,
        points=result.points,
        clusters_summary=result.clusters_summary,
        providers_summary=result.providers_summary,
    )


@router.get("/social-graph", response_model=SocialGraphResponse)
def get_case_social_graph(
    case_id: str,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    database: Annotated[Database, Depends(get_database)],
) -> SocialGraphResponse:
    """Retrieve social network topology and communication links across messaging platforms."""
    with database.session() as session:
        service = SocialGraphAnalyticsService(session, authenticated.principal)
        result = service.get_case_social_graph(case_id)
    return SocialGraphResponse(
        case_id=result.case_id,
        total_nodes=result.total_nodes,
        total_edges=result.total_edges,
        nodes=result.nodes,
        edges=result.edges,
        top_identities=result.top_identities,
        channels_summary=result.channels_summary,
    )
