"""Tests for the analytics API router."""

from pathlib import Path

from fastapi.testclient import TestClient

from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.cases import CaseService
from forensix_server.config import Settings


def test_analytics_endpoints_require_authentication(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)

    with TestClient(app) as client:
        res1 = client.get("/api/v1/cases/case-123/analytics/geolocation")
        assert res1.status_code in (401, 403)

        res2 = client.get("/api/v1/cases/case-123/analytics/social-graph")
        assert res2.status_code in (401, 403)


def test_analytics_endpoints_with_authenticated_session(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)

    with TestClient(app) as client:
        db = app.state.database
        with db.session() as session:
            auth_service = AuthService(settings)
            auth_service.ensure_roles(session)
            issued = auth_service.bootstrap_administrator(
                session,
                username="lead_analyst",
                display_name="Lead Analyst",
                password="StrongPassword123!",
            )
            principal = issued.principal
            case = CaseService().create(session, principal, title="Triage Investigation")
            case_id = case.id
            token = issued.session_token

        client.cookies.set("forensix_session", token)

        # 2. Test Geolocation endpoint
        geo_res = client.get(f"/api/v1/cases/{case_id}/analytics/geolocation")
        assert geo_res.status_code == 200
        geo_data = geo_res.json()
        assert geo_data["case_id"] == case_id
        assert "points" in geo_data
        assert "clusters_summary" in geo_data
        assert "providers_summary" in geo_data

        # 3. Test Social Graph endpoint
        graph_res = client.get(f"/api/v1/cases/{case_id}/analytics/social-graph")
        assert graph_res.status_code == 200
        graph_data = graph_res.json()
        assert graph_data["case_id"] == case_id
        assert "nodes" in graph_data
        assert "edges" in graph_data
        assert "top_identities" in graph_data
