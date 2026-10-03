"""Cloud service breadth is exposed as a factual support matrix."""

from pathlib import Path

from fastapi.testclient import TestClient

from forensix_api.main import create_app
from forensix_server.auth import AuthService
from forensix_server.config import Settings


def test_cloud_service_catalog_lists_breadth_and_deep_targets(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session() as session:
            auth = AuthService(settings)
            auth.ensure_roles(session)
            issued = auth.bootstrap_administrator(
                session,
                username="cloud_admin",
                display_name="Cloud Admin",
                password="StrongPassword123!",
            )
        client.cookies.set("forensix_session", issued.session_token)

        response = client.get("/api/v1/integrations/cloud-services")

    assert response.status_code == 200, response.text
    items = response.json()
    assert len(items) >= 50
    by_id = {item["service_id"]: item for item in items}
    assert {
        "google",
        "whatsapp",
        "icloud",
        "microsoft",
        "telegram",
    }.issubset(by_id)
    assert {by_id[item]["depth"] for item in ("google", "whatsapp", "icloud", "microsoft", "telegram")} == {
        "deep_target"
    }
    assert by_id["whatsapp"]["blocker_class"] == "encryption"
    assert "Takeout import" in " ".join(by_id["google"]["auth_methods"])
