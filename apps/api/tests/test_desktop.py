from pathlib import Path

from fastapi.testclient import TestClient

from forensix_api.desktop import create_desktop_app
from forensix_server.config import Settings


def test_desktop_app_serves_assets_spa_routes_and_api(tmp_path: Path) -> None:
    web_root = tmp_path / "web"
    web_root.mkdir()
    (web_root / "index.html").write_text("<h1>ForensiX</h1>", encoding="utf-8")
    (web_root / "app.js").write_text("console.log('ForensiX');", encoding="utf-8")
    settings = Settings(environment="test", data_dir=tmp_path / "data")

    with TestClient(create_desktop_app(web_root, settings)) as client:
        assert client.get("/").text == "<h1>ForensiX</h1>"
        assert client.get("/cases/example").text == "<h1>ForensiX</h1>"
        assert client.get("/app.js").status_code == 200
        assert client.get("/missing.js").status_code == 404
        assert client.get("/api/v1/health/live").status_code == 200


def test_desktop_app_rejects_missing_web_bundle(tmp_path: Path) -> None:
    settings = Settings(environment="test", data_dir=tmp_path / "data")

    try:
        create_desktop_app(tmp_path / "missing", settings)
    except RuntimeError as error:
        assert "missing or incomplete" in str(error)
    else:
        raise AssertionError("Missing desktop assets must not start the application.")
