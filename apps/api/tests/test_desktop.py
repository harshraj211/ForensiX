import socket
from pathlib import Path

from fastapi.testclient import TestClient

from forensix_api.desktop import DesktopDownloadApi, _select_port, create_desktop_app
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


def test_desktop_launcher_skips_a_busy_port() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        busy_port = blocker.getsockname()[1]

        selected = _select_port("127.0.0.1", busy_port)

    assert selected != busy_port


def test_native_download_api_streams_to_the_selected_path(tmp_path: Path) -> None:
    target = tmp_path / "exports" / "audit.json"

    class FakeWindow:
        def create_file_dialog(self, _dialog_type: object, *, save_filename: str) -> tuple[str]:
            assert save_filename == "audit.json"
            target.parent.mkdir()
            return (str(target),)

    class FakeWebView:
        SAVE_DIALOG = object()
        windows = [FakeWindow()]

    api = DesktopDownloadApi(FakeWebView())
    started = api.start_download("audit.json")
    assert started["status"] == "ready"
    download_id = started["download_id"]
    assert isinstance(download_id, str)

    import base64

    api.append_download(download_id, base64.b64encode(b'{"ok":true}').decode("ascii"))
    finished = api.finish_download(download_id)

    assert finished["status"] == "saved"
    assert target.read_bytes() == b'{"ok":true}'
