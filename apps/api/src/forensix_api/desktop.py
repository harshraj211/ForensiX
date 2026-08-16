"""Loopback-only desktop launcher and bundled single-origin web host."""

import argparse
import base64
import binascii
import hashlib
import importlib
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

import uvicorn
from fastapi import FastAPI
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from forensix_api.main import create_app
from forensix_server.config import Settings


class SpaStaticFiles(StaticFiles):
    """Serve the bundled SPA while retaining 404 responses for missing assets."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except HTTPException as error:
            if error.status_code != 404 or Path(path).suffix:
                raise
            return await super().get_response("index.html", scope)
        if response.status_code == 404 and not Path(path).suffix:
            return await super().get_response("index.html", scope)
        return response


@dataclass
class _DownloadSession:
    target: Path
    temporary: Path
    stream: BinaryIO
    bytes_written: int = 0


class DesktopDownloadApi:
    """Save authenticated WebView downloads through a native file dialog."""

    def __init__(self, webview: Any) -> None:
        self._webview = webview
        self._downloads: dict[str, _DownloadSession] = {}
        self._lock = threading.Lock()

    def start_download(self, filename: str = "forensix-download") -> dict[str, str]:
        window = self._window()
        safe_name = _safe_download_filename(filename)
        selected = window.create_file_dialog(
            self._webview.SAVE_DIALOG,
            save_filename=safe_name,
        )
        if not selected:
            return {"status": "cancelled"}
        target = Path(selected[0] if isinstance(selected, (list, tuple)) else selected).expanduser()
        if not target.parent.is_dir():
            raise RuntimeError("The selected download folder is not available.")

        download_id = secrets.token_urlsafe(18)
        temporary = target.with_name(f".{target.name}.{download_id}.part")
        stream = temporary.open("xb")
        with self._lock:
            self._downloads[download_id] = _DownloadSession(target, temporary, stream)
        return {"status": "ready", "download_id": download_id}

    def append_download(self, download_id: str, chunk_base64: str) -> dict[str, int]:
        try:
            chunk = base64.b64decode(chunk_base64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("The native download chunk is invalid.") from error
        if len(chunk) > 2 * 1024 * 1024:
            raise ValueError("The native download chunk is too large.")
        with self._lock:
            session = self._downloads.get(download_id)
            if session is None:
                raise ValueError("The native download session is no longer active.")
            session.stream.write(chunk)
            session.bytes_written += len(chunk)
            return {"bytes_written": session.bytes_written}

    def finish_download(self, download_id: str) -> dict[str, str | int]:
        with self._lock:
            session = self._downloads.pop(download_id, None)
        if session is None:
            raise ValueError("The native download session is no longer active.")
        try:
            session.stream.flush()
            session.stream.close()
            os.replace(session.temporary, session.target)
        except Exception:
            session.stream.close()
            session.temporary.unlink(missing_ok=True)
            raise
        return {
            "status": "saved",
            "path": str(session.target),
            "bytes_written": session.bytes_written,
        }

    def cancel_download(self, download_id: str) -> dict[str, str]:
        with self._lock:
            session = self._downloads.pop(download_id, None)
        if session is not None:
            session.stream.close()
            session.temporary.unlink(missing_ok=True)
        return {"status": "cancelled"}

    def _window(self) -> Any:
        windows = getattr(self._webview, "windows", [])
        if not windows:
            raise RuntimeError("The native workstation window is not ready.")
        return windows[0]


def _safe_download_filename(filename: str) -> str:
    candidate = Path(filename or "forensix-download").name
    candidate = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", candidate).strip(" .")
    return candidate or "forensix-download"


def create_desktop_app(web_root: Path, settings: Settings) -> FastAPI:
    root = web_root.expanduser().resolve()
    if not root.is_dir() or not (root / "index.html").is_file():
        raise RuntimeError("The bundled web application is missing or incomplete.")
    app = create_app(settings)
    app.mount("/", SpaStaticFiles(directory=root, html=True), name="desktop-web")
    return app


def main() -> int:
    arguments = _arguments()
    host = "127.0.0.1"
    port = _select_port(host, arguments.port)
    if port != arguments.port:
        print(
            f"Port {arguments.port} is already in use; using available port {port}.",
            file=sys.stderr,
        )
    origin = f"http://{host}:{port}"
    settings = Settings(
        environment="production",
        data_dir=arguments.data_dir or _default_data_dir(),
        adb_path=arguments.adb_path,
        allowed_origins=(origin,),
        api_host=host,
        api_port=port,
        deployment_transport="loopback_http",
        scrcpy_path=_scrcpy_path(),
        scrcpy_expected_sha256=_scrcpy_expected_sha256(),
    )
    app = create_desktop_app(_web_root(), settings)
    if arguments.no_browser:
        _run_server(app, host, port)
    elif arguments.browser:
        _run_in_browser(app, origin, host, port)
    else:
        _run_in_native_window(app, origin, host, port)
    return 0


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start the local ForensiX workstation.")
    parser.add_argument("--port", type=int, default=8765, choices=range(1024, 65536))
    parser.add_argument("--adb-path", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Open the workstation in the default browser instead of a native window.",
    )
    parser.add_argument("--no-browser", action="store_true")
    return parser.parse_args()


def _run_server(app: FastAPI, host: str, port: int) -> None:
    uvicorn.run(app, host=host, port=port, log_level="info")


def _select_port(host: str, requested: int) -> int:
    """Use the requested port when free, otherwise find a nearby free port."""
    for port in range(requested, min(requested + 100, 65536)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"No available loopback port found near {requested}.")


def _scrcpy_path() -> Path | None:
    configured = os.environ.get("FORENSIX_SCRCPY_PATH")
    if configured:
        return Path(configured).expanduser()
    bundle_root = getattr(sys, "_MEIPASS", None)
    if isinstance(bundle_root, str):
        candidate = Path(bundle_root) / "tools" / "scrcpy" / "scrcpy.exe"
    else:
        candidate = Path(__file__).resolve().parents[4] / "tools" / "scrcpy" / "scrcpy.exe"
    return candidate if candidate.is_file() else None


def _scrcpy_expected_sha256() -> str | None:
    configured = os.environ.get("FORENSIX_SCRCPY_EXPECTED_SHA256")
    if configured:
        return configured.lower()
    path = _scrcpy_path()
    if path is None:
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run_in_browser(app: FastAPI, origin: str, host: str, port: int) -> None:
    import webbrowser

    timer = threading.Timer(1.0, webbrowser.open, args=(origin,))
    timer.daemon = True
    timer.start()
    _run_server(app, host, port)


def _run_in_native_window(app: FastAPI, origin: str, host: str, port: int) -> None:
    try:
        webview: Any = importlib.import_module("webview")
    except ImportError:
        _run_in_browser(app, origin, host, port)
        return

    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="info"))
    server_thread = threading.Thread(target=server.run, name="forensix-api", daemon=True)
    server_thread.start()
    _wait_for_server(origin)
    try:
        download_api = DesktopDownloadApi(webview)
        webview.create_window(
            "ForensiX Workstation",
            origin,
            width=1440,
            height=920,
            min_size=(1024, 700),
            text_select=True,
            js_api=download_api,
        )
        webview.start()
    except Exception as error:  # noqa: BLE001
        print(f"Native window unavailable ({error}); opening the browser instead.", file=sys.stderr)
        server.should_exit = True
        server_thread.join(timeout=5)
        _run_in_browser(app, origin, host, port)
        return
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)


def _wait_for_server(origin: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(origin, timeout=0.5):  # noqa: S310
                return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)


def _web_root() -> Path:
    bundle_root = getattr(sys, "_MEIPASS", None)
    if isinstance(bundle_root, str):
        return Path(bundle_root) / "web"
    return Path(__file__).resolve().parents[3] / "web" / "dist"


def _default_data_dir() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "ForensiX"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ForensiX"
    root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "forensix"


if __name__ == "__main__":
    raise SystemExit(main())
