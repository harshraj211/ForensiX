"""Loopback-only desktop launcher and bundled single-origin web host."""

import argparse
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

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
    origin = f"http://{host}:{arguments.port}"
    settings = Settings(
        environment="production",
        data_dir=arguments.data_dir or _default_data_dir(),
        adb_path=arguments.adb_path,
        allowed_origins=(origin,),
        api_host=host,
        api_port=arguments.port,
        deployment_transport="loopback_http",
    )
    app = create_desktop_app(_web_root(), settings)
    if arguments.no_browser:
        _run_server(app, host, arguments.port)
    elif arguments.browser:
        _run_in_browser(app, origin, host, arguments.port)
    else:
        _run_in_native_window(app, origin, host, arguments.port)
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


def _run_in_browser(app: FastAPI, origin: str, host: str, port: int) -> None:
    import webbrowser

    timer = threading.Timer(1.0, webbrowser.open, args=(origin,))
    timer.daemon = True
    timer.start()
    _run_server(app, host, port)


def _run_in_native_window(app: FastAPI, origin: str, host: str, port: int) -> None:
    try:
        import webview  # type: ignore[import-not-found]
    except ImportError:
        _run_in_browser(app, origin, host, port)
        return

    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="info"))
    server_thread = threading.Thread(target=server.run, name="forensix-api", daemon=True)
    server_thread.start()
    _wait_for_server(origin)
    try:
        webview.create_window(
            "ForensiX Workstation",
            origin,
            width=1440,
            height=920,
            min_size=(1024, 700),
            text_select=True,
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
