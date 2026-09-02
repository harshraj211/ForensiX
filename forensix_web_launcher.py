"""Launch the ForensiX API with the bundled SPA served from the same origin."""

from pathlib import Path

import uvicorn

from forensix_api.main import create_app

app = create_app(web_dist=Path("/opt/forensix/web/dist"))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
