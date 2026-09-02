# syntax=docker/dockerfile:1

###############################################################################
# Stage 1: Build the React/TypeScript web application.
###############################################################################
FROM node:24-bookworm-slim AS web-build

WORKDIR /build

# Install pnpm first, then dependencies using the committed lockfile.
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Build the web application.
COPY apps/web/package.json apps/web/package.json
COPY tsconfig.base.json tsconfig.base.json
COPY apps/web/tsconfig.json apps/web/tsconfig.json
COPY apps/web/tsconfig.app.json apps/web/tsconfig.app.json
COPY apps/web/tsconfig.node.json apps/web/tsconfig.node.json
COPY apps/web/vite.config.ts apps/web/vite.config.ts
COPY apps/web/index.html apps/web/index.html
COPY apps/web/src apps/web/src
RUN pnpm --filter @forensix/web build

###############################################################################
# Stage 2: Install Python packages.
###############################################################################
FROM python:3.12-slim AS python-deps

WORKDIR /install

# Build dependencies for wheels that must be compiled from source.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY forensic/pyproject.toml forensic/pyproject.toml
COPY server/pyproject.toml server/pyproject.toml
COPY apps/api/pyproject.toml apps/api/pyproject.toml
COPY forensic forensic
COPY server server
COPY apps/api apps/api
# The Python packages are installed as wheels here only to resolve their
# dependencies into site-packages. The runtime imports the packages from the
# copied source trees under /opt/forensix (via PYTHONPATH) so the source-relative
# Alembic migration resolution keeps working.
RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir ./forensic ./server ./apps/api

###############################################################################
# Stage 3: Production runtime.
###############################################################################
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="ForensiX"
LABEL org.opencontainers.image.description="Local Android evidence-triage workstation"
LABEL org.opencontainers.image.version="1.0.0"

# curl for health checks; android-tools-adb provides the device transport.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes curl android-tools-adb \
    && rm -rf /var/lib/apt/lists/*

# Create a dedicated, non-root user.
RUN useradd --create-home --uid 10001 forensix

WORKDIR /opt/forensix

# The Python packages are installed as wheels into site-packages for their
# dependencies. The ForensiX source trees are also copied here and imported via
# PYTHONPATH so the source-relative Alembic migration resolution keeps working.
COPY --from=python-deps /install/forensic /opt/forensix/forensic
COPY --from=python-deps /install/server /opt/forensix/server
COPY --from=python-deps /install/apps /opt/forensix/apps
COPY --from=python-deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-deps /usr/local/bin /usr/local/bin
# Verify the source trees are importable before continuing.
RUN PYTHONPATH=/opt/forensix/forensic/src:/opt/forensix/server/src:/opt/forensix/apps/api/src \
    python -c "import forensix_api, forensix_server, forensix_forensic"

# The API serves the SPA through Starlette's StaticFiles.
COPY --from=web-build /build/apps/web/dist /opt/forensix/web/dist
# Fail fast when the web build is absent rather than serving an empty UI.
RUN test -f /opt/forensix/web/dist/index.html
# Launcher that serves the compiled SPA and the API from the same origin.
COPY forensix_web_launcher.py /opt/forensix/forensix_web_launcher.py
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# This application enforces a loopback-only security model: the API is designed
# to run on a single investigator workstation and must not be published as a
# LAN or internet service. The container therefore binds the loopback interface.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FORENSIX_ENVIRONMENT=production \
    FORENSIX_DEPLOYMENT_TRANSPORT=loopback_http \
    FORENSIX_API_HOST=127.0.0.1 \
    FORENSIX_API_PORT=8765 \
    FORENSIX_DATA_DIR=/data \
    FORENSIX_ALLOWED_ORIGINS='["http://127.0.0.1:5173"]' \
    PYTHONPATH=/opt/forensix/forensic/src:/opt/forensix/server/src:/opt/forensix/apps/api/src

# Persistent case database and evidence.
VOLUME ["/data"]

EXPOSE 8765

# Default to root so the entrypoint can prepare the mounted /data volume for the
# unprivileged runtime user. Rootless container engines are the operator's
# responsibility. Override the entrypoint when running as a non-root user.
USER root

# uvicorn serves both the API and the bundled SPA on one loopback origin.
# Use --network host for physical-device (ADB over USB) workflows, or map the
# loopback port only (never publish the port on a LAN-facing interface).
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "/opt/forensix/forensix_web_launcher.py"]
