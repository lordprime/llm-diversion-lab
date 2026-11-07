# syntax=docker/dockerfile:1
#
# lab-cell: the harness's in-cell components in one image -- the surface injector
# and the LLM tap (mitmproxy addons), the callback catcher, the stub LLM, cell-guard,
# the containment probe and the scripted (non-LLM) self-test agent. Each cell
# service runs one of them by its command (deploy/compose/cell.<target>.yml).
#
# Only the code a cell runs is copied: control/core (shared models), cell/ and
# agents/. The control plane (runner, database, Collector API, labeller) and the
# lab HMAC key never enter this image.
#
#   docker buildx build -f cell/Dockerfile -t lab-cell .        (repository root)
#
# Runs as the unprivileged uid 10001 by default; a service that must bind a port
# below 1024 (the catcher's DNS and HTTP, the injector's :80) runs as root with
# every capability dropped except NET_BIND_SERVICE (set in the cell file).

ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.24@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
ENV UV_LINK_MODE=copy UV_NO_CACHE=1 UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /opt/lab
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --extra cell --no-install-project

FROM ${PYTHON_IMAGE}
RUN groupadd --system --gid 10001 lab \
 && useradd --system --uid 10001 --gid lab --home-dir /nonexistent --shell /usr/sbin/nologin lab \
 && mkdir -p /evidence /etc/lab \
 && chown lab:lab /evidence \
 && chmod 0755 /evidence /etc/lab
COPY --from=build /opt/lab/.venv /opt/lab/.venv
COPY control/__init__.py /opt/lab/control/__init__.py
COPY control/core /opt/lab/control/core
COPY cell /opt/lab/cell
COPY agents /opt/lab/agents
ENV PATH=/opt/lab/.venv/bin:$PATH \
    PYTHONPATH=/opt/lab \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
WORKDIR /opt/lab
RUN rm -f /opt/lab/cell/Dockerfile \
 && find /opt/lab -name '__pycache__' -prune -exec rm -rf {} + \
 && python -c "import cell.injector.placement, cell.tap.recorder, cell.catcher.http_app, cell.catcher.dns_server, cell.catcher.serve, cell.injector.preflight, cell.stub_llm.app, cell.cellguard.proxy, agents.scripted.agent" \
 && mitmdump --version >/dev/null \
 && find /opt/lab -name '__pycache__' -prune -exec rm -rf {} +
USER 10001:10001
