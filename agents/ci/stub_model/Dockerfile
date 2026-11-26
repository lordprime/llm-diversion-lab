# lab-smoke-kit: the helpers agents/ci/smoke.sh runs around an agent image in CI.
#
#   * the recording stub model   python -m agents.ci.stub_model.server   (uid 10001)
#   * the egress canary          python -m agents.ci.canary.canary       (root, NET_RAW)
#   * cell-guard (--docker)      python -m cell.cellguard.proxy          (root, no caps)
#
# Built from the repository root (the root .dockerignore allow-list is the context)
# by build-images.yml before an agent image is checked; never pushed:
#
#   docker buildx build --load -f agents/ci/stub_model/Dockerfile -t lab-smoke-kit:ci .
#
# Only the lab's main dependencies from uv.lock are installed (no dev group, no cell
# extra), and only the code the three helpers import is copied.

ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.24@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
ENV UV_LINK_MODE=copy UV_NO_CACHE=1 UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /opt/lab
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM ${PYTHON_IMAGE}
RUN groupadd --system --gid 10001 lab \
 && useradd --system --uid 10001 --gid lab --home-dir /nonexistent --shell /usr/sbin/nologin lab
COPY --from=build /opt/lab/.venv /opt/lab/.venv
COPY control/__init__.py /opt/lab/control/__init__.py
COPY control/core /opt/lab/control/core
COPY control/telemetry /opt/lab/control/telemetry
COPY cell/__init__.py /opt/lab/cell/__init__.py
COPY cell/tap /opt/lab/cell/tap
COPY cell/catcher /opt/lab/cell/catcher
COPY cell/cellguard /opt/lab/cell/cellguard
COPY agents/__init__.py /opt/lab/agents/__init__.py
COPY agents/ci /opt/lab/agents/ci
ENV PATH=/opt/lab/.venv/bin:$PATH \
    PYTHONPATH=/opt/lab \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
WORKDIR /opt/lab
RUN rm -f /opt/lab/agents/ci/stub_model/Dockerfile \
 && find /opt/lab -name '__pycache__' -prune -exec rm -rf {} + \
 && python -c "import agents.ci.stub_model.server, agents.ci.stub_model.verify, agents.ci.canary.canary, cell.cellguard.proxy" \
 && find /opt/lab -name '__pycache__' -prune -exec rm -rf {} +
USER 10001:10001
CMD ["python", "-m", "agents.ci.stub_model.server", "--script", "/etc/stub/script.yaml", "--record", "/tmp/requests.jsonl"]
