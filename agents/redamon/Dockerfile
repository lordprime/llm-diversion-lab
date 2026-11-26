# agent-redamon: the RedAmon driver (agents/redamon/driver.py), the cell's `agent`
# service for RedAmon runs. It starts RedAmon's five services through cell-guard, so
# it holds none of RedAmon's code itself; the `source` stage below is the RedAmon tree
# the other images are built from (ci/build.sh exports it with --target source).
#
#   docker buildx build -f agents/redamon/Dockerfile -t agent-redamon .   (repo root)
#
# Stage `source`: RedAmon at the commit in agents/redamon/source.yaml, fetched by
# commit (never a branch), checked, and patched with agents/redamon/patches/*.patch in
# file-name order. A patch that does not apply fails the build.
#
# Runs as the unprivileged uid 10001. The driver needs only the cell-guard socket
# (mode 0666) and its evidence volume.

ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.24@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a

FROM ${PYTHON_IMAGE} AS source
ARG REDAMON_REPO=https://github.com/samugit83/redamon.git
ARG REDAMON_COMMIT=73ca9d38ced026be6d88d1dc526c72317e7d193c
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY agents/redamon/patches /patches
RUN git init --quiet /redamon \
 && git -C /redamon fetch --quiet --depth 1 "$REDAMON_REPO" "$REDAMON_COMMIT" \
 && git -C /redamon checkout --quiet --detach FETCH_HEAD \
 && test "$(git -C /redamon rev-parse HEAD)" = "$REDAMON_COMMIT" \
 && for p in /patches/*.patch; do git -C /redamon apply --verbose "$p"; done \
 && rm -rf /redamon/.git

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
ENV UV_LINK_MODE=copy UV_NO_CACHE=1 UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /opt/lab
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project \
 && uv pip install --python /opt/lab/.venv/bin/python websockets==17.4

FROM ${PYTHON_IMAGE}
RUN groupadd --system --gid 10001 lab \
 && useradd --system --uid 10001 --gid lab --home-dir /nonexistent --shell /usr/sbin/nologin lab \
 && mkdir -p /evidence /etc/lab \
 && chown 10001:10001 /evidence \
 && chmod 0750 /evidence
COPY --from=build /opt/lab/.venv /opt/lab/.venv
COPY agents/__init__.py /opt/lab/agents/__init__.py
COPY agents/redamon/__init__.py agents/redamon/plan.py agents/redamon/driver.py /opt/lab/agents/redamon/
ENV PATH=/opt/lab/.venv/bin:$PATH \
    PYTHONPATH=/opt/lab \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
WORKDIR /opt/lab
RUN python -c "import agents.redamon.driver, websockets.sync.client"
USER 10001:10001
CMD ["python", "-m", "agents.redamon.driver", "--plan", "/etc/lab/agent/redamon-plan.json"]
