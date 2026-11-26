# agent-strix: Strix (usestrix/strix) as a lab agent, pinned to the commit in
# agents/strix/source.yaml with the lab patches in agents/strix/patches applied.
#
#   bash agents/strix/ci/build.sh agent-strix:ci          (repository root)
#
# Strix is installed with `uv sync --frozen` from its own uv.lock, so every Python
# dependency is the version upstream locked (LiteLLM 1.101.0, openai-agents 0.19.0).
# The project is installed editable: a wheel build would compile the Go TUI, which a
# headless run never uses. Nothing is fetched at run time.
#
# Strix only checks that a `docker` command exists (strix/interface/environment.py 167);
# it talks to Docker through the Python SDK and DOCKER_HOST, which in a cell is
# cell-guard. The image therefore ships a `docker` that refuses to run instead of the
# real CLI.
#
# Runs as the unprivileged uid 10001, like the lab-cell image. HOME and the run folder
# are set by the adapter (a tmpfs path and the agent's evidence folder).

ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.24@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
ARG STRIX_REPO
ARG STRIX_COMMIT
ENV UV_LINK_MODE=copy UV_NO_CACHE=1 UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never
COPY --from=uv /uv /usr/local/bin/uv
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/strix
RUN test -n "$STRIX_REPO" && echo "$STRIX_COMMIT" | grep -Eqx '[0-9a-f]{40}' \
 && git init --quiet . \
 && git fetch --quiet --depth 1 "$STRIX_REPO" "$STRIX_COMMIT" \
 && git checkout --quiet --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$STRIX_COMMIT"
COPY agents/strix/patches/ /tmp/patches/
RUN for p in /tmp/patches/*.patch; do git apply --verbose "$p"; done \
 && rm -rf .git /tmp/patches
RUN uv sync --frozen --no-dev

FROM ${PYTHON_IMAGE}
RUN groupadd --system --gid 10001 lab \
 && useradd --system --uid 10001 --gid lab --home-dir /nonexistent --shell /usr/sbin/nologin lab \
 && mkdir -p /evidence /etc/lab /opt/lab \
 && chown 10001:10001 /evidence \
 && chmod 0750 /evidence \
 && printf '#!/bin/sh\necho "docker: no Docker CLI in this image; Strix uses DOCKER_HOST through the Python SDK" >&2\nexit 127\n' > /usr/local/bin/docker \
 && chmod 0755 /usr/local/bin/docker
COPY --from=build /opt/strix /opt/strix
COPY --chmod=0755 agents/strix/strix-entrypoint.sh /opt/lab/strix-entrypoint
ENV PATH=/opt/strix/.venv/bin:$PATH \
    HOME=/tmp/strix-home \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /tmp
CMD ["/opt/lab/strix-entrypoint", "--help"]
