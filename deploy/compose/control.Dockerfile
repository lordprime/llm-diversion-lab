# Control-plane image: the Collector API (python -m control.api) and the migrate
# one-shot (python -m control.cli.migrate). Build context: the repository root
# (deploy/compose/control-plane.yml sets it).
#
# Every base image is pinned by its multi-arch index digest (a test checks it);
# refresh them only in a reviewed commit:
#   python 3.12.16-slim-bookworm, uv 0.11.21 (resolved 7 Nov 2026).
# Dependencies come from uv.lock exactly (--frozen), without the dev group and
# without the in-cell extras (mitmproxy).

FROM docker.io/library/python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --no-cache

FROM docker.io/library/python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
RUN useradd --system --uid 10001 --user-group --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin lab
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY control ./control
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "control.api", "--host", "0.0.0.0", "--port", "8000"]
