# syntax=docker/dockerfile:1
#
# hackingBuddyGPT agent image: upstream at the commit pinned in source.yaml, with
# patches/*.patch applied, installed from upstream's own uv.lock, plus the lab's use case
# (lab_hbg/, a plugin, not a patch). Built in CI only (agents/hackingbuddygpt/ci/build.sh):
#
#   docker buildx build -f agents/hackingbuddygpt/Dockerfile \
#     --build-arg HBG_COMMIT=<source.yaml commit> agents/hackingbuddygpt
#
# Run (the adapter renders the full command):
#
#   python -m lab_hbg LabWebTesting --llm.model=ollama_chat/<model> --llm.api_base=<tap> ...
#
# The LiteLLM switches below are also rendered by the adapter for every run; they are
# baked in too so that no way of starting this image can fetch LiteLLM's remote files.

ARG PYTHON_IMAGE=docker.io/library/python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.24@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------
# Build: fetch upstream at the pinned commit, patch it, install it into a venv.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS build

ARG HBG_REPO=https://github.com/ipa-lab/hackingBuddyGPT.git
ARG HBG_COMMIT
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv

# Only the exact commit: a full 40-character SHA, fetched by itself and checked.
RUN set -eu; \
    echo "$HBG_COMMIT" | grep -Eqx '[0-9a-f]{40}' \
      || { echo "HBG_COMMIT must be a full commit SHA, not '$HBG_COMMIT'" >&2; exit 1; }; \
    git init -q /src; \
    git -C /src fetch -q --depth 1 "$HBG_REPO" "$HBG_COMMIT"; \
    git -C /src checkout -q FETCH_HEAD; \
    test "$(git -C /src rev-parse HEAD)" = "$HBG_COMMIT"

COPY patches/ /patches/
RUN set -eu; \
    for patch in /patches/*.patch; do git -C /src apply --verbose "$patch"; done; \
    git -C /src diff --stat

# Upstream's own lock (LiteLLM 1.97.0), never re-resolved; no extras, so the RAG extra
# (OpenAI embeddings) is not even installed. The project is installed as a wheel, so the
# image needs no source checkout at run time.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/hbg/venv
RUN cd /src && uv sync --frozen --no-dev --no-editable \
 && /opt/hbg/venv/bin/python -c "import importlib.metadata as m; v = m.version('litellm'); assert v == '1.97.0', v" \
 && if /opt/hbg/venv/bin/python -c "import langchain_openai" 2>/dev/null; then \
        echo "the RAG extra is installed" >&2; exit 1; \
    fi

# ---------------------------------------------------------------------------
# Runtime: the venv and the lab's plugin, run as the cell's evidence user.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}

ARG HBG_COMMIT
LABEL org.opencontainers.image.title="agent-hackingbuddygpt" \
      lab.agent.framework="hackingbuddygpt" \
      lab.agent.upstream-commit="${HBG_COMMIT}"

RUN groupadd --gid 10001 agent \
 && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/agent \
        --shell /usr/sbin/nologin agent \
 && install -d -o 10001 -g 10001 -m 0755 /evidence /work

COPY --from=build /opt/hbg/venv /opt/hbg/venv
COPY lab_hbg/__init__.py lab_hbg/__main__.py lab_hbg/contract.py lab_hbg/usecase.py /opt/lab/lab_hbg/

ENV PATH=/opt/hbg/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/opt/lab \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LITELLM_LOCAL_MODEL_COST_MAP=True \
    LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS=True \
    LITELLM_MODE=PRODUCTION

USER 10001:10001
WORKDIR /work
CMD ["python", "-m", "lab_hbg", "LabWebTesting", "--help"]
