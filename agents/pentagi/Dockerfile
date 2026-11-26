# syntax=docker/dockerfile:1
#
# The PentAGI agent image: the patched PentAGI server, PostgreSQL 17 with pgvector, and
# the driver that runs one flow per container (agents/pentagi/driver.py). No web UI, no
# scraper, no Graphiti, no observability stack: the minimum PentAGI needs for one
# headless flow. Workers are started through the cell's cell-guard, never here.
#
# Build context: agents/pentagi (this directory). The upstream source is fetched at the
# commit pinned in source.yaml and agents/pentagi/patches/*.patch are applied in name
# order; the build fails if the checkout is not exactly that commit or a patch does not
# apply.
#
#   docker buildx build -f agents/pentagi/Dockerfile \
#     --build-arg PENTAGI_COMMIT=<source.yaml commit> agents/pentagi
#
# Both bases are pinned by digest (the same digests as source.yaml; a test keeps them
# equal).

ARG GO_IMAGE=docker.io/library/golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd
ARG BASE_IMAGE=docker.io/pgvector/pgvector:0.8.6-pg17-bookworm@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f

# --------------------------------------------------------------------------- build
FROM ${GO_IMAGE} AS build
ARG PENTAGI_REPO=https://github.com/vxcontrol/pentagi
ARG PENTAGI_COMMIT
WORKDIR /src
RUN set -eu; \
    test -n "${PENTAGI_COMMIT}"; \
    git init -q .; \
    git remote add origin "${PENTAGI_REPO}"; \
    git fetch -q --depth 1 origin "${PENTAGI_COMMIT}"; \
    git -c advice.detachedHead=false checkout -q FETCH_HEAD; \
    test "$(git rev-parse HEAD)" = "${PENTAGI_COMMIT}"
COPY patches/ /patches/
RUN set -eu; for patch in /patches/*.patch; do git apply --verbose "${patch}"; done
WORKDIR /src/backend
ENV CGO_ENABLED=0 GO111MODULE=on
RUN go mod download && go mod verify
# the same version stamp as upstream's own Dockerfile ("ce": no release number)
RUN go build -trimpath \
      -ldflags "-X pentagi/pkg/version.PackageName=pentagi \
                -X pentagi/pkg/version.PackageVer=ce \
                -X pentagi/pkg/version.PackageRev= \
                -X pentagi/pkg/version.Edition=ce" \
      -o /out/pentagi ./cmd/pentagi

# --------------------------------------------------------------------------- runtime
FROM ${BASE_IMAGE}
# The base starts postgres as its entrypoint and stops with SIGINT; this image's
# command is the driver, which exports the evidence on SIGTERM (docker stop).
ENTRYPOINT []
STOPSIGNAL SIGTERM
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --uid 10001 --user-group --home-dir /tmp/pentagi \
      --shell /usr/sbin/nologin pentagi; \
    mkdir -p /opt/pentagi/bin /opt/pentagi/fe /opt/lab/pentagi /evidence; \
    chown pentagi:pentagi /evidence
COPY --from=build /out/pentagi /opt/pentagi/bin/pentagi
COPY driver.py /opt/lab/pentagi/driver.py
RUN chmod 0755 /opt/pentagi/bin/pentagi && chmod 0644 /opt/lab/pentagi/driver.py
USER pentagi
WORKDIR /tmp
CMD ["python3", "/opt/lab/pentagi/driver.py"]
