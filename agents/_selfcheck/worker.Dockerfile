# agent-selfcheck-worker: a worker image built in the same CI job as the self-check, so
# the lane proves smoke.sh --worker-image accepts a locally built tag (allowed by its
# image id) as well as a pinned reference. Never pushed.
ARG BUSYBOX_IMAGE=docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
FROM ${BUSYBOX_IMAGE}
LABEL org.opencontainers.image.title="agent-selfcheck-worker"
USER 65534:65534
