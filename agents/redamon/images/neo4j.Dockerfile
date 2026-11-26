# agent-redamon-neo4j: RedAmon's graph database with APOC baked in.
#
# Upstream sets NEO4J_PLUGINS='["apoc"]' (docker-compose.yml:65), which can make the
# image's entrypoint download the plugin at start; a cell has no way out. The official
# image ships APOC core under labs/, so it is copied into plugins/ at build instead. The
# procedure allow-list stays upstream's (set by the RedAmon adapter as env).

ARG NEO4J_IMAGE=docker.io/library/neo4j:5.26-community@sha256:c5fd91e41d44858ea678813fd53f8e60602e771a7656c502385247ffbcb0aec0
FROM ${NEO4J_IMAGE}
RUN set -eu; \
    set -- /var/lib/neo4j/labs/apoc-*-core.jar; \
    [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "expected exactly one APOC core jar under labs/" >&2; exit 1; }; \
    cp "$1" /var/lib/neo4j/plugins/
