# agent-redamon-kali-standin-smoke-only: a CI stand-in for RedAmon's Kali sandbox.
#
# It runs RedAmon's own MCP servers (mcp/servers at the pinned, patched commit) with
# their Python libraries, but none of the tools: a tool call reaches the server and
# fails. That is enough for the smoke, which checks that every model call reaches the
# tap; the real sandbox (mcp/kali-sandbox/Dockerfile, tens of GB) is built and pinned on
# the CISPA VM. Its name carries "kali-standin-smoke-only", and the RedAmon run plan
# refuses that name outside the smoke. No entrypoint update runs here at all.
#
# Build context: the patched RedAmon tree's mcp/ directory (ci/build.sh).

ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
FROM ${PYTHON_IMAGE}
# fastmcp and mcp as upstream pins them (mcp/requirements.txt, pip-constraints.txt);
# the rest resolve against them. The stand-in is rebuilt per CI job and never pinned
# into a run, so its other versions do not need to be.
COPY kali-sandbox/pip-constraints.txt /tmp/pip-constraints.txt
RUN pip install --no-cache-dir -c /tmp/pip-constraints.txt \
      fastmcp==3.2.4 mcp==1.29.0 "httpx[http2]" sse-starlette starlette uvicorn \
      pydantic PyYAML requests websockets
RUN groupadd --system --gid 10001 lab \
 && useradd --system --uid 10001 --gid lab --home-dir /tmp --shell /usr/sbin/nologin lab \
 && mkdir -p /opt/mcp_servers /opt/output /workspace \
 && chown 10001:10001 /opt/output
COPY servers/ /opt/mcp_servers/
ENV PYTHONPATH=/opt:/opt/mcp_servers PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /tmp
RUN cd /opt/mcp_servers \
 && for s in network_recon_server nuclei_server metasploit_server nmap_server playwright_server; do \
      python -c "import importlib; importlib.import_module('$s')" || exit 1; \
    done
USER 10001:10001
CMD ["python", "/opt/mcp_servers/run_servers.py"]
