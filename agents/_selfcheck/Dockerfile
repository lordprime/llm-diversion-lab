# agent-selfcheck: the agent lane's own self-check (selfcheck.py), not a tool under test.
# Built and smoke-tested by build-images.yml like an agent image, never pushed.
#
#   docker buildx build --load -f agents/_selfcheck/Dockerfile -t agent-selfcheck:ci agents/_selfcheck

ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
FROM ${PYTHON_IMAGE}
RUN groupadd --system --gid 10001 selfcheck \
 && useradd --system --uid 10001 --gid selfcheck --home-dir /nonexistent --shell /usr/sbin/nologin selfcheck
COPY selfcheck.py /opt/selfcheck/selfcheck.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "/opt/selfcheck/selfcheck.py"]
CMD ["apis"]
