# ADHD lab image: offline analysis, MCP server and agent.  Standard library only: no pip install.
# Air-gapped lab: build on a connected machine, then `docker save` / `docker load` (docs/docker.md).
ARG BASE=python:3.12-slim
FROM ${BASE}

LABEL org.opencontainers.image.title="adhd" \
      org.opencontainers.image.description="AD + Entra ID hybrid assessment: offline analysis, attack paths, read-only MCP server, local-model agent" \
      org.opencontainers.image.source="https://github.com/Kevintw88/ADHD"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONUTF8=1
WORKDIR /opt/adhd
COPY adhd/ adhd/
COPY tools/ tools/
COPY tests/python/ tests/python/
COPY docker/entrypoint.py docker/entrypoint.py
COPY docs/ docs/
COPY README.md LICENSE ./

# no user database entry needed; any uid works because the image only reads /opt/adhd
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["python3", "/opt/adhd/docker/entrypoint.py"]
CMD ["--help"]
