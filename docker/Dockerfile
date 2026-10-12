# hybrid-idsec：確定性核心 + 唯讀 MCP + Agent 層
# Claude Agent SDK 內建原生 CLI，不需要 Node.js。
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/idsec \
    IDSEC_HOME=/app

RUN useradd --create-home --uid 10001 idsec
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[live]"

COPY config ./config
COPY .claude ./.claude
COPY mock_data ./mock_data

RUN mkdir -p /app/output && chown -R idsec:idsec /app/output
USER idsec

ENTRYPOINT ["idsec"]
CMD ["run"]
