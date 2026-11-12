# Runs the read-only ONAA Registry MCP server over stdio.
# It talks to the public development registry at https://api.onaa.net by default.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ONAA_REGISTRY_URL=https://api.onaa.net

WORKDIR /app
COPY packages/sdk-python ./packages/sdk-python
COPY apps/mcp-registry ./apps/mcp-registry

RUN pip install --no-cache-dir ./packages/sdk-python ./apps/mcp-registry \
    && useradd --create-home --uid 10001 onaa

USER onaa
ENTRYPOINT ["onaa-mcp-registry"]
