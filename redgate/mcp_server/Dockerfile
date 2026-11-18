FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      dnsutils nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10002 mcpuser \
    && useradd -u 10002 -g mcpuser -s /usr/sbin/nologin mcpuser

WORKDIR /app
COPY mcp_server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY mcp_server /app/mcp_server
USER 10002:10002
EXPOSE 8001
CMD ["uvicorn", "mcp_server.http_server:app", "--host", "0.0.0.0", "--port", "8001"]
