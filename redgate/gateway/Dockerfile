FROM golang:1.23-bookworm AS go-toolchain
FROM node:20-bookworm-slim AS node-toolchain

FROM python:3.12-slim-bookworm

# Copy modern Go 1.23 and Node.js 20 toolchains for static validation (gofmt/vet/build, node --check, ESLint v9)
COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=node-toolchain /usr/local/bin/node /usr/local/bin/node
COPY --from=node-toolchain /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

ENV PATH="/usr/local/go/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash shellcheck ca-certificates \
    && npm install -g eslint@9 \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10000 redgate \
    && useradd -u 10000 -g redgate -d /tmp -s /usr/sbin/nologin redgate \
    && mkdir -p /app/data /tmp/sandbox \
    && chown -R redgate:redgate /app/data /tmp/sandbox

WORKDIR /app
COPY gateway/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY gateway /app/gateway
COPY mcp_server/__init__.py mcp_server/tools.py /app/mcp_server/
COPY config /app/config
COPY skills /app/skills

ENV REDGATE_SKILLS_DIR=/app/skills
USER 10000:10000
EXPOSE 8000
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
