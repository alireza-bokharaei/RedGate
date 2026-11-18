# Stage 1: Build static Go sandbox-runner binary (zero external dependencies)
FROM golang:1.23-bookworm AS builder
WORKDIR /src
COPY sandbox_runner/go.mod sandbox_runner/main.go sandbox_runner/runner.go sandbox_runner/egress.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sandbox-runner .

FROM node:20-bookworm-slim AS node-toolchain

# Stage 2: Minimal isolated execution container (non-root, read-only rootfs ready)
FROM debian:bookworm-slim

COPY --from=builder /usr/local/go /usr/local/go
COPY --from=node-toolchain /usr/local/bin/node /usr/local/bin/node
COPY --from=builder /out/sandbox-runner /usr/local/bin/sandbox-runner

ENV PATH="/usr/local/go/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash python3 curl dnsutils openssl ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 sandbox \
    && useradd -u 10001 -g sandbox -d /tmp/sandbox -s /usr/sbin/nologin sandbox \
    && mkdir -p /tmp/sandbox && chown sandbox:sandbox /tmp/sandbox

USER 10001:10001
ENV REDGATE_SANDBOX_ADDR=0.0.0.0:8002
ENV REDGATE_SANDBOX_ROOT=/tmp/sandbox
EXPOSE 8002
ENTRYPOINT ["/usr/local/bin/sandbox-runner"]
