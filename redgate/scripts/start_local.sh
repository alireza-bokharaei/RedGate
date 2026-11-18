#!/usr/bin/env bash
# =============================================================================
# RedGate Local Integrated Stack Launcher
# Generates fresh ephemeral random credentials at every startup (zero hardcoded
# secrets), starts Layer 3 Go Sandbox Runner + Layer 2 Python MCP Server on
# loopback, and serves Layer 1 FastAPI Gateway + RedGate Web Console on :8000.
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p "$ROOT_DIR/data" "$ROOT_DIR/bin" /tmp/sandbox
chmod 700 /tmp/sandbox

# Compile Go sandbox-runner if binary is missing.
if [[ ! -x "$ROOT_DIR/bin/sandbox-runner" ]]; then
  echo "[start] Building Go sandbox-runner..."
  (cd "$ROOT_DIR/sandbox_runner" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$ROOT_DIR/bin/sandbox-runner" .)
fi

rand_hex() {
  python3 -c "import secrets; print(secrets.token_hex($1))"
}
sha256_str() {
  python3 -c "import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$1"
}

REDGATE_INTERNAL_TOKEN="$(rand_hex 24)"
export REDGATE_INTERNAL_TOKEN

TOK_ALICE="rg_op_$(rand_hex 16)"
TOK_SARA="rg_lead_$(rand_hex 16)"
TOK_KAVEH="rg_adm_$(rand_hex 16)"

REDGATE_TOKEN_HASH_OP_ALICE="$(sha256_str "$TOK_ALICE")"
REDGATE_TOKEN_HASH_LEAD_SARA="$(sha256_str "$TOK_SARA")"
REDGATE_TOKEN_HASH_ADMIN_KAVEH="$(sha256_str "$TOK_KAVEH")"
export REDGATE_TOKEN_HASH_OP_ALICE REDGATE_TOKEN_HASH_LEAD_SARA REDGATE_TOKEN_HASH_ADMIN_KAVEH

export REDGATE_GATEWAY_PORT="${REDGATE_GATEWAY_PORT:-8000}"
export REDGATE_MCP_PORT="${REDGATE_MCP_PORT:-8001}"
export REDGATE_SANDBOX_PORT="${REDGATE_SANDBOX_PORT:-8002}"

export REDGATE_CONFIG_DIR="$ROOT_DIR/config"
export REDGATE_SKILLS_DIR="$ROOT_DIR/skills"
export REDGATE_DB_PATH="$ROOT_DIR/data/redgate.db"
export REDGATE_SANDBOX_ADDR="127.0.0.1:${REDGATE_SANDBOX_PORT}"
export REDGATE_SANDBOX_URL="http://127.0.0.1:${REDGATE_SANDBOX_PORT}"
export REDGATE_MCP_URL="http://127.0.0.1:${REDGATE_MCP_PORT}"
export REDGATE_LLM_MODE="${REDGATE_LLM_MODE:-mock}"
export REDGATE_STRICT_DNS_RESOLVE="false"
export REDGATE_DEMO_MODE="${REDGATE_DEMO_MODE:-true}"

DEMO_FILE="/tmp/sandbox/.demo_tokens.json"
python3 - "$DEMO_FILE" "$TOK_ALICE" "$TOK_SARA" "$TOK_KAVEH" <<'PY'
import json, os, sys
path, t_alice, t_sara, t_kaveh = sys.argv[1:]
payload = {
    "notice": "Ephemeral local-lab tokens generated at process start (disabled in production).",
    "profiles": [
        {"operator_id": "op-alice", "label": "op-alice · Operator", "role": "operator", "token": t_alice},
        {"operator_id": "lead-sara", "label": "lead-sara · Approver", "role": "approver", "token": t_sara},
        {"operator_id": "admin-kaveh", "label": "admin-kaveh · Admin", "role": "admin", "token": t_kaveh},
    ],
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
os.chmod(path, 0o600)
PY
export REDGATE_DEMO_TOKENS_FILE="$DEMO_FILE"

cleanup() {
  echo "[stop] Terminating background layers..."
  if [[ -n "${SB_PID:-}" ]]; then kill "$SB_PID" 2>/dev/null || true; fi
  if [[ -n "${MCP_PID:-}" ]]; then kill "$MCP_PID" 2>/dev/null || true; fi
  rm -f "$DEMO_FILE"
}
trap cleanup EXIT INT TERM

# Start Layer 3: Go Sandbox Runner (loopback only)
"$ROOT_DIR/bin/sandbox-runner" &
SB_PID=$!

# Start Layer 2: Python MCP Tool Server (loopback only)
python3 -m uvicorn mcp_server.http_server:app --host 127.0.0.1 --port "${REDGATE_MCP_PORT}" --log-level warning &
MCP_PID=$!

sleep 0.6
echo "[ready] RedGate stack starting Gateway + Web Console on 0.0.0.0:${REDGATE_GATEWAY_PORT}"
python3 -m uvicorn gateway.main:app --host 0.0.0.0 --port "${REDGATE_GATEWAY_PORT}" --log-level info
