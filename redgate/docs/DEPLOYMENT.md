# RedGate Deployment & Operations Guide

## 1. Isolated Production Deployment (Docker Compose)

RedGate separates internal service communication (`control_net`, marked `internal: true` with no external routing) from controlled assessment egress (`target_egress_net`) and LLM gateway traffic (`llm_egress_net`).

### Step 1: Generate Operator & Service Secrets (Zero Hardcoded Credentials)

```bash
cd redgate
cp .env.example .env
mkdir -p secrets && chmod 700 secrets

# 1. Generate internal service-to-service token (Gateway <-> MCP <-> Go Sandbox)
INTERNAL_TOK=$(openssl rand -hex 32)

# 2. Generate distinct Bearer tokens per operator (distribute securely out-of-band;
#    store ONLY SHA-256 hashes on the server!)
TOK_ALICE="rg_op_$(openssl rand -hex 24)"
TOK_SARA="rg_lead_$(openssl rand -hex 24)"
TOK_KAVEH="rg_adm_$(openssl rand -hex 24)"

HASH_ALICE=$(printf '%s' "$TOK_ALICE" | sha256sum | awk '{print $1}')
HASH_SARA=$(printf '%s' "$TOK_SARA"  | sha256sum | awk '{print $1}')
HASH_KAVEH=$(printf '%s' "$TOK_KAVEH" | sha256sum | awk '{print $1}')

# Populate REDGATE_INTERNAL_TOKEN and REDGATE_TOKEN_HASH_* in .env
# Initialize LLM secret file (can be a placeholder when using local Ollama or mock mode)
printf '%s' "initial-placeholder-key" > secrets/llm_api_key
chmod 600 secrets/llm_api_key
```

### Step 2: Launch Hardened Stack

```bash
docker compose up -d --build
docker compose ps
curl -s http://127.0.0.1:8000/api/v1/health | jq .
```

### Step 3: Enforce Host-Level Egress Firewall on `target_egress_net`

Never connect `sandbox-runner` to `network_mode: host`. Apply host `nftables`/`iptables` rules to the `target_egress_net` bridge allowing traffic **only** to signed engagement CIDRs and rejecting RFC 1918/metadata destinations not in scope:

```bash
# Example: restrict sandbox bridge to signed engagement subnet 192.0.2.0/24
sudo iptables -I DOCKER-USER -i br-target-egress -d 169.254.169.254/32 -j REJECT
sudo iptables -I DOCKER-USER -i br-target-egress ! -d 192.0.2.0/24 -j REJECT
```

---

## 2. Configuring Engagement Allowlists

1. **Declarative (Recommended / GitOps)**: Edit `config/allowlist.yaml` before an engagement:
   - Assign a unique engagement `id` (e.g., `ENG-2026-014`).
   - Set exact UTC `valid_from` and `valid_until` matching your signed Rules of Engagement.
   - Add authorized IPs, CIDRs (`/16` to `/32`), exact domains, or `*.subdomain.tld` entries.
   - Restart `gateway` to synchronize into SQLite.
2. **Runtime API (Approver / Admin only — fully audit-logged)**:
   ```bash
   # Add target
   curl -X POST http://127.0.0.1:8000/api/v1/allowlist \
     -H "Authorization: Bearer $TOK_SARA" \
     -H "Content-Type: application/json" \
     -d '{"engagement_id":"ENG-2026-001","target":"192.0.2.50","description":"Signed RoE addendum #2"}'

   # Immediately revoke target mid-engagement
   curl -X PATCH http://127.0.0.1:8000/api/v1/allowlist/5 \
     -H "Authorization: Bearer $TOK_SARA" \
     -H "Content-Type: application/json" \
     -d '{"active": false}'
   ```

---

## 3. Enabling / Disabling Tools & Two-Person Approval

- Edit `config/tool_policy.yaml` for persistent baseline policy, or toggle dynamically as `admin`:
  ```bash
  # Disable nmap immediately
  curl -X PATCH http://127.0.0.1:8000/api/v1/policies/tools/nmap \
    -H "Authorization: Bearer $TOK_KAVEH" \
    -H "Content-Type: application/json" \
    -d '{"enabled": false}'
  ```
- **Safety invariant**: Tools classified as `high` or `critical` (`hydra`, `john`, `sqlmap`, `nmap_aggressive`) are disabled by default and **cannot** have `requires_approval` disabled even by an administrator. Destructive flags (`sqlmap --os-shell`, `nmap -T5`, `--script`) remain permanently blocked in `mcp_server/tools.py`.
- **Approving a queued scan (Two-Person Rule)**:
  ```bash
  # Must be called by an approver/admin DIFFERENT from requested_by
  curl -X POST http://127.0.0.1:8000/api/v1/approvals/apr-xxxxxxxxxxxx/decide \
    -H "Authorization: Bearer $TOK_SARA" \
    -H "Content-Type: application/json" \
    -d '{"decision":"approved","note":"Confirmed with SOC ticket #4412","execute_immediately":true}'
  ```

---

## 4. Configuring Local AI (Ollama / LM Studio / Hugging Face GGUF) & API Key Rotation

### Option A: 100% Private Local Models via Ollama or LM Studio ($0 API Cost)

```bash
# Containerized Ollama alongside RedGate:
docker compose --profile ollama up -d --build

# Or pull a quantized Hugging Face GGUF model & create the custom redgate-analyst Modelfile:
./scripts/setup_local_llm.sh ollama Qwen/Qwen2.5-Coder-14B-Instruct-GGUF Q4_K_M

# Or via LM Studio CLI:
./scripts/setup_local_llm.sh lm_studio Qwen/Qwen2.5-Coder-7B-Instruct-GGUF Q5_K_M
```

Switch runtimes live without restarting containers (Admin Web Console tab **Local AI & Quantization Hub** or REST API):

```bash
curl -X PUT http://127.0.0.1:8000/api/v1/models/runtime \
  -H "Authorization: Bearer $TOK_KAVEH" \
  -H "Content-Type: application/json" \
  -d '{"provider":"ollama","base_url":"http://ollama:11434/v1","model":"redgate-analyst:latest","quantization":"Q4_K_M","context_length":8192}'
```

Use `POST /api/v1/models/recommend` (or the Web Console VRAM/RAM calculator) to pick the optimal GGUF quantization (`Q3_K_M`..`Q8_0`/`FP16`) for your hardware. All local/custom open-weight models remain strictly governed by allowlists, static validators, Two-Person approvals, and the Go Sandbox (`bypass_policy_for_local_models: false`).

### Option B: Cloud / Internal OpenAI-Compatible Proxy (vLLM / LiteLLM)

Set in `.env`:
```ini
REDGATE_LLM_MODE=openai_compatible
REDGATE_LLM_BASE_URL=http://ollama.internal:11434/v1
REDGATE_LLM_MODEL=qwen2.5-coder:14b
```

### Option C: Claude Code Terminal Integration

Open the repository root in Claude Code — `.mcp.json` automatically registers RedGate's stdio MCP server (`mcp_server/stdio_server.py`), `CLAUDE.md` loads architectural/security guardrails, and `.claude/commands/` provides `/project:new-skill`, `/project:new-mcp-tool`, and `/project:triage-report`.

### Rotating LLM API Keys (Zero Downtime)

`gateway/llm_proxy.py` reads `REDGATE_LLM_API_KEY_FILE` (`/run/secrets/llm_api_key`) dynamically on every request. Rotate without restarting containers:

```bash
./scripts/rotate_llm_key.sh
# Prompts silently for new key, writes 0600 temp file, atomically renames into secrets/llm_api_key,
# and logs only the truncated SHA-256 fingerprint transition.
```

To revoke downstream keys, immediately invalidate the previous API key in your LLM gateway provider console after running `rotate_llm_key.sh`.

---

## 5. Verifying Immutable Audit Log Integrity & PostgreSQL Upgrade

```bash
curl -s http://127.0.0.1:8000/api/v1/audit/verify \
  -H "Authorization: Bearer $TOK_KAVEH" | jq .
```

When upgrading to PostgreSQL (`docker compose --profile postgres up -d`), enforce database-level append-only grants in addition to hash chaining:

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_log FROM redgate_app;
GRANT SELECT, INSERT ON TABLE audit_log TO redgate_app;
```
