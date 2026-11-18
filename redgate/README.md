# RedGate v2 — Auditable Local-AI Security Testing & Recon Platform

RedGate v2 combines a **policy-controlled, 3-layer security verification platform** (FastAPI Governance Gateway + Python MCP Tool Server + isolated Go Sandbox Runner) with a **100% private, offline-capable, personalized Local-AI Recon & Triage Agent**.

> **Authorized Use Only**: RedGate is built exclusively for defensive posture verification and authorized assessments under signed written Rules of Engagement (RoE). It contains zero exploit payloads, credential-attack automation, or evasion logic. See [`SECURITY.md`](SECURITY.md) and [`LIMITATIONS.md`](LIMITATIONS.md).

---

## Core Capabilities

- **Private Local AI & Quantization Hub** (`gateway/model_hub.py`, `config/local_models.yaml`, `config/Modelfile.redgate`)
  Run quantized **GGUF** open-weight models from **Hugging Face** locally via **Ollama** (`:11434`), **LM Studio** (`:1234`), or any OpenAI-compatible runtime (**vLLM**, **llama.cpp**) — offline, private, and with `$0` API cost. Includes a hardware-aware VRAM/RAM quantization sizer (`Q3_K_M`..`Q8_0`/`FP16`), ready-to-run `ollama pull hf.co/...` & `lms get` commands, and a custom analyst `Modelfile` that prevents false-positive refusals on benign security terms while keeping all deterministic policy gates enforced (`bypass_policy_for_local_models: false`).
- **Personalized Agent Brain — Skills & Persistent Memory** (`gateway/skills.py`, `skills/*.yaml`, `gateway/memory.py`)
  Reusable YAML/API hunting playbooks (**Skills**) and secret-scrubbed, engagement-isolated **Memory** (`methodology`, `preference`, `false_positive_rule`, `target_note`). Marking a finding as a false positive automatically teaches the agent to suppress recurring noise on future runs.
- **Automated Subdomain-to-Report Recon & Dual-Verification** (`gateway/agent.py`)
  Progresses from allowlist-validated subdomains and DNS lookups through paced TCP probing, HTTP security headers, TLS inspection, and **Dual-Verification** (independent Go verification script compiled and executed in Layer 3 Go Sandbox to boost finding confidence and eliminate single-tool anomalies), pausing medium-risk tools (`nmap -T2`) in the **Two-Person Approval Queue** and exporting full **Markdown reports**.
- **Explicit Human-Judgment Gates** (`LIMITATIONS.md`, `PATCH /api/v1/recon/findings/{id}`)
  Every finding reports `ai_confidence`, `dual_verified`, and `requires_human_judgment` where analyst context (business logic, BOLA/IDOR, upstream WAF/CDN controls) cannot be replaced by AI.
- **Native Claude Code Integration** (`CLAUDE.md`, `.mcp.json`, `.claude/commands/`)
  Connects Claude Code directly to RedGate's allowlist-enforcing stdio MCP server (`mcp_server/stdio_server.py`) with built-in slash commands (`/project:new-skill`, `/project:new-mcp-tool`, `/project:triage-report`).
- **Hard Security & Audit Invariants**
  SHA-256 hashed Bearer tokens + RBAC (`operator` / `approver` / `admin`), per-engagement allowlists + DNS rebinding & cloud-metadata blocking, 4-language static code validation (**Python AST**, **Bash + ShellCheck**, **`gofmt` + `go vet` + `go build`**, **Node + ESLint**), `CGO_ENABLED=0` **Go Sandbox Runner** (`prlimit`, process-group reaping, scrubbed env, `/tmp/sandbox`), and an append-only **SHA-256 hash-chained `audit_log`**.

---

## Repository Structure

```text
redgate/
├── gateway/            # Layer 1: FastAPI Governance Gateway, Local AI Hub, Skills, Memory, Recon Agent,
│   ├── validators/     #          4-language static validators (Python, Bash, Go, JS)
│   └── static/         #          9-tab Web Management Console (zero external CDN deps)
├── mcp_server/         # Layer 2: Python MCP Server (HTTP JSON-RPC + Claude Code stdio, strict param allowlists)
├── sandbox_runner/     # Layer 3: Isolated Go Sandbox Runner (CGO_ENABLED=0, SHA-256 check, prlimit, egress rules)
├── config/             # Externalized YAML policies, Hugging Face GGUF catalog & Ollama Modelfile.redgate
├── skills/             # Built-in declarative recon & dual-verification playbooks
├── scripts/            # Secret bootstrap, local launcher, Ollama/LM Studio GGUF setup & zero-downtime key rotation
├── .claude/commands/   # Claude Code slash commands (/project:new-skill, new-mcp-tool, triage-report)
├── docs/               # Architecture, Deployment & Persian prompt review documentation
└── tests/              # End-to-end tests: policies, audit hash chain, 4 validators, Go sandbox & v2 agent
```

---

## Quickstart

### 1. Docker Compose Deployment (Recommended)

```bash
./scripts/bootstrap_env.sh                 # Generates random operator tokens + .env (chmod 0600)
docker compose up -d --build               # Add `--profile ollama` to run containerized Ollama
```

Optional — pull a quantized Hugging Face GGUF model and build the local `redgate-analyst` profile:

```bash
./scripts/setup_local_llm.sh ollama Qwen/Qwen2.5-Coder-14B-Instruct-GGUF Q4_K_M
# Or with LM Studio CLI:
./scripts/setup_local_llm.sh lm_studio Qwen/Qwen2.5-Coder-7B-Instruct-GGUF Q5_K_M
```

Open `http://127.0.0.1:8000` (Web Console) or `http://127.0.0.1:8000/docs` (OpenAPI reference).

### 2. Direct Local Run (Linux VM)

```bash
./scripts/start_local.sh
```

### 3. Using with Claude Code

Open the repository directory in Claude Code; `.mcp.json` automatically connects to `mcp_server.stdio_server` and `CLAUDE.md` enforces project guardrails. Run `/project:new-skill`, `/project:new-mcp-tool`, or `/project:triage-report` directly from the terminal.

### 4. Running Tests & Linters

```bash
shellcheck scripts/*.sh
node --check gateway/static/app.js
(cd sandbox_runner && go test -v ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/sandbox-runner .)
PYTHONPATH=. pytest -v tests/
```

---

## Key API Endpoints

| Area | Endpoints |
|---|---|
| **Auto Recon Agent** | `POST /api/v1/recon/run`, `GET /api/v1/recon/runs`, `GET /api/v1/recon/runs/{id}/report.md`, `PATCH /api/v1/recon/findings/{id}` |
| **Skills & Memory Brain** | `GET/POST /api/v1/skills`, `GET/POST /api/v1/memory`, `PATCH /api/v1/memory/{id}` |
| **Local AI & Quantization** | `GET /api/v1/models/hub`, `PUT /api/v1/models/runtime`, `POST /api/v1/models/recommend` |
| **MCP Scans & Sandbox** | `POST /api/v1/scan`, `POST /api/v1/script/generate`, `POST /api/v1/script/validate`, `POST /api/v1/script/run` |
| **Governance & Audit** | `GET/POST/PATCH /api/v1/allowlist`, `GET/PATCH /api/v1/policies/*`, `POST /api/v1/approvals/{id}/decide`, `GET /api/v1/audit/verify` |

---

## Documentation & License

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — 3-layer + v2 agent architecture, Go sandbox rationale, and SQLite/PostgreSQL schema
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — Hardened Docker networking, Local AI setup, allowlist ops, and zero-downtime key rotation
- [`LIMITATIONS.md`](LIMITATIONS.md) — Explicit technical boundaries, quantization trade-offs, and human-judgment requirements
- [`SECURITY.md`](SECURITY.md) — Authorized testing & vulnerability disclosure policy
- [`LICENSE`](LICENSE) — MIT License (with authorized security testing notice)
