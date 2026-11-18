# RedGate Architecture, Data Model & Design Justification

## 1. Multi-Layer Architecture Diagram

```text
+======================================================================================+
|                           OPERATOR / RED TEAM CONSOLE                                |
|    CLI (curl)  |  Web Dashboard (/)  |  Approval Reviewer (lead/admin)               |
+=======================================+==============================================+
                                        | HTTPS + Authorization: Bearer <token>
                                        v
+======================================================================================+
| LAYER 1 — CORE GATEWAY (Python 3.11+ / FastAPI)                   [control_net]      |
|                                                                                      |
|  [1] AuthN/AuthZ    : SHA-256 token lookup (hmac.compare_digest) + RBAC              |
|  [2] Rate Limiter   : Sliding-window RPM per operator_id                             |
|  [3] Scope Engine   : Engagement RoE window + IP/CIDR/Domain/Wildcard allowlist      |
|                       + DNS Resolution Pinning + Cloud Metadata / Rebinding Block    |
|  [4] Policy & Quota : tool_policy + script_policy + atomic call/token quota check    |
|  [5] Approval Gate  : requires_approval -> approval_queue (Two-Person DB CHECK)      |
|                                                                                      |
|  Endpoints:                                                                          |
|    POST /api/v1/scan              POST /api/v1/script/generate                       |
|    POST /api/v1/script/validate   POST /api/v1/script/run                            |
|    GET  /api/v1/approvals         POST /api/v1/approvals/{id}/decide                 |
|    GET  /api/v1/audit             GET  /api/v1/audit/verify                          |
|    GET/POST/PATCH /api/v1/allowlist   GET/PATCH /api/v1/policies                     |
|    POST /api/v1/recon/run         GET  /api/v1/recon/runs/{id}/report.md             |
|    PATCH /api/v1/recon/findings/{id}  GET/POST /api/v1/skills                        |
|    GET/POST/PATCH /api/v1/memory  GET/PUT /api/v1/models/{hub,runtime,recommend}     |
+==========+================================+================================+=========+
           |                                |                                |
           | X-Internal-Service-Token       | Restricted Prompt              | Append-Only
           | (MCP JSON-RPC 2.0)             | + Secret Scrubber              | + SHA-256 Chain
           v                                v                                v
+========================+   +==============================+   +======================+
| LAYER 2 — MCP SERVER   |   | AI PROXY + STATIC VALIDATORS |   | PERSISTENCE (SQLite  |
| (Python / MCP 2024-11) |   |                              |   | WAL -> PostgreSQL)   |
|                        |   | [A] LLM Proxy Gateway        |   |                      |
| - JSON Schema tools    |   |  - Regex secret stripping    |   | - engagements        |
| - Strict param white-  |   |  - Non-exploit guard         |   | - allowlist          |
|   list (nmap -T1/-T2)  |   |  - Token quota metering      |   | - tool_policy        |
| - Banned flags in code |   |  - OpenAI-compat (Ollama /   |   | - script_policy      |
|   (no --os-shell, -T4) |   |    vLLM / Cloud) + Mock      |   | - validated_scripts  |
| - High-risk disabled   |   |              |               |   | - quota              |
|   (hydra/john/sqlmap)  |   |              v (UNTRUSTED)   |   | - approval_queue     |
| - Bounded semaphore    |   | [B] 4-Language Validators    |   | - audit_log          |
| - Subprocess argv only |   |  - Py : ast.parse + AST walk |   |   (NO UPDATE/DELETE  |
| - Hard timeout + 64KB  |   |  - Sh : bash -n + shellcheck |   |    triggers + hash   |
|   output cap           |   |  - Go : gofmt+list+vet+build |   |    chain prev->curr) |
+===========+============+   |  - JS : node --check + eslint|   +======================+
            |                |  - URL/IP scope literal check|
            |                +==============+===============+
            |                               | Validated Script + Expected SHA-256
            |                               | + X-Internal-Service-Token
            |                               v
            |                +=========================================================+
            |                | LAYER 3 — SANDBOX RUNNER (Go Static Binary, CGO=0)      |
            |                |                                                         |
            |                | - SHA-256 payload verification (blocks TOCTOU mutation) |
            |                | - Read-only container FS; ephemeral /tmp/sandbox/job-*  |
            |                | - Scrubbed env (zero host secrets inherited)            |
            |                | - Kernel rlimits (prlimit CPU/FSIZE/NOFILE/AS)          |
            |                | - Setpgid + SIGKILL(-pgid) on context timeout           |
            |                | - Bounded 64KB stdout/stderr buffers                    |
            |                | - Cloud metadata block + default-deny iptables ruleset  |
            |                +===========================+=============================+
            |                                            |
            +--------------------+-----------------------+
                                 | Constrained Egress ONLY to Allowlisted / Pinned IPs
                                 v
                  +------------------------------+
                  | AUTHORIZED ENGAGEMENT TARGET |
                  +------------------------------+
```

---

## 2. Why Go Was Chosen for Layer 3 (Sandbox Runner)

Per Instruction #7, **Go (`sandbox_runner/`)** was selected over Python as the primary sandbox execution service for five concrete security and systems-engineering reasons:

1. **Minimal Attack Surface (`CGO_ENABLED=0` static binary)**: The runner compiles to a single ~5.7 MB dependency-free static binary with zero third-party packages and no dynamic interpreter state inside the control loop.
2. **Safe Concurrent Process Supervision**: Go goroutines, channel semaphores (`chan struct{}`), and `context.WithTimeout` provide deterministic concurrency limits and race-free timeout handling without Python's GIL or `fork()`-in-multithreaded-process hazards.
3. **Native Process-Group Containment (`syscall.SysProcAttr{Setpgid: true}`)**: Every untrusted script spawns inside its own process group. On timeout, `syscall.Kill(-pid, syscall.SIGKILL)` atomically reaps both the script interpreter and any forked child processes.
4. **Bounded Memory Overhead**: Thread-safe `limitedBuffer` writers enforce hard byte caps (64 KB default) on `stdout` and `stderr` in constant memory, preventing output-flood OOM attacks against the runner.
5. **Cryptographic Integrity Gate**: Constant-time token auth (`crypto/subtle.ConstantTimeCompare`) and `crypto/sha256` verification ensure the runner refuses any script that did not pass Layer 1's static validator.

---

## 3. Data Model Summary

| Table | Purpose | Key Integrity / Security Controls |
|---|---|---|
| `engagements` | Signed engagement scope & RoE time window | `valid_from`, `valid_until`, `active` checked on every request |
| `allowlist` | Approved IP, CIDR, exact domain, or `*.domain` per engagement | `FOREIGN KEY(engagement_id)`, `UNIQUE(engagement_id, target)`, metadata IPs blocked |
| `tool_policy` | Tool enablement, max timeout, param whitelist JSON, risk, approval gate | High/critical risk tools disabled by default & locked to `requires_approval=1` |
| `script_policy` | Per-language (`python`, `bash`, `go`, `javascript`) allowed/forbidden imports & regexes | Externalized in `config/script_policy.yaml` |
| `validated_scripts` | Immutable registry of statically approved scripts | Stores canonical `sha256` verified by Go sandbox before execution |
| `quota` | Per-operator call and LLM token accounting by period | Updated atomically inside `BEGIN IMMEDIATE` transactions |
| `approval_queue` | Gated tool/script approval workflow | DB `CHECK (approved_by IS NULL OR approved_by != requested_by)` (Two-Person Rule) |
| `llm_runtime_config` | Live-switchable LLM backend (`ollama`, `lm_studio`, `openai_compatible`, `mock`), GGUF model & quantization | SSRF/metadata URL validation + audited admin updates |
| `agent_skills` | Built-in (`skills/*.yaml`) + operator custom recon playbooks | Validated against `tool_policy`; high-risk tools blocked; `nmap` locked to `recommend_approval` |
| `agent_memory` | Personalized operator brain (`methodology`, `preference`, `false_positive_rule`, `target_note`) | Regex secret scrubbing on write; strict operator + per-engagement scope isolation |
| `recon_runs` | End-to-end bounded recon executions (subdomain/DNS -> MCP + Go sandbox verify -> Markdown report) | Capped steps (`<= 6`), scoped targets only, linked to `approval_queue` |
| `recon_findings` | Prioritized (`0-100`) findings with `ai_confidence`, `requires_human_judgment`, and analyst verdicts | `false_positive` verdict auto-learns a scoped `false_positive_rule` in `agent_memory` |
| `audit_log` | Immutable operational & rejection ledger | `trg_audit_log_no_update` + `trg_audit_log_no_delete` triggers + SHA-256 `prev_hash -> entry_hash` chain |

---

## 4. RedGate v2 Personalized Recon Agent & Claude Code Architecture

1. **Local Model Hub & Quantization Sizer (`gateway/model_hub.py`, `config/local_models.yaml`, `config/Modelfile.redgate`)**:
   - Supports live probing and zero-restart hot-switching across **Ollama** (`:11434`), **LM Studio** (`:1234`), generic **OpenAI-compatible** servers (vLLM / llama.cpp / cloud), and deterministic offline **Mock** mode.
   - Estimates total model memory footprint (`weights + KV-cache + runtime overhead`) across `Q3_K_M`, `Q4_K_M`, `Q5_K_M`, `Q6_K`, `Q8_0`, and `FP16`, outputting ready-to-run `ollama pull hf.co/<org>/<repo>:<quant>` and `lms get` commands plus a domain-tuned `Modelfile` that avoids false refusals on legitimate security terms while preserving every deterministic RedGate policy gate (`bypass_policy_for_local_models: false`).
2. **Skills + Persistent Memory Brain (`gateway/skills.py`, `gateway/memory.py`, `gateway/agent.py`)**:
   - **Skills** define structured multi-stage pipelines (`dns_lookup`, `tcp_port_probe`, `http_headers`, `tls_inspect`, dual-verification in Go Sandbox, and approval-gated `nmap -T2`).
   - **Memory** personalizes priority scoring, LLM triage synthesis, and noise reduction. Analyst verdicts on `recon_findings` feed back into `agent_memory` without leaking across engagements or operators.
3. **Claude Code Integration (`CLAUDE.md`, `.mcp.json`, `.claude/commands/`)**:
   - Connects Claude Code directly to `mcp_server/stdio_server.py` (including `list_recon_skills`) and provides guided terminal workflows (`/project:new-skill`, `/project:new-mcp-tool`, `/project:triage-report`) bound by RedGate's non-exploitation and validation invariants.
