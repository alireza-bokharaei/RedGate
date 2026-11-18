# RedGate 2.1.0 — Governed Mission Workspace

[فارسی / English — README دوزبانه](../README.md) · [Verification record](docs/VERIFICATION_2.1.0.md)

**Authorized, read-only security assessment orchestration with local-AI support.**

نسخهٔ **۲٫۱٫۰** مدیریت مأموریت، گراف دارایی و بررسی، شواهد HTTP و بازآزمایی محدود یافته‌ها را به RedGate اضافه می‌کند. **Bash، Go، JavaScript و Docker** در پروژه استفاده شده‌اند. این نسخه پیاده‌سازی مستقلِ قابلیت‌های منتخبِ الهام‌گرفته از ARTEX است؛ ادغام کامل کد ARTEX نیست. [جزئیات فارسی و محدودهٔ تغییرات](docs/RELEASE_2.1.0_FA.md).

> Use only with written authorization and an active Rules of Engagement (RoE) window. Reading a dashboard never starts a scan. Local models and generated scripts are untrusted. See [Security](SECURITY.md) and [Limitations](LIMITATIONS.md).

## What's new in 2.1

- **Durable missions:** save a scope-checked plan, explicitly start/pause/resume/cancel, keep completed work after restart, and export Markdown/JSON. Owner identity, per-operator quota, absolute deadline and action reservations remain attached to the mission—even when an assigned admin controls it.
- **Two graphs:** an engagement asset inventory and a mission exploration trail linking goals → intents → checks → findings/evidence/retests. Discovery is not tested coverage; a finding is not proof of exploitability.
- **HTTP evidence:** a native Go collector performs anonymous, DNS-pinned HEAD/GET requests. HEAD/no response body is the default. No credentials, arbitrary headers, query strings, redirects, MITM proxy or cookie replay. Optional text previews are capped at 8 KiB and heuristically redacted.
- **Conservative finding retests:** repeat a supported missing-security-header check against its original endpoint. Append `still_present`, `not_observed` or `inconclusive` history; never overwrite the analyst verdict or original evidence.
- **Local JavaScript console:** keyboard-operable SVG graphs, safe text rendering, same-origin requests, responsive workspace and stale-response guards. No frontend build server or external CDN is needed at runtime.
- **Container/operations work:** multi-stage `full`/`lite` images, a separate evidence-only runner target, non-root/read-only service containers, locked dependencies, private bootstrap/rotation, consistent SQLite backups, and one polyglot verification command. **Container size/speed improvements have not been measured.**

Existing skills, engagement-scoped memory, local-model/quantization hub, bounded recon, four-language validators, two-person approval and hash-chained audit records are retained.

## Architecture and languages

```text
Browser (vanilla JavaScript + SVG)
              │ same-origin Bearer-authenticated API
FastAPI Gateway ─── SQLite WAL + additive migrations + append-only ledgers
  policy/RoE/RBAC/quotas │ mission coordinator │ local-LLM proxy/validators
              ├── internal-token MCP tool service (Python)
              └── internal-token Go runner: fixed HTTP collector / script adapters
Bash: lifecycle, credentials, model setup, backups and verification
Docker Compose: separate control / target-egress / inference networks
```

The native collector pins its actual network dial and verifies TLS against the logical hostname. **Arbitrary scripts do not acquire an OS/network sandbox merely by running under Go.** Production needs a separately enforced, default-deny egress policy and an appropriate hostile-code isolation boundary. Rendered firewall rules are not installed by RedGate.

## Quickstart — Docker Compose

From the repository root:

```bash
cd redgate
./scripts/bootstrap_env.sh       # Prints PRIVATE operator tokens once; stores hashes
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full   # Docker Engine + Compose v2.20+ + BuildKit
```

Open **http://127.0.0.1:8000**, press **Token**, and enter your private operator token. API documentation is at `/docs`. Compose disables demo login, publishes only the gateway on loopback, and retains data in the `redgate_data` volume. Do not publish the service without TLS and network access control. Review the sample scopes before any live assessment.

```bash
./scripts/redgate.sh up --lite   # Python/Bash adapters; NO Go/JS validation/execution
./scripts/redgate.sh status
./scripts/redgate.sh backup     # WAL-consistent gzip snapshot, mode 0600
./scripts/redgate.sh down       # Stops stack, KEEPS volumes
```

`full` is the default and keeps all four language toolchains. `lite` still supports missions, MCP checks, graphs, evidence and retests; skills needing Go/JS adapters cannot complete those steps. `/api/v1/health` reports installed validator tools and runner languages. [GitHub CI](https://github.com/alireza-bokharaei/RedGate/actions/runs/44288999257) passed build/startup/readiness/capability checks for both flavors and built the evidence-only target. Intended-host adapter, containment and resource checks remain deployment responsibilities; see [verification status](docs/VERIFICATION_2.1.0.md).

### Local inference (optional)

The default is deterministic **mock** mode: no model download or external AI call.

```bash
# Configure the container-reachable Ollama URL; does NOT download model files:
./scripts/setup_local_llm.sh --compose ollama
# Explicitly start bundled Ollama and fetch/build a model (potentially many GB):
./scripts/setup_local_llm.sh --compose --pull ollama Qwen/Qwen2.5-Coder-14B-Instruct-GGUF Q4_K_M
# Host-run gateway instead of Compose:
./scripts/setup_local_llm.sh --local lm_studio Qwen/Qwen2.5-Coder-7B-Instruct-GGUF Q5_K_M
```

The helper writes `.env` for **initial** database setup. Existing saved runtime settings take precedence: update them through the admin **Local AI → Runtime** panel/API. A host-only `127.0.0.1` inference URL is not reachable from the gateway container. Model downloads, model licensing, runtime networking and hardware sizing remain operator responsibilities. Offline inference requires previously downloaded weights and a genuinely local endpoint.

## Local development and checks

Linux, Python 3.11+, Go 1.22+ (verified with 1.26.6), Node 22.13+ and ShellCheck are required for the complete checks. Use a dedicated VM; direct local execution is **not host isolation**.

```bash
# From repository root:
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r redgate/requirements-dev.txt
cd redgate
npm ci --ignore-scripts
./scripts/verify.sh              # Bash + JS + Go race/vet/build + Python suite
./scripts/start_local.sh         # Loopback-only, mock AI, temporary private tokens
```

The launcher prints the path of a private token manifest; it does not automatically source `.env`. For an **explicit private lab only**, `REDGATE_DEMO_MODE=true ./scripts/start_local.sh` exposes temporary lab identities to anyone who can reach that gateway. Never use demo mode for a deployment or a real engagement. See [browser smoke testing](docs/VERIFICATION_2.1.0.md) for a reproducible local end-to-end UI check.

## Workspace API

Every endpoint below requires a Bearer token assigned to the engagement. Mission controls additionally require its owner or an assigned admin. Full request/response schemas are available in `/docs`.

| Area | Routes under `/api/v1` |
|---|---|
| Workspace | `GET /workspace?engagement_id=…` |
| Missions | `POST/GET /missions`, `GET /missions/{id}`, `POST /missions/{id}/control` |
| Mission outputs | `GET /missions/{id}/graph`, `/report.md`, `/export.json` |
| Inventory | `GET /assets`, `GET /assets/graph` (engagement query required) |
| Evidence | `POST /evidence/capture`, `GET /evidence`, `GET /evidence/{id}`, `/export.json` |
| Retests | `POST /recon/findings/{id}/retest`, `GET /recon/findings/{id}/retests`, `/evidence` |
| Existing recon | `POST /recon/run`, `GET /recon/runs`, `PATCH /recon/findings/{id}` |
| Existing governance | `/skills`, `/memory`, `/models/*`, `/scan`, `/script/*`, `/approvals`, `/allowlist`, `/policies/*`, `/audit/verify` |

Missions accept **1–8 hosts**, **1–64 actions** (default 24), and **10–1800 seconds** (default 300). At most **two missions globally / one per owner** may execute. The deadline starts on first start and keeps running while paused. Failed/reserved actions are not refunded. After a crash, resume is explicit and an interrupted, uncheckpointed action may be attempted again; this is not exactly-once delivery.

## Documentation and license

- [Deployment, backup, upgrade and rollback](docs/DEPLOYMENT.md)
- [Architecture and data integrity](docs/ARCHITECTURE.md)
- [ARTEX capability mapping and licensing boundary](docs/ARTEX_SCOPE.md)
- [2.1.0 Persian release notes](docs/RELEASE_2.1.0_FA.md)
- [Tests performed and unverified deployment work](docs/VERIFICATION_2.1.0.md)
- [Security](SECURITY.md) · [Limitations](LIMITATIONS.md) · [MIT license](LICENSE)

No ARTEX source, assets or dependencies have been imported. This is not a claim of full ARTEX compatibility or of adopting its AGPL-licensed implementation. Third-party dependencies and any future imported code retain their own license obligations.
