# CLAUDE.md — Redstrike v2 Project Instructions for Claude Code

This repository implements **Redstrike v2**, an internal, policy-controlled, auditable security testing and personalized reconnaissance platform powered by local LLMs (Ollama / LM Studio / Hugging Face GGUF), composable **Skills**, persistent operator **Memory**, **MCP tools**, 4-language static validation (**Python, Bash, Go, JavaScript**), and an isolated **Go Sandbox Runner**.

## Non-Negotiable Safety & Architecture Rules

1. **Scope First**: Never add code or tools that contact targets outside `allowlist` or bypass `gateway/policy.py` (engagement RoE window + DNS rebinding + cloud metadata block).
2. **No Exploit or Evasion Logic**: Only build read-only reconnaissance, configuration verification, triage, prioritization, and reporting capabilities. High-risk tools remain disabled by default and bound by Two-Person approval (`approval_queue`).
3. **Zero Hardcoded Secrets/Targets**: Externalize all settings in `config/*.yaml` and `skills/*.yaml`; load secrets strictly via environment variables or `secrets/llm_api_key`.
4. **Untrusted AI Code**: Every generated script must pass `gateway/validators/` AND SHA-256 verification in `sandbox_runner/runner.go` inside `/tmp/sandbox`.
5. **Immutable Audit Trail**: Every new tool, skill run, policy toggle, or analyst verdict must write to `db.write_audit_log(...)` (protected by SQLite abort triggers + SHA-256 hash chain).

## Key Extension Points (Tool & Skill Authoring)

- **Add a new Recon Skill**: Create `skills/<skill-id>.yaml`, validate via `gateway.skills.validate_skill_spec`, and add a test in `tests/test_agent_v2.py`. (Or run `/project:new-skill`.)
- **Add a new MCP Tool**:
  1. Register JSON Schema + parameter whitelist in `mcp_server/tools.py`.
  2. Implement bounded, timeout-isolated handler in `mcp_server/executor.py` (`shell=False` argv only).
  3. Add default policy entry in `config/tool_policy.yaml`.
  4. Add positive + negative parameter tests in `tests/test_policy_and_audit.py`. (Or run `/project:new-mcp-tool`.)
- **Tune Local Model & Quantization**: Edit `config/local_models.yaml` or `config/Modelfile.redgate`, or run `./scripts/setup_local_llm.sh`.

## Verification Commands (Always Run Before Committing)

```bash
shellcheck scripts/*.sh
(cd sandbox_runner && go test -v ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/sandbox-runner .)
PYTHONPATH=. pytest -v tests/
```
