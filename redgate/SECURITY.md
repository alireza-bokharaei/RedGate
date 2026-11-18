# Security & Responsible Use Policy

## Authorized Security Testing Only

RedGate is a **policy-controlled, auditable security verification and reconnaissance governance platform** engineered strictly for defensive security teams, authorized penetration testers, and internal Red Teams operating under signed written **Rules of Engagement (RoE)**.

- **Mandatory Scope Authorization**: Never add any IP address, CIDR range, domain, or wildcard entry to `config/allowlist.yaml` or `/api/v1/allowlist` without explicit written authorization from the asset owner. Default sample entries use only RFC 2606 / RFC 5737 documentation ranges (`*.lab.example`, `192.0.2.0/24`) and loopback (`127.0.0.1`).
- **Non-Exploitation by Design**: RedGate intentionally excludes exploit payloads, credential stuffing/brute-force automation, lateral movement, persistence, C2, and evasion/stealth mechanisms. High-risk tools (`sqlmap`, `hydra`, `john`, `nmap_aggressive`) are disabled by default and permanently block destructive flags.
- **Zero Hardcoded Secrets**: Operator Bearer tokens are never stored in plaintext (only `SHA-256` hashes compared in constant time via `hmac.compare_digest`), LLM prompts pass through regex secret scrubbing before leaving the host, and `.env` / `secrets/` / `data/` are excluded from version control.
- **Untrusted AI Governance**: Both cloud and local open-weight models (Ollama / LM Studio / Hugging Face GGUF) are treated as untrusted components (`bypass_policy_for_local_models: false`). Every generated script must pass static AST/linter/compiler validation and execute inside the isolated Go Sandbox Runner with kernel resource limits, and medium/high-risk actions enforce Two-Person approval.

## Reporting a Vulnerability

If you discover a security vulnerability in RedGate itself (for example, an allowlist bypass, DNS rebinding edge case, static validator escape, sandbox isolation flaw, or audit hash-chain weakness):

1. **Do not** open a public GitHub issue containing working bypass details.
2. Use GitHub's private **Security Advisories** ("Report a vulnerability" tab in this repository) with minimal reproduction steps, affected component (`gateway/`, `mcp_server/`, or `sandbox_runner/`), and impact assessment.
3. Include only safe, non-destructive proof-of-concept inputs against RFC 2606 / loopback targets.
