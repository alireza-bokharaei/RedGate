# LIMITATIONS & OPERATIONAL BOUNDARIES

RedGate is a **policy-controlled orchestration, static-validation, sandboxing, and audit platform** for authorized internal security testing teams. Every operator, team lead, and engagement sponsor MUST understand and accept the following limitations before operating the platform.

---

## 1. No Guarantee of Alarm-Free or Stealth Operation

- **RedGate does NOT suppress, evade, or bypass SIEM, IDS/IPS, WAF, EDR, or network telemetry.**
- Constraining parameters (for example, limiting `nmap` to `-T1`/`-T2` and restricting `tcp_port_probe` to 10 ports with inter-probe pacing) **reduces scan noise and outage risk**, not detectability.
- Even a single `HEAD /` request, TLS handshake, DNS query, or `-sV` service probe generates normal application logs, firewall flow records, and potentially SOC alerts.
- Evasion flags (`nmap -D`, `-S`, `-f`, `--spoof-mac`, `--data-string`, etc.) are **permanently blocked** in code. Blue-team / SOC deconfliction remains a mandatory human process prior to every engagement.

## 2. No Exploit Authoring or Weaponized Payloads

- **The platform itself contains zero exploit logic, credential-stuffing modules, payload encoders, C2 channels, or post-exploitation capabilities.**
- The LLM proxy explicitly rejects objectives requesting exploits, reverse/bind shells, brute-force routines, denial-of-service loops, privilege escalation, data exfiltration, or defense evasion.
- High-risk external tools (`hydra`, `john`, `sqlmap`, `nmap_aggressive`) are **disabled by default** in `config/tool_policy.yaml`, require **Two-Person Approval** even if temporarily enabled by an administrator, and permanently prohibit OS-execution or file-access flags (e.g., `sqlmap --os-shell`, `--os-pwn`, `--file-write`, `--file-read`) at the source-code level.

## 3. AI-Generated Scripts Are Untrusted by Default

- Output from any LLM (local or cloud) may be buggy, hallucinated, noisy, vulnerable to indirect prompt injection, or subtly non-compliant with engagement intent.
- RedGate treats every AI-generated and operator-submitted script as **untrusted code**:
  1. Prompts pass through regex secret scrubbing and a locked system template.
  2. Returned source code must pass language-specific static validation (`ast.parse` + AST walker, `bash -n` + `shellcheck`, `gofmt` + `go list` + `go vet` + `go build`, `node --check` + `eslint` + module allowlist) plus literal host allowlist checks.
  3. Validated scripts are pinned by **SHA-256 digest** before execution; any byte mismatch is rejected by the Go sandbox runner.
  4. Scripts execute inside an ephemeral `/tmp/sandbox/job-*` workspace with scrubbed environment variables, process-group timeouts, kernel resource limits (`prlimit`), container read-only root filesystem, and dropped Linux capabilities.

## 4. Static Analysis Is Defense-in-Depth, Not a Sound Proof

- By Rice's theorem, static analysis cannot decide all dynamic runtime behaviors of arbitrary code (e.g., constructing URLs via string concatenation at runtime).
- Therefore, **Layer 3 sandbox isolation and container/host egress firewalling are the primary security boundary**, while static analysis acts as an early filter.
- Production deployments MUST enforce host- or namespace-level default-deny egress firewall rules (using `target_egress_net` + `nftables`/`iptables` rules rendered by `sandbox_runner/egress.go`) in addition to application-level allowlist checks.

## 5. Secret Scrubbing Is Pattern-Based

- `gateway/llm_proxy.py` strips common credentials (PEM keys, Bearer tokens, JWTs, `sk-*`, AWS keys, GitHub tokens, and `password=/api_key=/token=` assignments) before calling an upstream LLM.
- Custom or unformatted secrets (e.g., an internal passphrase embedded inside prose) may evade regex scrubbing. Operators MUST never paste credentials, session cookies, or customer PII into script objectives, and air-gapped Red Team deployments SHOULD pair RedGate with a self-hosted LLM (`Ollama` / `vLLM`) inside the internal enclave.

## 6. Local Open-Weight Models, Quantization & Where Human Judgment Is Irreplaceable

- **Custom / Open-Weight Local Models**: RedGate v2 allows running quantized GGUF models from Hugging Face locally via **Ollama** or **LM Studio** (100% offline, private, and free of API charges), including domain-tuned `Modelfile` profiles that avoid false refusals on legitimate security terminology. **However, no local model is ever trusted**: RedGate's deterministic allowlists, non-exploitation policy guards, static validators, Two-Person approval queue, and Go sandbox apply identically to every model (`bypass_policy_for_local_models: false`).
- **Quantization Trade-Offs**: Lower bit-widths (`Q3_K_M`, `Q4_K_M`) enable 7B–32B models on ordinary hardware, but slightly increase subtle syntax or reasoning slips compared to `Q6_K`/`Q8_0`/`FP16`. RedGate mitigates this through compiler/linter validation and optional MCP + Go Sandbox dual-verification (`skills/polyglot_sandbox_verify.yaml`).
- **Irreplaceable Human Judgment**: Automated recon and AI triage can inspect observable surface posture (subdomains, DNS, open ports, HTTP headers, TLS hygiene), **never** business-logic flaws, object-level authorization (IDOR/BOLA), multi-step authentication workflows, asset criticality, or upstream CDN/WAF compensating controls. Every finding tagged `requires_human_judgment: true` MUST be manually verified by a qualified operator before inclusion in an engagement deliverable.
- **Bounded Agent Loop**: Unlike unconstrained autonomous agents, RedGate's `PersonalizedReconAgent` is strictly capped (`max_steps <= 6`), executes only low-risk read-only tools plus validated sandbox checks, and halts at `approval_queue` for any medium/high-risk action.
- **Legal Authorization**: Technical allowlists do not replace signed written Rules of Engagement (RoE). Administrators are solely responsible for ensuring every entry in `config/allowlist.yaml` and the `allowlist` table has active legal authorization.
