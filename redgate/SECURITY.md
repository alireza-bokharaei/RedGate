# Security and Responsible Use — Redstrike 2.1

## Authorized use only

Use Redstrike only against assets covered by signed written Rules of Engagement (RoE). Technical allowlisting is not legal authorization. Default entries are examples/documentation ranges plus an explicit loopback lab; they are not authorization to assess someone else's infrastructure.

The 2.1 mission path is bounded, read-only posture assessment. It does not import ARTEX exploitation, credential theft, evasion, persistence or lateral-movement workflows. Existing high/critical-risk external-tool entries remain disabled by default; gated work still requires a different authorized approver. Do not enable tools merely because a model recommends them.

## Trust boundaries

- **Gateway:** Bearer-token hashes, constant-time comparison, engagement RBAC, RoE checks, DNS/metadata policy, operator quotas, action reservations and audited controls. Never expose internal MCP or runner ports to operators or the internet.
- **Missions:** saving/viewing a plan performs no target I/O. Explicit start/resume is required. Controls are restricted to the owner or an admin assigned to that engagement; execution and quota stay attributed to the original enabled identity. Restart never silently resumes work. Pause drains the current intent; cancel prevents subsequent actions but cannot retract a request already sent.
- **Native HTTP evidence:** internal authentication; fresh gateway DNS pin; pinned dial with logical Host/TLS SNI; certificate verification and TLS 1.2+; no redirects or environment proxies; only anonymous HEAD/GET and origin-relative paths without query strings. No caller-supplied cookies/headers. Default no body; explicit text/JSON previews are bounded and heuristically redacted.
- **Evidence/retests:** append-only database triggers and a checksum over the canonical **stored, redacted** snapshot, anchored in the audit chain. They are not signed packets, a TLS transcript or proof of an uncompromised collector. A database administrator can drop triggers or rewrite an entire unanchored chain. Export audit anchors to trusted external storage if stronger tamper evidence is needed.
- **Scripts/AI:** static validation and SHA-256 checks are defense in depth, not proof of safe dynamic behavior. The runner is a process/resource supervisor, not a VM or a per-job OS namespace. It does not install a firewall. Compose drops capabilities and sets read-only roots but shares a kernel. Deploy a separately verified hostile-code isolation and default-deny egress boundary before accepting untrusted adapters. In-process iptables enforcement is unsupported and explicitly fails closed if requested.

## Deployment checklist

1. Use Docker Engine/Compose with TLS/access control in front of the gateway. Bind loopback unless you explicitly intend remote access. Keep demo login **disabled**; Compose hard-codes this off.
2. Run one gateway process/replica per SQLite database. Mission coordination is not a distributed queue.
3. Enforce external IPv4 **and** IPv6 default-deny egress for both MCP and runner. A network named `target_egress_net` is not a firewall. Restrict access to the control/inference services as well as targets.
4. Protect `.env` (0600), `secrets/` (0750) and key files (0640 with a restricted supplementary group, or 0600 for local use). Bootstrap prints operator tokens once; keep them out of logs/chat/source control. Do not mount the Docker socket or host home directories into services.
5. Mount the **secret directory**, not just a key-file inode, so atomic rotation is visible. LLM secrets are read per request. The configured key file takes precedence when it exists; `REDGATE_LLM_API_KEY` is a fallback.
6. Treat evidence, SQLite backups, reports, screenshots and runtime configuration as sensitive. Redaction is pattern-based and cannot guarantee removal of PII, custom secrets or sensitive URL paths. Encrypt disks/backups, restrict exports and define retention outside this application.
7. Pin approved image digests and scan dependencies/images before release. Review current [verification gaps](docs/VERIFICATION_2.1.0.md); local tests are not a container or independent security certification.

Internal service clients disable environment proxy inheritance. Any inference endpoint you configure is a privileged data destination: local/cloud model output is untrusted, and choosing a remote or proxied runtime can send prompts off-host. Prompt scrubbing does not make that private.

## Reporting a vulnerability

Do not publish working scope bypasses, sandbox escapes or secret disclosures in a public issue. Use the repository's private **Security → Report a vulnerability** flow if enabled; otherwise privately contact the maintainer through their published contact channel to arrange disclosure. Include affected version/component, expected/actual behavior, and a minimal non-destructive reproduction using only disposable loopback or documentation targets. Never include production tokens, customer data or unrelated target details.
