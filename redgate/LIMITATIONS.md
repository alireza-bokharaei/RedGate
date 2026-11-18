# Limitations and Operational Boundaries — 2.1.0

## Scope of this release

This is an independent addition of mission/graph/evidence/retest workflows to RedGate, not a full ARTEX source merge, feature clone or compatibility layer. See [ARTEX_SCOPE.md](docs/ARTEX_SCOPE.md). Exploitation, credential attacks, stealth, persistence, browser interception, unrestricted proxy/replay and autonomous offensive agents are not added.

## Authorization and traffic

- Application scope checks do not replace legal authorization, SOC deconfliction, external egress controls or careful engagement scheduling.
- DNS resolution, TLS, TCP checks and even HEAD requests are observable and can trigger alerts. Read-only HTTP can still have server-side effects on poorly designed targets. No stealth or zero-impact guarantee is made.
- HTTP evidence fails closed without a safe DNS pin, even if legacy strict-DNS mode has been relaxed. Metadata, link-local, multicast and unspecified destinations are not valid evidence targets. Explicitly allowlisted loopback is for private labs; inside Docker, `127.0.0.1` denotes the worker container, not the host gateway.
- Domain scope does not mean that an entire shared-hosting IP is authorized. Do not broaden egress scopes merely to make a tool run.

## Mission lifecycle and reliability

- A single gateway process owns the in-memory workers; SQLite stores their durable state. Do not run multiple Uvicorn workers, replicas or a shared network filesystem database. There is no distributed lease, external job broker or horizontally scaled scheduler.
- At most 8 target hosts, 64 actions and 1800 seconds per mission; at most two active missions globally and one per owner. A pause does not extend the absolute deadline. A terminal/budget-exhausted mission needs a new plan.
- Pause drains the current intent. Cancel gates later actions, not an already-sent network request. Shutdown can leave a remote collector finishing its bounded in-flight request.
- Completed/checkpointed runs are not silently replayed. After a hard crash, an action that performed I/O but did not persist its checkpoint may be retried on explicit resume. There is no exactly-once network execution guarantee. Reserved/failed attempts are not refunded.
- A mission can complete with failed/skipped checks or unavailable evidence; inspect intent warnings and step results. `completed` describes orchestration, not a clean bill of security.
- Plans snapshot a Skill; live target and tool permissions still apply. Gated follow-ups enter the existing approval workflow rather than executing autonomously.

## Graphs, coverage and exports

- Asset graph: up to 200 server-projected nodes. Exploration graph: up to 500 nodes. Console SVG: up to 120 nodes. Use paginated inventory APIs for larger datasets.
- The workspace displays the latest 30 missions and 20 evidence records. JSON mission export caps evidence at 100 and retest history at 100 per finding; inspect the export's limit/truncation metadata. It is not an unlimited archive of an engagement.
- Discovery is not a tested finding. Coverage counts recorded checks/evidence for known assets, not every path, port, vulnerability class or business workflow.
- No automatic importer/backfill of old recon runs or ARTEX databases is provided. Existing RedGate records are preserved; workspace inventory is built by new activity.

## Evidence and retests

- Only anonymous HEAD/GET with verified HTTPS or explicit plaintext HTTP. No authenticated-session replay, custom headers, request body, query/fragment, redirect following, browser DOM/network capture, HAR import or raw packet store.
- Native collector limits: four concurrent captures; two requests/second per logical host/port; timeout up to 15 seconds; response headers up to 32 KiB; explicit body preview up to 8192 bytes. These are collector limits, not a universal rate limit covering every legacy MCP/adaptor action.
- Headers are allowlisted; Set-Cookie and arbitrary application headers are discarded. Bodies are omitted by default and only eligible text previews may be retained. Secret filtering is heuristic: custom secrets, URL path identifiers and PII can survive. `redacted: true` means filtering was applied, not guaranteed absence of sensitive data.
- SHA-256 validates the stored redacted representation, not raw-wire authenticity or the honesty of a compromised worker. SQLite is not encrypted by this application; backups/exports need independent protection.
- Automatic retests cover supported `missing:<security-header>` findings from the original completed HTTP endpoint only. They preserve scheme, port, path and method. Non-2xx responses and HSTS over plaintext are inconclusive. Header presence does not establish its effectiveness. Other findings require manual review. Original analyst verdicts are never auto-updated.

## Script isolation and deployment

- Static analysis cannot prove arbitrary scripts safe. Timeouts, prlimit, environment scrubbing, digest verification and process-group cleanup are defense in depth—not an OS sandbox, VM, filesystem jail or network namespace.
- The runner only renders proposed IPv4 firewall commands; it does not apply them or prove IPv6/default-deny enforcement. `REDGATE_ENFORCE_IPTABLES=true` is unsupported and refuses script execution rather than falsely claiming protection. Use an independently verified external firewall and stronger per-job containment for hostile code.
- Compose provides non-root/read-only service containers, not per-script isolation. Jobs within a runner share a UID and persistent tool caches; a hostile adapter could interfere with that state. Avoid multi-tenant hostile workloads. Native evidence invokes no user-supplied code.
- `lite` omits Go/Node adapters and their validators. `full` includes all four languages but first-use Go compilation under finite memory/time may fail closed until caches are warm. The evidence-only runner target refuses scripts regardless of installed base utilities.
- PostgreSQL's optional Compose profile is provisioning only: the application still uses SQLite. There is no supported PostgreSQL driver, automatic database conversion or multi-node deployment.
- Docker builds, container startup, actual resource limits, image-size comparisons, performance benchmarks and real external inference were not run in the implementation sandbox. Local test timings are not production capacity or speedup measurements.

## Local models and human judgment

Offline inference requires previously downloaded model weights, correct model licenses and an actually local endpoint. Download/setup initially needs network access and storage. Local compute is not cost-free, quantization sizing is an estimate, and remote inference/proxies can send prompts off-host.

Model output, summaries, confidence and dual verification can be wrong or affected by prompt injection. They do not replace analyst assessment of authorization/business logic, IDOR/BOLA, compensating controls, asset criticality, privacy or impact. A model cannot enlarge scope, bypass policy or approve its own work.
