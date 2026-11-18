# RedGate 2.1 Architecture and Data Integrity

## Components and boundaries

```text
Vanilla JS console / API client (one origin; Bearer token in session storage)
       │
       ▼
Gateway — FastAPI, exactly one process per SQLite database
  Auth/RBAC → RoE/scope/DNS policy → quota/approval → bounded dispatch → audit
  ├─ MissionService: finite intent plan, lifecycle, checkpoints, report projections
  ├─ WorkspaceStore: serialized short SQLite writes; engagement-bound references
  ├─ EvidenceService: validates/redacts native observations; immutable snapshots
  ├─ Existing skills/memory/recon/LLM hub + four-language static validators
  │
  ├── X-Internal-Service-Token → Python MCP tools (argv-only external processes)
  ├── X-Internal-Service-Token → Go runner
  │                               ├─ fixed anonymous pinned HTTP collector
  │                               └─ digest-checked, bounded script processes
  ├── configured local/remote inference endpoint (untrusted model output)
  └── SQLite WAL: existing v2 data + additive workspace tables
```

Compose separates `control_net` (internal), target-egress and inference networks. It publishes only the loopback gateway. Application pinning and process supervision are not an external firewall or per-job OS sandbox. Production hostile-code containment and IPv4/IPv6 egress enforcement must be provided independently. See [SECURITY.md](../SECURITY.md).

## Mission semantics

`MissionCreateRequest` accepts a bounded host list, snapshotted enabled Skill, HTTP endpoint settings, action budget and duration. Planning validates scope syntax/assignment **without DNS or target contact**. The root target becomes an intent/asset; merely being known is not coverage.

```text
draft ──explicit start──► running ──all intents finished──► completed / failed
  │                         │
  ├─cancel──► cancelled     ├─pause──► pausing ──drain intent──► paused
  └─pause───► paused        ├─cancel─► cancelling ──next action gate──► cancelled
                             └─deadline/action cap──► budget_exhausted
paused ──explicit resume, original identity authorized, deadline valid──► running
restart: running/pausing → paused; cancelling → cancelled (never auto-resume)
```

An assigned admin may control a mission but cannot replace its original owner/quota. The execution owner must remain configured with an enabled credential digest and access to the engagement. The planner cannot enlarge the autonomous tool set; live scope/policy and low-risk status are rechecked on execution.

Reservations occur **before I/O**, under `BEGIN IMMEDIATE`; failures do not refund actions. Global/per-owner concurrency admission is also transactional. Owner API/LLM quotas remain enforced. This is a single-process coordinator with durable checkpoints, not a distributed lease/exactly-once queue. A crash between network I/O and checkpoint can lead to a repeated attempt only after explicit resume. Pause drains the current intent; cancel never retracts previously sent traffic.

## Native evidence path

1. Authenticate operator, authorize engagement, recheck RoE/scope and resolve a safe DNS pin.
2. Require enabled low-risk/non-gated `http_headers` policy and whitelisted endpoint parameters.
3. Reserve action/quota, then call Go `/http-evidence` using internal authentication and no environment proxy.
4. Go validates the contract independently; dials only the gateway-supplied IP while retaining logical Host/SNI; verifies HTTPS certificates/TLS ≥1.2; never follows redirects or supplies credentials. The collector bounds concurrency, host/port pacing, deadlines, headers and eligible text previews.
5. Gateway validates endpoint/method/connected pin and typed response, drops non-allowlisted headers, applies heuristic secret filtering, canonicalizes JSON and stores a SHA-256 snapshot. A separate audit entry anchors its identifier/digest.

HEAD and no body are defaults. Only explicit GET can request ≤8192 preview bytes. No query strings, arbitrary request headers, proxy URL, cookie jar, browser session or arbitrary replay exists. Evidence is a redacted application observation, not packet/TLS authenticity or proof against a compromised collector.

Retesting derives **only** a supported missing-header finding's original completed HTTP settings. A successful 2xx with/without the header yields `not_observed`/`still_present`; non-2xx or plaintext HSTS yields `inconclusive`. New immutable evidence/history is linked; analyst verdict and original finding remain unchanged.

## Storage and migration

Existing `engagements`, `allowlist`, policies, quota, approval queue, validated scripts, recon runs/findings, skills/memory/model runtime and hash-chained `audit_log` remain in SQLite. Foreign keys are enabled on connections. Serialized short write transactions avoid awaiting network I/O under a SQLite write lock.

`002_workspace.sql` adds:

| Table | Purpose / integrity |
|---|---|
| `workspace_assets` | Engagement/kind/locator deduplication; domain, IP, service, endpoint; parent references |
| `asset_runs` | Links observed asset coverage to authoritative recon runs |
| `missions` | Owner, Skill/HTTP snapshot, lifecycle, budgets, absolute deadline |
| `mission_intents` | Ordered targets, attempt count, checkpointed run, state/error |
| `http_evidence` | Canonical redacted payload, digest, capture identity and mission/run references; UPDATE/DELETE abort triggers |
| `finding_retests` | Finding/evidence link, actor, outcome, timestamp/note; UPDATE/DELETE abort triggers |
| `schema_migrations` | Applied migration name/SHA-256/time; detects subsequent source drift |

Migration application and digest registration are transactional and idempotent. Existing rows are not rewritten by this migration. Foreign-key existence alone is not authorization: store/service/API checks also require matching engagement/run/mission references. Database owners can defeat local triggers/checksums; trusted external audit anchors and encrypted backups are separate deployment concerns.

## Graphs and browser behavior

Graphs are deterministic **projections**, not another authoritative finding database. Asset IDs derive from engagement/kind/locator; graph node labels are DOM `textContent`, never HTML from target data. Missing/prototype-like kinds use a safe fallback. Keyboard Enter/Space operates the SVG nodes.

Server asset/exploration caps are 200/500 nodes, with a 120-node client cap. Snapshot reads are bounded and never resolve DNS or launch a scan. Active polling occurs every ten seconds only while the workspace is visible. Reset/sequence guards discard responses from a prior identity, engagement or superseded refresh. Authenticated API responses carry `Cache-Control: no-store` and `Vary: Authorization`; credentials are not placed in URLs.

Static files are served by gateway. Node/ESLint are validation/test toolchains, not a frontend production server. `full` images include all four script languages; `lite` omits Go/Node and advertises actual availability. The runner `evidence` target explicitly denies `/execute`, even if its base image happens to contain utilities.

## Existing AI and adapter path

The model hub estimates quantized-model memory; it does not guarantee capacity or output correctness. LLM output remains subject to prompt filtering, static validators, policy, approvals and digest verification. Runtime settings saved in SQLite take precedence over initial environment defaults. The configured API-key file is read per request and takes precedence over the environment fallback when present.

Go script compilation is offline (`GOPROXY=off`, `GOSUMDB=off`) with a cache; caches are not an isolation boundary. The runner scrubs child environments, bounds output/time/resource usage and cleans process groups, but does not create per-job namespaces. Proposed IPv4 firewall commands are diagnostic only; requesting unsupported in-process firewall enforcement refuses scripts instead of claiming enforcement.
