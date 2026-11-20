# Live Verification — 2.3 offensive surface

Everything below was executed against a **loopback Gateway** with three operators
and the RFC 5737 engagement from `config/allowlist.yaml`. No external host was
contacted. `alice` and `sara` are operators; `kaveh` is the admin/approver.

Reproduce with `.arena/live_run.sh` (gitignored scratch launcher) and
`uvicorn gateway.main:app --host 0.0.0.0 --port 8123`.

## Session Start Protocol

| # | Call | Result |
|---|---|---|
| 1 | `GET /api/v1/health` | `agent_roles_count: 49`, `tool_catalog_size: 4` (installed), `pwntools_layer: false` |
| 2 | `GET /offensive/brief` | mission `unclassified`; scope active with 4 allowlist entries; RoE `posture:permissive_in_scope`, `consent_met: false`, two-person list of 3; TLS `mandatory: true, pending: true`; layers `tool_execution: available`, `agents: available`, `pwntools: unavailable` |

## Control model

| # | Call | Result |
|---|---|---|
| 3 | `POST /decide` (`tool:nmap`, no consent) | `allowed: false`, `missing_consents: ["operator"]` |
| 4 | `POST /consent` (posture declaration) | `level: operator` recorded |
| 5 | `POST /decide` (`tool:nmap`, after consent) | `allowed: true`, `two_person_required: false` — *"Permitted by posture within declared scope."* |
| 6 | `POST /decide` (`tool:nmap_aggressive`) | `allowed: true`, `two_person_required: false` |
| 7 | `POST /decide` (`exploitation:proof_of_concept`) | `allowed: false`, `two_person_required: true` (operator consent alone is insufficient) |
| 8 | `POST /explore/mass-scan` (64 hosts / 5000 requests) | `pending_approval`, `apr-…` |

## Refusals

| # | Attempt | Result |
|---|---|---|
| 9 | `sqlmap --os-shell` | **422** `'sqlmap --os-shell' is refused by policy (destructive, evasive, or file-system affecting).` |
| 10 | `nmap 203.0.113.99` | **422** `Target '203.0.113.99' is NOT in active allowlist` |
| 11 | `nmap 169.254.169.254` | **422** `address … is in blocked cloud metadata range` |
| 12 | `nmap 198.51.100.10 -sV` | `status: unavailable`, argv `["nmap","-sV","--","198.51.100.10"]`, exit 127, *"argv was validated; nothing was executed"* |

## Exploitation lifecycle

| # | Step | Result |
|---|---|---|
| 13 | kaveh grants `approver` consent for `exploitation:proof_of_concept` | recorded |
| 14 | alice drafts a PoC | `status: drafted`, `two_person_required: true`, `approval_id: apr-…` |
| 15 | alice self-approves | **403** `Only 'approver' or 'admin' roles may decide…` |
| 16 | execute before approval | **422** `still awaiting independent approval` |
| 17 | execute with `execute_immediately: true` | approval status became `failed` — the approval is consumed by execution, so the operator must record the run explicitly |
| 19 | fresh PoC, approval with `execute_immediately: false` | approval `approved`; execution recorded, `output_sha256` returned |
| 20 | sara reproduces with different output | **422** → finding demoted to `unverified`, summary `confirmed: 0` |
| 21 | sara reproduces exactly | `status: verified`, `verified_by: sara` |
| 23 | chain from two verified findings | `chn-…`, `weakest_link: "Missing HSTS… (low)"` |
| 24 | chain including an unverified step | **422** `Not verified: exp-…` |

## Discovery, bounty, loops

| # | Call | Result |
|---|---|---|
| 25 | `POST /explore/discover` with 5 candidates | 3 in scope, 1 out of scope → proposal, 1 rejected (`Refusing to treat 'bad host; rm -rf /' as a host`); expansion request `xpn-…` `pending` |
| 26 | register hackerone program | `source: manual`, `last_synced_at: null`, `sync_error` set |
| 27 | `POST …/sync` with no credentials | `status: unavailable`, names `HACKERONE_API_USERNAME`, `HACKERONE_API_TOKEN`; scope stays manual |
| 28 | duplicate check | `outcome: unverified`, confidence 0.0 |
| 29 | report draft from verified finding | `body_chars: 871`, contains PoC and output SHA-256 |
| 31 | scope drift | both assets `testable`, none blocked by the allowlist |
| 32 | `GET /agents` | 49 roles, 14 phases |
| 33–34 | open loop, iterate, gate with `unknown`/`no` | `passed: false`, blocking `q3_security_impact(unknown)`, `q5_independent_validation(no)` |
| 35 | kill loop with reason | `status: killed`, reason stored |
| 36 | `GET /brain` | `{hypothesis:1, lesson:1, note:1, question:7, verdict:1}`, `loops: {killed: 1}` |
| 37 | direct `UPDATE`/`DELETE` on `brain_entries` | both refused by trigger |
| 38 | `GET /pwntools/status?refresh=true` | `available: false`, `ModuleNotFoundError: No module named 'pwn'` |

## Posture change and the floor

| # | Call | Result |
|---|---|---|
| 39 | `POST /posture` → `posture:ctf_aggressive` (kaveh) | applied; `risk: high`, `two_person: false` |
| 40 | out-of-scope target **and** `--os-shell` under CTF posture | both still **422** — the aggressive posture never widens reach or capability |
| 41 | `GET /api/v1/audit/verify` | `valid: true`, 35 entries, head hash `51281d4f…`, both append-only triggers present |

## Binary tooling through the live bridge

With a real MCP service on `:8001` (`catalog_size: 144`, 12 groups) and a copy of
`/bin/true` at `.arena/artifacts/vuln.elf`:

| Call | Result |
|---|---|
| `readelf vuln.elf -h` | **200**, `status: completed`, exit 0, argv `['readelf','-h','vuln.elf']`, ELF header printed |
| `readelf nope.elf -h` | exit 127, `Artifact 'nope.elf' was not found in the configured root.` |
| `readelf ../../etc/passwd -h` | **422**, path refused |
| gateway with the MCP service stopped | `status: unavailable` (bridge error quoted), **not** a 500 stack trace |

## Two bugs found and fixed during this run

1. `POST /bounty/reports` with a non-existent `check_id` returned **500** via an
   `IntegrityError`. Fixed by validating the foreign keys first: it now returns
   **422** with `Unknown duplicate check '…'`. Regression test:
   `test_report_rejects_unknown_foreign_keys_with_a_reason`.
2. `POST /tools/run` with `tool: readelf, target: 127.0.0.1` was scope-checking a
   *file name* against the allowlist, and the executor resolved artifacts against
   the MCP process cwd. Both fixed: `takes_artifact()` splits network tools from
   binary tooling, `build_argv()` refuses path separators, and the executor
   resolves names against an explicit `REDGATE_ARTIFACT_DIR` with a real
   containment check. A downstream bridge failure is now a `status: unavailable`
   result instead of an unhandled 500. Regression tests:
   `test_binary_tools_take_artifacts_not_hosts`,
   `test_artifact_root_resolution_is_contained`,
   `test_executor_without_artifact_root_refuses_rather_than_guessing`.

## Test totals

```
tests/test_offensive_surface.py                                71 passed
tests/ (minus e2e / agent_v2 / collector)                     232 passed, 3 environmental failures
ruff check .                                                   clean
```

The three remaining failures are `tests/test_validators.py`, which needs
`shellcheck`/`go`/`eslint` on the image; the five errors are the e2e suites that
need `bin/sandbox-runner` and free ports 28001/28002.
