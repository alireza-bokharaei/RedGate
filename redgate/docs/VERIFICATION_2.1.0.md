# Redstrike 2.1.0 — Verification Record

Verified locally and in GitHub CI on **2026-11-18**. This record distinguishes executed local checks, the linked remote CI result and remaining deployment work. It is not a security certification or a performance benchmark.

## Executed local checks

| Check | Result |
|---|---|
| Unified `scripts/verify.sh`, using a fresh Python virtualenv and a fresh `npm ci` | Passed the local Bash/JS/Go/Python stages; local Docker stage explicitly skipped |
| Complete Python regression/integration suite | **108 passed in 20.12s** on the pre-publication rerun, no failures/skips; one upstream TestClient deprecation warning |
| Python lint | Ruff passed for `gateway`, `mcp_server`, `tests` with the repository's configured rule set |
| Go | `gofmt` clean; `go test -race ./...` passed (2.390s); `go vet ./...` and static runner build passed |
| JavaScript | Syntax and ESLint passed; **9 graph/controller/DOM tests passed** |
| Bash | Syntax and ShellCheck passed for every `scripts/*.sh`; executable file modes verified |
| Fresh Python dependency installation | `pip install --require-hashes -r requirements-dev.txt` succeeded; `pip check` found no broken requirements |
| Python 3.12 wheel compatibility | Hash-verified binary runtime wheels successfully resolved/downloaded locally; the separate executed Python 3.12 CI job is recorded below |
| Validator-only Node installation | Locked `npm ci --omit=dev` succeeded; ESLint 10.15.0 works; linkedom/Playwright test packages absent |
| Compose schema | Structural validation passed against compose-spec revision `6b3a2a93e77c30ded1aa8264307e74d1208a6eae`; executed Compose checks are recorded below |
| Workflow | Local YAML structure, read-only permissions and pinned action references checked; actionlint's binary download was unavailable; remote execution is recorded below |
| Version/patch consistency | Shared 2.1.0 version checks and `git diff --check` passed |

Local toolchain: Python **3.11.2**, Go **1.26.6**, Node **22.22.3**, ShellCheck **0.11.0** on Linux x86-64. Python/test/lint and Node dependencies are pinned in the checked-in locks. The TestClient warning is Starlette's deprecation of its `httpx` backend in favor of `httpx2`; no warning suppression or claim of zero warnings is made. New asynchronous API feature tests use HTTPX ASGI transport.

### Coverage represented by the tests

- Mission creation without DNS/target I/O, explicit lifecycle/owner attribution, pause/cancel gates, checkpoint recovery/shutdown, absolute deadlines, action/quota/concurrency limits and revoked scope/tool policies.
- Atomic action reservations across two Database instances and concurrent attempts; an action budget cannot be overspent by those races.
- Engagement authorization before finding mutation, mission controls and evidence/retest reads/exports. Dashboard reads do not start scans.
- Additive migration preserving old records; repeated startup; applied-digest drift; DDL/ledger rollback on an intentionally broken migration and successful retry.
- Redaction, immutable evidence/history triggers, checksum/corruption checks, invalid worker endpoint/pin/method rejection and supported/unsupported retest behavior without analyst-verdict mutation.
- Mapped IPv6 metadata/literal/CIDR denial, mapped loopback authorization, unspecified-address rejection and canonical IP normalization.
- MCP actual loopback pinned HTTP dial, preserved Host/TLS SNI, certificate verification, no redirect/proxy use, streaming without buffering a huge advertised body, and internal-token transport settings.
- Native Go collector tests for auth, pins, verified TLS, redirects, proxies, bounds, pacing/cancellation and race safety.
- **Real gateway → compiled Go collector → disposable loopback HTTP** tests for HEAD/no-body, GET/redaction/no secret forwarding, redirects not followed, both header-retest outcomes, unchanged analyst verdict, and evidence-only script denial.
- Bash bootstrap hashes/modes, non-clobbering WAL-consistent gzip backups, atomic key rotation, lifecycle wrapper behavior and safe host-vs-container LLM setup without model downloads.
- Graph determinism/bounds, hostile labels/prototype-like kinds, SVG keyboard behavior, markup hooks, explicit controls/polling, stale identity/engagement/evidence responses and Markdown download handling.

Some mission/evidence unit cases intentionally use fake MCP/runner transports to exercise races and malformed responses. They are **not** substituted for the real collector tests or browser run described here. Local tests do not establish production isolation or external-target compatibility.

## Executed real-browser smoke test

Chromium **153.0.8010.0** with Playwright Core **1.65.1** drove a three-process local stack using a disposable, loopback-only scope, mock AI and disabled script adapters. The native MCP header path and Go evidence collector were real processes, not browser API mocks.

The test:

1. Obtained an explicit demo-lab identity and selected `ENG-LOCAL-LAB`.
2. Planned and explicitly started a mission against the local `/probe/headers` endpoint.
3. Observed completion and inspected an intact redacted evidence record.
4. Opened the exploration graph and invoked a missing-CSP header retest.
5. Observed the appended retest and unchanged-verdict notice; API regression tests separately assert that the stored analyst verdict is unchanged.
6. Downloaded/checked the actual Markdown report and activated a graph node with Enter.
7. Checked desktop and 390px mobile layouts, zero page-JavaScript errors and zero browser requests outside the local origin.

Latest output:

```json
{"browser":"153.0.8010.0","mission":"completed","evidence":1,"headerRetest":"appended","markdown":"downloaded","keyboard":"passed","mobile":{"document":390,"viewport":390},"externalRequests":0,"javascriptErrors":0}
```

This run found and fixed a real-browser SVG visibility bug (`SVGElement` has no `HTMLElement.hidden` setter) and mobile header overflow. DOM-only tests would not by themselves have established correct browser rendering.

### Reproduce on a Linux development machine

Install development dependencies and run `scripts/verify.sh` first. Install a compatible Chromium through your approved browser/package process; `npm ci` does not download one. Keep ports 8000/8001/8002 free.

Terminal A, from `redgate/`, in a **private lab only**:

```bash
LAB_DIR=$(mktemp -d)
REDGATE_DB_PATH="$LAB_DIR/lab.sqlite" \
REDGATE_DEMO_MODE=true REDGATE_LLM_MODE=mock \
./scripts/start_local.sh
```

Terminal B, from `redgate/`:

```bash
REDGATE_CHROMIUM_EXECUTABLE=/usr/bin/chromium npm run test:browser
```

Adjust the executable path to your approved installation. In the implementation sandbox the Chromium binary/shared libraries were temporarily obtained via the npm `@sparticuz/chromium` package, with `LD_LIBRARY_PATH`/`FONTCONFIG_PATH` set for that package; those binaries/libraries are **not shipped** with Redstrike. Screenshots/report are written to ignored `test-results/browser/`. Stop the launcher and securely remove the disposable lab data when finished. Never expose demo login as a deployment.

The reproducible smoke test is for a **direct host** stack, not Compose: container loopback is a different network endpoint. For a restricted demo matching the run above, use a copied config with only the loopback engagement and disabled script policies. The normal local config can exercise additional approved adapter steps, subject to installed tools/timeouts; these are not required to establish the native evidence UI flow.

## Executed GitHub CI

[Run **44288999257**](https://github.com/alireza-bokharaei/Redstrike/actions/runs/44288999257) completed with **success** on 2026-11-18 for source commit [`763da1108e773bdee6bdadb4d84d0ad4c1f9eaad`](https://github.com/alireza-bokharaei/Redstrike/commit/763da1108e773bdee6bdadb4d84d0ad4c1f9eaad) in [PR #1](https://github.com/alireza-bokharaei/Redstrike/pull/1). The workflow ran on Ubuntu 24.04 runners:

| Job | Observed result |
|---|---|
| `polyglot (3.11)` | Passed locked dependency installation and the unified Bash/JS/Go race/vet/build/Python regression and integration checks |
| `polyglot (3.12)` | Passed the same checks using an executed Python 3.12 runtime |
| `containers (full)` | Passed Compose configuration, image builds, container startup, readiness, demo-disabled and actual installed-tool/language checks |
| `containers (lite)` | Passed the same checks with the reduced toolchains, and built the script-denying `evidence` target |

The CI uses disposable credentials/project volumes and read-only repository permissions. It emitted Node.js 20 deprecation annotations for pinned helper Actions that GitHub ran with Node.js 24; the jobs passed. This is not a claim of warning-free CI and does not change the application's tested Node 22 toolchain.

The container jobs establish build/startup/health/capability behavior on those CI runners. They do **not** execute the complete hostile-code workload or a target-facing native evidence capture inside those containers. The evidence-only image was **built**, not separately runtime-smoke-tested as an image; its mode/auth/script-denial behavior is covered by the host native-runner integration tests. Consult Actions/PR checks for subsequent commits instead of treating this historical run as a result for changed code.

## Still unverified / required before production

- Intended-host mounts/secret-group access, non-root/read-only behavior and actual resource enforcement under realistic workloads. There is still no Docker daemon/socket in the implementation sandbox itself; the executed Docker result above came from GitHub CI.
- In-container native collector and Go/JS adapter execution under real deployment networks and memory/time limits; external IPv4/IPv6 default-deny firewall, scope-denial tests and hostile-code containment.
- Measured image sizes, cold/warm build/startup times, idle/loaded RAM/CPU or speed improvements. No numeric performance advantage is asserted.
- Real Ollama/LM Studio/model downloads, loaded model IDs, hardware sizing, cloud/provider key rotation and off-host inference/proxy behavior.
- A staging upgrade/restore using an actual deployment backup, long-running/multi-operator load tests, independent security review and accessibility audit across browsers/assistive technologies.
- Whole-project ARTEX import/compatibility and AGPL integration: not implemented or silently relicensed; see [scope/provenance](ARTEX_SCOPE.md).
