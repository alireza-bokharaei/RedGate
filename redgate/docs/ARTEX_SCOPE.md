# ARTEX Review, Implementation Scope and Licensing Boundary

## Reviewed reference

The reference was [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX) at commit [`51e2c603b94d88856215dd73744d19641f44f3ca`](https://github.com/BaaRai/ARTEX/tree/51e2c603b94d88856215dd73744d19641f44f3ca), reviewed on 2026-11-18. Its [AGPL-3.0 license](https://github.com/BaaRai/ARTEX/blob/51e2c603b94d88856215dd73744d19641f44f3ca/LICENSE) differs from Redstrike's existing MIT license.

**No ARTEX source, assets, dependencies, database schema or frontend have been copied/vendored into this release.** Redstrike 2.1 independently implements the workflows below within its existing governed architecture. This is not an ARTEX fork, a whole-project merge, an upstream-supported integration or a feature-parity claim.

This release delivers the capability subset in the table below. It must not be represented as fulfilling a literal whole-project ARTEX source integration or as approval of a licensing change. Whole-source integration remains pending an explicit compatibility/license/deployment decision and a larger security review.

## Capability mapping

| ARTEX-inspired workflow | Redstrike 2.1 delivery | Deliberate boundary |
|---|---|---|
| Mission-oriented assessment | Persistent host intents, explicit lifecycle, finite budgets/deadline, checkpoint recovery | Existing bounded Skills; no unrestricted autonomous offensive agent |
| Asset graph | Engagement-scoped domain/IP/service/endpoint inventory and graph projection | Known/discovered is not tested; no external asset feed or ARTEX database import |
| Exploration graph | Goal → intent → check → finding/evidence/retest references | Read-only projection of authoritative Redstrike records, capped/paginated |
| HTTP evidence | Anonymous native Go HEAD/GET, pinned dial, verified TLS, redacted immutable snapshots | No MITM, browser session capture, arbitrary proxy, authenticated replay or raw secret store |
| Finding retest | Append-only missing-security-header observations on the original endpoint | No exploit replay, business-logic validation or automatic analyst verdict changes |
| Operator workspace/reporting | Native JavaScript/SVG console and audited Markdown/JSON exports | No imported React/Next.js stack; no ARTEX UI/API compatibility promise |
| Operational packaging | Bash tooling, native Go service, JS validators/tests and multi-stage Docker targets | No measured container performance advantage is asserted |

ARTEX's unrelated platform/tool/plugin features, offensive execution workflows, database/backend/frontend components and complete CLI/API surface are **not** included simply because this release has analogous core workflows. Redstrike's own non-exploitation, RoE, approvals, quotas and auditing remain authoritative.

## License handling

Redstrike retains its existing [MIT license](../LICENSE) for its own code; dependencies and deployed external tools keep their respective licenses. Referencing a workflow/project is not a claim to have relicensed the referenced source.

If future work imports or modifies ARTEX code, do not remove AGPL notices or assume the resulting combined work can be distributed as MIT-only. Evaluate how components are combined, distribution and network use, corresponding-source obligations (including AGPL section 13 for modified network-interactive software), notices and deployment responsibilities. This note is a scope/provenance record, not legal advice or a substitute for license review.
