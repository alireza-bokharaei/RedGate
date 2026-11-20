"""Advisory agent-role catalogue for 2.2, adapted from the pentest-agents workflow.

A role is a *planner*: it proposes which governed primitive to use, what to look
for, and what would refute the claim. A role can never call a tool, raise a
budget, widen scope, approve a request or mark a finding confirmed — those remain
Gateway/Gateway-policy/database decisions.

Each role declares the capabilities it needs so the Gateway can intersect them
with the active mode before a planner is allowed to run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentRole:
    role_id: str
    title: str
    phase: str
    capabilities: frozenset[str]
    primitives: tuple[str, ...]
    objective: str
    refutation: str
    outputs: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_id": self.role_id,
            "title": self.title,
            "phase": self.phase,
            "capabilities": sorted(self.capabilities),
            "primitives": list(self.primitives),
            "objective": self.objective,
            "refutation": self.refutation,
            "outputs": list(self.outputs),
            "can_execute": False,
            "can_approve": False,
            "can_widen_scope": False,
        }


def _role(
    role_id: str,
    title: str,
    phase: str,
    capabilities: tuple[str, ...],
    primitives: tuple[str, ...],
    objective: str,
    refutation: str,
    outputs: tuple[str, ...] = (),
) -> AgentRole:
    return AgentRole(
        role_id=role_id,
        title=title,
        phase=phase,
        capabilities=frozenset(capabilities),
        primitives=primitives,
        objective=objective,
        refutation=refutation,
        outputs=outputs,
    )


AGENT_ROLES: tuple[AgentRole, ...] = (
    # -- reconnaissance -------------------------------------------------------
    _role(
        "scope-cartographer",
        "Scope Cartographer",
        "recon",
        ("recon",),
        ("dns_lookup", "tcp_port_probe"),
        "Enumerate only in-scope names and reachable service ports; stop at the allowlist edge.",
        "Refutes itself when a discovered name resolves outside the engagement allowlist.",
        ("asset-inventory.json",),
    ),
    _role(
        "subdomain-expansion-planner",
        "Subdomain Expansion Planner",
        "recon",
        ("recon",),
        ("dns_lookup",),
        "Propose candidate subdomains from the mission's declared prefix budget.",
        "Every candidate is rejected unless the scope engine independently allows it.",
        ("subdomain-candidates.txt",),
    ),
    _role(
        "service-inventory-analyst",
        "Service Inventory Analyst",
        "recon",
        ("recon", "port_probe"),
        ("tcp_port_probe", "nmap"),
        "Describe exposed services and defensible follow-up checks per open port.",
        "Treats an open port as inventory, never as a finding.",
    ),
    # -- transport ------------------------------------------------------------
    _role(
        "tls-deep-analyst",
        "TLS Deep Analyst",
        "transport",
        ("tls_deep_analysis", "external_tls_adapters"),
        ("tls_inspect", "http_headers"),
        "Sweep protocol floor, cipher strength, certificate chain and HSTS posture.",
        "Re-probes any claimed weak protocol twice before it may be reported.",
        ("tls-summary.json",),
    ),
    _role(
        "certificate-lifecycle-analyst",
        "Certificate Lifecycle Analyst",
        "transport",
        ("tls_deep_analysis",),
        ("tls_inspect",),
        "Correlate expiry windows, SAN coverage and signature algorithm strength.",
        "Confirms an expiry finding against the parsed notAfter, not a model summary.",
    ),
    # -- web hunters ----------------------------------------------------------
    _role(
        "http-hardening-hunter",
        "HTTP Hardening Hunter",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Detect missing or weak defensive headers on an approved endpoint and method.",
        "Downgrades a missing header to informational when a compensating proxy sets it.",
        ("http-hardening.md",),
    ),
    _role(
        "cors-posture-hunter",
        "CORS Posture Hunter",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Read Access-Control-* behaviour allowed by the header allowlist.",
        "Discards any observation that would require an authenticated session or a custom origin.",
    ),
    _role(
        "cookie-flag-hunter",
        "Cookie Flag Hunter",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Check Secure/HttpOnly/SameSite only when the collector is allowed to retain Set-Cookie.",
        "Reports 'not observable' rather than guessing when the header is discarded.",
    ),
    _role(
        "redirect-policy-analyst",
        "Redirect Policy Analyst",
        "web",
        ("http_header_audit",),
        ("http_headers",),
        "Describe a 3xx Location without following it.",
        "Never chases a redirect; a cross-host Location is reported, not visited.",
    ),
    # -- discovery / correlation ---------------------------------------------
    _role(
        "vulnerability-class-planner",
        "Vulnerability Class Planner",
        "discovery",
        ("recon", "http_header_audit", "tls_deep_analysis"),
        ("http_headers", "tls_inspect", "dns_lookup"),
        "Rank the vulnerability classes most likely to be reachable from observed surface.",
        "Marks every hypothesis as a hypothesis until a deterministic check supports it.",
    ),
    _role(
        "chain-builder",
        "Exploit Chain Builder (planning only)",
        "discovery",
        ("chain_analysis", "correlation"),
        (),
        "Describe how confirmed findings could combine, with the weakest link named.",
        "Refuses to combine a candidate-level finding into a confirmed chain.",
        ("chain-plan.md",),
    ),
    _role(
        "devils-advocate",
        "Devil's Advocate",
        "validation",
        ("correlation",),
        (),
        "Attempt to disprove every candidate: cache, CDN, proxy, honeypot, by-design, measurement error.",
        "If a counter-observation exists, the candidate may not be confirmed.",
        ("refutations.json",),
    ),
    _role(
        "evidence-validator",
        "Evidence Validator",
        "validation",
        ("correlation",),
        (),
        "Apply the seven-question gate and record which question failed and why.",
        "Cannot confirm anything itself; it can only reject or downgrade.",
        ("gate-results.json",),
    ),
    _role(
        "finding-correlator",
        "Finding Correlator",
        "correlation",
        ("correlation",),
        (),
        "Merge duplicate observations across hosts and record the shared root cause.",
        "Requires an identical finding key and a re-runnable check before merging.",
    ),
    # -- expansion ------------------------------------------------------------
    _role(
        "scope-expansion-negotiator",
        "Scope Expansion Negotiator",
        "governance",
        ("scope_expansion_request",),
        (),
        "Draft a scope or budget expansion request with the RoE clause it relies on.",
        "Cannot add a target itself; a different human must approve every expansion.",
    ),
    _role(
        "approval-drafter",
        "Approval Drafter",
        "governance",
        ("correlation",),
        (),
        "Prepare the human-readable justification for a gated action.",
        "A model-written justification is still subject to independent approval.",
    ),
    # -- bug bounty -----------------------------------------------------------
    _role(
        "bug-bounty-scope-sync",
        "Bug Bounty Scope Sync",
        "bug_bounty",
        ("recon",),
        (),
        "Reconcile the program's in-scope list with the local engagement allowlist.",
        "Any program asset absent locally is reported as 'not authorised here'.",
    ),
    _role(
        "duplicate-hinter",
        "Duplicate Hinter",
        "bug_bounty",
        ("duplicate_hinting",),
        (),
        "Flag findings whose class/endpoint is commonly already reported.",
        "Explicitly states it has no live platform lookup and cannot prove non-duplication.",
    ),
    _role(
        "report-writer",
        "Report Writer",
        "reporting",
        ("report_drafting",),
        (),
        "Draft a reproduction-first report from gate-confirmed findings only.",
        "Refuses to include a finding whose gate status is not 'confirmed'.",
        ("report-draft.md",),
    ),
    # -- ctf / binary --------------------------------------------------------
    _role(
        "binary-triage-analyst",
        "Binary Triage Analyst",
        "binary",
        ("binary_hardening_triage",),
        ("binary_hardening_triage",),
        "Read ELF hardening flags (NX, PIE, RELRO, canary, RPATH) from a local artifact.",
        "Reports only parsed header facts; no exploitation, no remote interaction.",
        ("binary-hardening.json",),
    ),
    _role(
        "challenge-solver",
        "Challenge Solver",
        "ctf",
        ("recon", "http_header_audit"),
        ("http_headers", "dns_lookup"),
        "Plan challenge-specific checks against the CTF's authorised host set.",
        "Cannot expand beyond the CTF engagement's declared allowlist.",
    ),
)

_BY_ID = {role.role_id: role for role in AGENT_ROLES}


class UnknownRole(KeyError):
    pass


def get_role(role_id: str) -> AgentRole:
    try:
        return _BY_ID[role_id]
    except KeyError as exc:
        raise UnknownRole(f"Unknown agent role '{role_id}'.") from exc


def list_roles() -> list[dict[str, Any]]:
    return [role.to_dict() for role in AGENT_ROLES]


def roles_for_capabilities(capabilities: set[str] | frozenset[str]) -> list[AgentRole]:
    """Roles whose required capabilities are all satisfied by the active mode."""
    return [role for role in AGENT_ROLES if role.capabilities <= set(capabilities)]


def plan(
    *,
    capabilities: set[str] | frozenset[str],
    mode_id: str,
    phase: str | None = None,
) -> dict[str, Any]:
    """Return the advisory plan for a mode; contains no executable action."""
    available = roles_for_capabilities(capabilities)
    if phase:
        available = [r for r in available if r.phase == phase]
    blocked = [r for r in AGENT_ROLES if r.role_id not in {a.role_id for a in available}]
    return {
        "mode": mode_id,
        "phase": phase,
        "roles": [r.to_dict() for r in available],
        "unavailable_roles": [
            {"role_id": r.role_id, "missing_capabilities": sorted(r.capabilities - set(capabilities))}
            for r in blocked
        ],
        "advisory_only": True,
        "note": (
            "Roles plan; the Gateway executes. No role output can approve, expand scope, "
            "raise a budget or confirm a finding."
        ),
    }
