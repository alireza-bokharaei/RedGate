"""Composable, policy-validated Skill registry for the Redstrike Recon Agent.

Skills encode reusable recon playbooks, severity calibration rules, and reporting
focus in declarative YAML or operator-defined specs. A skill can NEVER unlock
disabled high-risk tools (sqlmap, hydra, john) or bypass Two-Person approval.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from gateway.db import Database

# Tools a skill may execute autonomously (strictly low-risk read-only + validated sandbox).
AUTONOMOUS_SKILL_TOOLS: frozenset[str] = frozenset(
    {"dns_lookup", "tcp_port_probe", "http_headers", "tls_inspect", "sandbox_script"}
)
# Tools a skill may ONLY propose into the Two-Person Approval Queue (never run directly).
APPROVAL_ONLY_SKILL_TOOLS: frozenset[str] = frozenset({"nmap"})
SAFE_SUBDOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,30}[a-z0-9])?$")
VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


class SkillValidationError(ValueError):
    """Raised when a skill definition violates platform safety boundaries."""


def validate_skill_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a skill playbook before storing or executing it."""
    steps = spec.get("steps")
    if not isinstance(steps, list) or not (1 <= len(steps) <= 6):
        raise SkillValidationError("Skill must define between 1 and 6 bounded steps.")

    clean_steps: list[dict[str, Any]] = []
    for idx, raw_step in enumerate(steps, start=1):
        tool = str(raw_step.get("tool", "")).strip()
        mode = str(raw_step.get("mode", "execute")).strip()
        if tool in APPROVAL_ONLY_SKILL_TOOLS:
            # Force gated tools into recommend_approval mode (cannot bypass human review).
            mode = "recommend_approval"
        elif tool not in AUTONOMOUS_SKILL_TOOLS:
            raise SkillValidationError(
                f"Step #{idx}: tool '{tool}' is prohibited in automated skills. "
                f"Allowed: {sorted(AUTONOMOUS_SKILL_TOOLS | APPROVAL_ONLY_SKILL_TOOLS)}."
            )
        clean_steps.append(
            {
                "stage": str(raw_step.get("stage", f"step_{idx}"))[:48],
                "tool": tool,
                "params": dict(raw_step.get("params") or {}),
                "mode": mode,
                "on_ip_target": str(raw_step.get("on_ip_target", "run")),
                "only_if_port_open": raw_step.get("only_if_port_open"),
                "rationale": str(raw_step.get("rationale", ""))[:240],
            }
        )

    raw_prefixes = list(spec.get("subdomain_prefixes") or [])[:8]
    clean_prefixes: list[str] = []
    for pref in raw_prefixes:
        label = str(pref).strip().lower()
        if not SAFE_SUBDOMAIN_LABEL_RE.match(label):
            raise SkillValidationError(f"Invalid subdomain prefix label '{pref}'.")
        if label not in clean_prefixes:
            clean_prefixes.append(label)

    raw_prio = dict(spec.get("prioritization_rules") or {})
    clean_prio: dict[str, Any] = {}
    for k, v in raw_prio.items():
        if k.endswith("_severity"):
            sv = str(v).lower()
            if sv not in VALID_SEVERITIES:
                raise SkillValidationError(f"Invalid severity '{v}' for rule '{k}'.")
            clean_prio[k] = sv
        elif isinstance(v, (int, float)):
            clean_prio[k] = v

    return {
        "max_steps": min(int(spec.get("max_steps", len(clean_steps))), 6),
        "expand_wildcard_subdomains": bool(spec.get("expand_wildcard_subdomains", False)),
        "subdomain_prefixes": clean_prefixes,
        "steps": clean_steps,
        "prioritization_rules": clean_prio,
        "report_focus": str(spec.get("report_focus", "")).strip()[:400],
    }


def seed_builtin_skills(db: Database, skills_dir: str | Path) -> int:
    """Load declarative `skills/*.yaml` files into `agent_skills` idempotently."""
    base = Path(skills_dir)
    if not base.is_dir():
        return 0
    count = 0
    for path in sorted(base.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "id" not in raw:
            continue
        clean_spec = validate_skill_spec(raw)
        db.upsert_skill(
            skill_id=str(raw["id"]),
            name=str(raw.get("name", raw["id"])),
            version=str(raw.get("version", "1.0")),
            category=str(raw.get("category", "recon")),
            description=str(raw.get("description", "")).strip(),
            spec=clean_spec,
            created_by="builtin",
            enabled=True,
            is_builtin=True,
        )
        count += 1
    return count
