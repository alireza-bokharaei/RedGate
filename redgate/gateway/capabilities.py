"""Operational modes, capability resolution and the widened 2.2 policy surface.

The 2.2 control model widens *what a mission may do* while keeping every hard
invariant in force:

* An engagement's signed RoE window and allowlist remain authoritative.
* ``mcp_server.tools`` code-level ban lists cannot be removed by this module.
* Cloud-metadata / DNS-rebinding guards in ``gateway.policy`` are untouched.
* Budget and quota can be *raised* only through a Two-Person approval request.
* A capability name grants nothing on its own; it must also intersect the live
  tool policy, the skill snapshot and the mission ceiling.

Everything here is a pure, side-effect-free evaluation so it can be audited and
unit tested without a container or a network target.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

MODEL_HARD_LIMITS: dict[str, int] = {
    "max_hosts": 8,  # workspace_models.MissionCreateRequest upper bound
    "max_actions": 128,  # 2.2 discretionary ceiling (legacy default remains 64/mission)
    "max_seconds": 3600,
}

CAPABILITY_MODE_POLICY = "redgate_capability_mode"


class CapabilityError(ValueError):
    """A requested mode, capability or ceiling is not permitted by policy."""


@dataclass(frozen=True)
class ModeCeiling:
    """Validated execution ceiling for one operational mode."""

    max_hosts: int
    max_actions: int
    max_seconds: int
    concurrent_missions: int


@dataclass(frozen=True)
class ModeDefinition:
    """A named operational mode and the capabilities it may exercise."""

    mode_id: str
    label: str
    summary: str
    default_skill: str
    ceiling: ModeCeiling
    capabilities: frozenset[str]
    mandatory_capabilities: frozenset[str] = frozenset()
    expansion_clauses: tuple[str, ...] = ()
    expansion_max: int = 0
    expansion_max_hosts: int = 0
    expansion_requires_approver: bool = True

    def allows(self, capability: str) -> bool:
        return capability in self.capabilities


@dataclass(frozen=True)
class CapabilityDecision:
    """Outcome of resolving one capability request."""

    allowed: bool
    mode: str
    capability: str
    reason: str
    requires_approval: bool = False
    degraded: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


def _validate_concurrency(value: Any) -> int:
    """Concurrent missions are a system-wide cap, not a per-mission ceiling."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CapabilityError("Ceiling 'concurrent_missions' must be an integer.") from exc
    if not 1 <= parsed <= 8:
        raise CapabilityError(
            f"Ceiling 'concurrent_missions'={parsed} is outside 1..8."
        )
    return parsed


def _clamped(value: Any, name: str, floor: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CapabilityError(f"Ceiling '{name}' must be an integer.") from exc
    hard = MODEL_HARD_LIMITS[name]
    if parsed < floor or parsed > hard:
        raise CapabilityError(f"Ceiling '{name}'={parsed} is outside {floor}..{hard}.")
    return parsed


class CapabilityRegistry:
    """Loads ``config/capabilities.yaml`` and evaluates mode/capability requests."""

    def __init__(self, manifest: dict[str, Any] | None = None) -> None:
        self._manifest = manifest or {}
        self._modes: dict[str, ModeDefinition] = {}
        for raw in self._manifest.get("modes", []) or []:
            mode = self._parse_mode(raw)
            self._modes[mode.mode_id] = mode

    # ------------------------------------------------------------------
    # Construction / introspection
    # ------------------------------------------------------------------
    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> CapabilityRegistry:
        from pathlib import Path

        candidate = Path(path)
        if not candidate.exists():
            # Absent manifest means "no widening": only legacy behaviour remains.
            return cls({})
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise CapabilityError("capabilities.yaml must contain a top-level mapping.")
        return cls(data)

    @property
    def manifest_version(self) -> str:
        return str(self._manifest.get("manifest_version", "0"))

    @property
    def enabled(self) -> bool:
        return bool(self._modes)

    def _parse_mode(self, raw: dict[str, Any]) -> ModeDefinition:
        if not isinstance(raw, dict) or not raw.get("id"):
            raise CapabilityError("Every mode requires an 'id'.")
        ceiling_raw = dict(raw.get("ceiling") or {})
        ceiling = ModeCeiling(
            max_hosts=_clamped(ceiling_raw.get("max_hosts", 8), "max_hosts"),
            max_actions=_clamped(ceiling_raw.get("max_actions", 64), "max_actions", floor=1),
            max_seconds=_clamped(ceiling_raw.get("max_seconds", 1800), "max_seconds", floor=10),
            concurrent_missions=_validate_concurrency(
                ceiling_raw.get("concurrent_missions", 2)
            ),
        )
        capabilities = frozenset(str(c) for c in raw.get("capabilities", []))
        mandatory = frozenset(str(c) for c in raw.get("mandatory_capabilities", []))
        missing = mandatory - capabilities
        if missing:
            raise CapabilityError(
                f"Mode '{raw['id']}' declares mandatory capabilities it does not allow: {sorted(missing)}"
            )
        expansion = dict(raw.get("expansion") or {})
        return ModeDefinition(
            mode_id=str(raw["id"]),
            label=str(raw.get("label", raw["id"])),
            summary=str(raw.get("summary", "")).strip(),
            default_skill=str(raw.get("default_skill", "web-surface-audit")),
            ceiling=ceiling,
            capabilities=capabilities,
            mandatory_capabilities=mandatory,
            expansion_clauses=tuple(str(c) for c in expansion.get("allowed_clauses", [])),
            expansion_max=int(expansion.get("max_per_mission", 0) or 0),
            expansion_max_hosts=int(expansion.get("max_hosts_added", 0) or 0),
            expansion_requires_approver=bool(expansion.get("requires_approver", True)),
        )

    def mode_ids(self) -> list[str]:
        return sorted(self._modes)

    def get_mode(self, mode_id: str) -> ModeDefinition:
        mode = self._modes.get(str(mode_id))
        if mode is None:
            raise CapabilityError(
                f"Unknown operational mode '{mode_id}'. Available: {self.mode_ids() or 'none'}."
            )
        return mode

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "id": m.mode_id,
                "label": m.label,
                "summary": m.summary,
                "default_skill": m.default_skill,
                "ceiling": {
                    "max_hosts": m.ceiling.max_hosts,
                    "max_actions": m.ceiling.max_actions,
                    "max_seconds": m.ceiling.max_seconds,
                    "concurrent_missions": m.ceiling.concurrent_missions,
                },
                "capabilities": sorted(m.capabilities),
                "mandatory_capabilities": sorted(m.mandatory_capabilities),
                "expansion": {
                    "allowed_clauses": list(m.expansion_clauses),
                    "max_per_mission": m.expansion_max,
                    "max_hosts_added": m.expansion_max_hosts,
                    "requires_approver": m.expansion_requires_approver,
                },
            }
            for m in sorted(self._modes.values(), key=lambda x: x.mode_id)
        ]

    # ------------------------------------------------------------------
    # Toggles held in the SQLite tool_policy table (admin controlled)
    # ------------------------------------------------------------------
    def db_toggle(self, db: Any) -> dict[str, Any]:
        """Read the optional DB toggle row; absence means 'manifest is authoritative'."""
        row = db.get_tool_policy(CAPABILITY_MODE_POLICY)
        if not row:
            return {"enabled": True, "modes": None}
        allowed = dict(row.get("allowed_params") or {})
        modes = allowed.get("modes")
        return {
            "enabled": bool(row.get("enabled")),
            "modes": [str(m) for m in modes] if isinstance(modes, list) else None,
        }

    def mode_enabled(self, db: Any, mode_id: str) -> tuple[bool, str]:
        toggle = self.db_toggle(db)
        if not toggle["enabled"]:
            return False, "Capability modes are disabled by administrator policy."
        if toggle["modes"] is not None and mode_id not in toggle["modes"]:
            return False, f"Mode '{mode_id}' is not on the administrator's allow-list."
        return True, ""

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def enforce_ceiling(
        self,
        db: Any,
        mode_id: str,
        *,
        target_count: int,
        max_actions: int,
        max_seconds: int,
    ) -> ModeDefinition:
        """Validate a mission plan against the mode ceiling and admin toggle."""
        mode = self.get_mode(mode_id)
        enabled, reason = self.mode_enabled(db, mode_id)
        if not enabled:
            raise CapabilityError(reason)
        if target_count > mode.ceiling.max_hosts:
            raise CapabilityError(
                f"Mode '{mode_id}' allows at most {mode.ceiling.max_hosts} hosts "
                f"(requested {target_count})."
            )
        if max_actions > mode.ceiling.max_actions:
            raise CapabilityError(
                f"Mode '{mode_id}' allows at most {mode.ceiling.max_actions} actions "
                f"(requested {max_actions})."
            )
        if max_seconds > mode.ceiling.max_seconds:
            raise CapabilityError(
                f"Mode '{mode_id}' allows at most {mode.ceiling.max_seconds}s "
                f"(requested {max_seconds})."
            )
        return mode

    def resolve(
        self,
        db: Any,
        mode_id: str,
        capability: str,
        *,
        tool_policy: dict[str, Any] | None = None,
        principal_role: str | None = None,
    ) -> CapabilityDecision:
        """Decide whether `capability` may be used in `mode_id` right now."""
        try:
            mode = self.get_mode(mode_id)
        except CapabilityError as exc:
            return CapabilityDecision(False, mode_id, capability, str(exc))
        enabled, reason = self.mode_enabled(db, mode_id)
        if not enabled:
            return CapabilityDecision(False, mode_id, capability, reason)
        if not mode.allows(capability):
            return CapabilityDecision(
                False,
                mode_id,
                capability,
                f"Mode '{mode_id}' does not include capability '{capability}'.",
            )
        if tool_policy is not None:
            if not tool_policy.get("enabled"):
                return CapabilityDecision(
                    False, mode_id, capability, "The backing tool is disabled by tool policy."
                )
            if tool_policy.get("requires_approval"):
                return CapabilityDecision(
                    True,
                    mode_id,
                    capability,
                    "Capability is available but every use requires Two-Person approval.",
                    requires_approval=True,
                )
        if capability in {"external_tls_adapters", "binary_hardening_triage"}:
            role = (principal_role or "operator").lower()
            return CapabilityDecision(
                True,
                mode_id,
                capability,
                "Elevated capability; restricted to approver/admin principals.",
                requires_approval=True,
                metadata={"allowed_roles": ["approver", "admin"], "role": role},
            )
        if capability in mode.mandatory_capabilities:
            return CapabilityDecision(
                True,
                mode_id,
                capability,
                "Mandatory capability for this mode; runs during every TLS-bearing mission.",
            )
        return CapabilityDecision(True, mode_id, capability, "Permitted by mode policy.")

    def capabilities_for(self, mode_id: str) -> list[str]:
        return sorted(self.get_mode(mode_id).capabilities)

    # ------------------------------------------------------------------
    # Static sections
    # ------------------------------------------------------------------
    def layers(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._manifest.get("layers", []) or []]

    def tls_profile(self) -> dict[str, Any]:
        return dict(self._manifest.get("tls_audit") or {})

    def expansion_policy(self) -> dict[str, Any]:
        return dict(self._manifest.get("expansion") or {})

    def evidence_gate(self) -> dict[str, Any]:
        return dict(self._manifest.get("evidence_gate") or {})

    def session_brief(self, db: Any) -> dict[str, Any]:
        """Session-start protocol payload: scope, modes, layers and TLS status."""
        modes = []
        for mode in sorted(self._modes.values(), key=lambda m: m.mode_id):
            enabled, reason = self.mode_enabled(db, mode.mode_id)
            modes.append(
                {
                    "id": mode.mode_id,
                    "label": mode.label,
                    "enabled": enabled,
                    "disabled_reason": reason,
                    "ceiling": {
                        "max_hosts": mode.ceiling.max_hosts,
                        "max_actions": mode.ceiling.max_actions,
                        "max_seconds": mode.ceiling.max_seconds,
                    },
                    "mandatory_capabilities": sorted(mode.mandatory_capabilities),
                }
            )
        tls = self.tls_profile()
        return {
            "manifest_version": self.manifest_version,
            "modes": modes,
            "layers": self.layers(),
            "tls_audit": {
                "enabled": bool(tls.get("enabled", False)),
                "mandatory_for": [m.mode_id for m in self._modes.values() if "tls_deep_analysis" in m.mandatory_capabilities],
                "protocols": list(tls.get("probe_protocols", [])),
                "minimum_acceptable_protocol": tls.get("minimum_acceptable_protocol"),
                "external_adapters": [
                    str(a.get("id")) for a in tls.get("external_adapters", []) or []
                ],
            },
            "expansion": {
                "enabled": bool(self.expansion_policy().get("enabled", False)),
                "max_pending_per_mission": int(
                    self.expansion_policy().get("max_pending_per_mission", 0) or 0
                ),
                "requires_distinct_approver": bool(
                    self.expansion_policy().get("require_distinct_approver", True)
                ),
            },
            "evidence_gate": {
                "enabled": bool(self.evidence_gate().get("enabled", False)),
                "questions": [
                    {"id": q.get("id"), "prompt": q.get("prompt")}
                    for q in self.evidence_gate().get("questions", []) or []
                ],
            },
        }


def mode_label(registry: CapabilityRegistry, mode_id: str | None) -> str:
    """Human label used in reports; never raises for an unclassified mission."""
    if not mode_id:
        return "unclassified (legacy 2.1 plan)"
    try:
        return registry.get_mode(mode_id).label
    except CapabilityError:
        return f"unknown mode '{mode_id}'"


def summarise_capabilities(decisions: Iterable[CapabilityDecision]) -> dict[str, Any]:
    decisions = list(decisions)
    return {
        "allowed": sorted(d.capability for d in decisions if d.allowed),
        "denied": sorted(d.capability for d in decisions if not d.allowed),
        "approval_required": sorted(
            d.capability for d in decisions if d.allowed and d.requires_approval
        ),
    }
