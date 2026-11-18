"""Persistent, secret-scrubbed Memory Engine for personalized operator workflows.

Supports four operator-curated memory types + automatic run summaries:
  - `methodology`         : How the operator approaches recon & triage (global)
  - `preference`          : Reporting language, severity calibration, focus (global)
  - `false_positive_rule` : Verified noise patterns automatically downgraded on future runs
  - `target_note`         : Architecture context scoped strictly to one engagement_id
  - `run_summary`         : Compact baseline saved after each recon run (engagement-scoped)
"""

from __future__ import annotations

import re
from typing import Any

from gateway.db import Database
from gateway.llm_proxy import LLMProxyGateway


class AgentMemoryEngine:
    """Stores, scrubs, recalls, and applies personalized operator memory."""

    def __init__(self, db: Database, llm_proxy: LLMProxyGateway) -> None:
        self.db = db
        self.llm_proxy = llm_proxy

    def remember(
        self,
        *,
        operator_id: str,
        engagement_id: str | None,
        memory_type: str,
        title: str,
        content: str,
        tags: list[str] | None = None,
        pattern_key: str | None = None,
    ) -> tuple[dict[str, Any], list[str]]:
        """Scrub secrets from title/content and store persistent memory entry."""
        clean_title, s1 = self.llm_proxy.scrub_secrets(title)
        clean_content, s2 = self.llm_proxy.scrub_secrets(content)
        scrubbed = [*s1, *s2]

        # Enforce engagement isolation: target_note and run_summary MUST be scoped.
        if memory_type in {"target_note", "run_summary"} and not engagement_id:
            raise ValueError(f"Memory type '{memory_type}' requires an engagement_id to prevent cross-scope leak.")

        clean_tags = [
            re.sub(r"[^a-z0-9_\-:]", "", t.strip().lower())[:32]
            for t in (tags or [])
            if t.strip()
        ]
        entry = self.db.add_memory(
            operator_id=operator_id,
            engagement_id=engagement_id,
            memory_type=memory_type,
            title=clean_title,
            content=clean_content,
            tags=clean_tags,
            pattern_key=pattern_key,
        )
        return entry, scrubbed

    def recall_for_run(
        self,
        *,
        operator_id: str,
        engagement_id: str,
        target: str,
        operator_focus: str = "",
        max_items: int = 12,
    ) -> list[dict[str, Any]]:
        """Retrieve relevant operator-global + engagement-scoped memories ranked by utility."""
        candidates = self.db.list_memories(
            operator_id=operator_id,
            engagement_id=engagement_id,
            active_only=True,
            limit=100,
        )
        query_tokens = set(
            re.findall(r"[a-z0-9_\-]{3,}", f"{target} {engagement_id} {operator_focus}".lower())
        )

        def _score(mem: dict[str, Any]) -> tuple[int, int]:
            mtype = str(mem["memory_type"])
            # Always prioritize explicit false-positive rules, methodology, and preferences.
            base = {
                "false_positive_rule": 50,
                "methodology": 40,
                "preference": 38,
                "target_note": 35,
                "run_summary": 15,
            }.get(mtype, 10)
            haystack = f"{mem['title']} {mem['content']} {' '.join(mem.get('tags', []))}".lower()
            overlap = sum(6 for tok in query_tokens if tok in haystack)
            if target.lower() in haystack:
                overlap += 18
            return (base + overlap, int(mem["id"]))

        ranked = sorted(candidates, key=_score, reverse=True)
        return ranked[:max_items]

    @staticmethod
    def apply_false_positive_memories(
        findings: list[dict[str, Any]], memories: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Downgrade findings matched by operator-verified `false_positive_rule` memories.

        Findings are NEVER silently deleted: they are marked `suppressed_by_memory` and
        downgraded to `info` so the audit trail and analyst remain in full control.
        """
        fp_rules = [m for m in memories if m.get("memory_type") == "false_positive_rule" and m.get("active")]
        applied: list[dict[str, Any]] = []

        for finding in findings:
            fkey = str(finding.get("finding_key", "")).lower()
            ftitle = str(finding.get("title", "")).lower()
            for rule in fp_rules:
                pkey = str(rule.get("pattern_key") or "").strip().lower()
                if not pkey:
                    continue
                if pkey == fkey or pkey in fkey or pkey in ftitle:
                    finding["suppressed_by_memory"] = f"Memory #{rule['id']}: {rule['title']}"
                    finding["severity"] = "info"
                    finding["priority_score"] = max(5, min(int(finding["priority_score"]), 15))
                    finding["human_judgment_reason"] = (
                        f"Auto-downgraded by your saved Memory rule ({rule['title']}). "
                        "Confirm this assumption still holds for this specific endpoint."
                    )
                    if not any(a["id"] == rule["id"] for a in applied):
                        applied.append(
                            {
                                "id": rule["id"],
                                "memory_type": rule["memory_type"],
                                "title": rule["title"],
                                "effect": f"Downgraded '{finding['finding_key']}' to info",
                            }
                        )
                    break

        # Also record methodology/preference/target_note memories used as prompt context.
        for mem in memories:
            if mem["memory_type"] in {"methodology", "preference", "target_note"}:
                applied.append(
                    {
                        "id": mem["id"],
                        "memory_type": mem["memory_type"],
                        "title": mem["title"],
                        "effect": "Injected into triage & reporting context",
                    }
                )

        return findings, applied

    def format_prompt_context(self, memories: list[dict[str, Any]]) -> str:
        """Render concise, secret-free memory context for the Local LLM prompt."""
        if not memories:
            return "No saved operator memories yet."
        lines: list[str] = []
        for m in memories[:8]:
            scope = f"engagement:{m['engagement_id']}" if m.get("engagement_id") else "global"
            lines.append(
                f"- [{m['memory_type']} | {scope}] {m['title']}: {str(m['content'])[:220]}"
            )
        return "\n".join(lines)
