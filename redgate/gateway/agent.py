"""Personalized, Policy-Bounded Recon, Prioritization & Reporting Agent (Iteration 2).

Executes an end-to-end automated reconnaissance workflow from subdomain/scope
verification to prioritized findings and exportable Markdown reports while keeping
every RedGate Iteration 1 safety invariant intact:
  1. Every root target and candidate subdomain is checked against `allowlist` + DNS guard.
  2. Bounded step count (`max_steps <= 6`) and quota metering — no runaway loops.
  3. Only enabled low-risk MCP tools + validated Go-sandbox scripts execute automatically;
     medium/high-risk follow-ups (e.g., `nmap -T2`) pause in Two-Person `approval_queue`.
  4. Operator Skills + Persistent Memory drive severity calibration and false-positive cuts.
  5. Every finding exposes `ai_confidence`, `dual_verified`, and `requires_human_judgment`
     so the operator knows precisely where human expertise is irreplaceable.
  6. Every stage and the final report are recorded in the SHA-256 hash-chained `audit_log`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
import uuid
from typing import Any

from gateway.db import Database, utc_now_iso
from gateway.llm_proxy import LLMProxyError, LLMProxyGateway
from gateway.mcp_client import MCPBridgeClient, MCPClientError
from gateway.memory import AgentMemoryEngine
from gateway.policy import ScopePolicyEngine
from gateway.sandbox_client import GoSandboxClient, SandboxClientError
from gateway.validators import ScriptValidationOrchestrator

SEVERITY_BASE_SCORE: dict[str, int] = {
    "critical": 95,
    "high": 80,
    "medium": 58,
    "low": 34,
    "info": 14,
}

HEADER_REMEDIATIONS: dict[str, tuple[str, str, bool, str]] = {
    "strict-transport-security": (
        "Missing HTTP Strict-Transport-Security (HSTS)",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.",
        True,
        "Verify whether TLS terminates at an upstream CDN/load-balancer or whether the endpoint serves non-browser internal traffic only.",
    ),
    "content-security-policy": (
        "Missing Content-Security-Policy (CSP)",
        "Deploy a restrictive `Content-Security-Policy` (including `default-src 'self'; frame-ancestors 'none'; object-src 'none'`).",
        True,
        "AI cannot determine if this route renders dynamic HTML/JS (meaningful XSS impact) or returns pure JSON with `nosniff` (often low impact / false positive).",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options Clickjacking Header",
        "Set `X-Frame-Options: DENY` or `SAMEORIGIN` alongside CSP `frame-ancestors`.",
        True,
        "Check if CSP `frame-ancestors` already protects the page or if state-changing UI actions actually exist on this route.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options Header",
        "Return `X-Content-Type-Options: nosniff` on all HTTP/API responses.",
        False,
        "Confirm no legacy browser MIME-sniffing dependency exists before enabling globally.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy Header",
        "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
        False,
        "Assess whether URLs on this asset ever carry sensitive tokens, reset codes, or internal identifiers.",
    ),
    "permissions-policy": (
        "Missing Permissions-Policy Header",
        "Restrict unused browser features, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
        False,
        "Low standalone impact; confirm whether third-party iframes are embedded on this origin.",
    ),
    "cross-origin-opener-policy": (
        "Missing Cross-Origin-Opener-Policy (COOP)",
        "Consider `Cross-Origin-Opener-Policy: same-origin` for sensitive authenticated web apps.",
        True,
        "Verify OAuth/SSO popup flows manually — strict COOP can break legitimate cross-origin auth popups.",
    ),
}


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class PersonalizedReconAgent:
    """Orchestrates Skill + Memory + MCP + Go Sandbox + Local LLM into vetted reports."""

    def __init__(
        self,
        *,
        db: Database,
        scope: ScopePolicyEngine,
        mcp: MCPBridgeClient,
        sandbox: GoSandboxClient,
        validator: ScriptValidationOrchestrator,
        llm: LLMProxyGateway,
        memory: AgentMemoryEngine,
        sandbox_mem_mb: int = 128,
        sandbox_max_output: int = 65536,
    ) -> None:
        self.db = db
        self.scope = scope
        self.mcp = mcp
        self.sandbox = sandbox
        self.validator = validator
        self.llm = llm
        self.memory = memory
        self.sandbox_mem_mb = sandbox_mem_mb
        self.sandbox_max_output = sandbox_max_output

    async def execute_run(
        self,
        *,
        operator_id: str,
        quota_period: str,
        engagement_id: str,
        raw_target: str,
        skill_record: dict[str, Any],
        candidate_subdomains: list[str],
        http_port_override: int | None = None,
        http_scheme_override: str | None = None,
        http_path_override: str | None = None,
        queue_gated_followups: bool = True,
        operator_focus: str = "",
    ) -> dict[str, Any]:
        """Run the full bounded recon-to-report pipeline and persist results + audit chain."""
        run_id = f"rcn-{uuid.uuid4().hex[:12]}"
        started_at = utc_now_iso()
        t0 = time.monotonic()

        root_scope = self.scope.evaluate_target(engagement_id, raw_target, resolve_dns=True)
        if not root_scope.allowed:
            raise PermissionError(root_scope.reason or "Target is outside engagement allowlist.")

        root_target = root_scope.normalized_target
        spec = dict(skill_record["spec"])
        prio_rules = dict(spec.get("prioritization_rules") or {})
        steps_log: list[dict[str, Any]] = []
        queued_approvals: list[str] = []

        # ------------------------------------------------------------------
        # Stage 1: Scope-Controlled Subdomain & Asset Enumeration
        # ------------------------------------------------------------------
        discovered_assets: list[dict[str, Any]] = [
            {
                "asset": root_target,
                "source": "primary_target",
                "in_scope": True,
                "matched_rule": root_scope.matched_rule,
                "resolved_ips": root_scope.resolved_ips,
            }
        ]

        sub_candidates: list[str] = list(candidate_subdomains)
        if (
            spec.get("expand_wildcard_subdomains")
            and not _is_ip_literal(root_target)
            and len(sub_candidates) < 8
        ):
            base_dom = root_target.removeprefix("www.")
            for prefix in spec.get("subdomain_prefixes", []):
                fqdn = f"{prefix}.{base_dom}"
                if fqdn != root_target and fqdn not in sub_candidates:
                    sub_candidates.append(fqdn)

        for cand in sub_candidates[:10]:
            sub_res = self.scope.evaluate_target(engagement_id, cand, resolve_dns=True)
            discovered_assets.append(
                {
                    "asset": sub_res.normalized_target,
                    "source": "subdomain_discovery",
                    "in_scope": sub_res.allowed,
                    "matched_rule": sub_res.matched_rule,
                    "resolved_ips": sub_res.resolved_ips,
                    "note": None if sub_res.allowed else f"Skipped (out of allowlist): {sub_res.reason}",
                }
            )

        # ------------------------------------------------------------------
        # Stage 2: Recall Operator's Persistent Memory (Brain)
        # ------------------------------------------------------------------
        recalled_memories = self.memory.recall_for_run(
            operator_id=operator_id,
            engagement_id=engagement_id,
            target=root_target,
            operator_focus=operator_focus,
        )

        # ------------------------------------------------------------------
        # Stage 3: Execute Bounded Skill Playbook Steps (MCP + Go Sandbox)
        # ------------------------------------------------------------------
        is_ip = _is_ip_literal(root_target)
        open_ports: list[int] = []
        http_observation: dict[str, Any] | None = None
        tls_observation: dict[str, Any] | None = None
        dns_observation: str = ""
        sandbox_confirmed_missing: set[str] = set()
        sandbox_ran_ok = False

        max_steps = min(int(spec.get("max_steps", 6)), 6)
        for step in list(spec.get("steps", []))[:max_steps]:
            stage = str(step["stage"])
            tool = str(step["tool"])
            mode = str(step.get("mode", "execute"))

            if is_ip and step.get("on_ip_target") == "skip":
                steps_log.append(
                    {"stage": stage, "tool": tool, "status": "skipped", "detail": "Target is IP literal."}
                )
                continue

            req_open = step.get("only_if_port_open")
            if req_open is not None and open_ports and int(req_open) not in open_ports:
                steps_log.append(
                    {
                        "stage": stage,
                        "tool": tool,
                        "status": "skipped",
                        "detail": f"Port {req_open} not open on {root_target}.",
                    }
                )
                continue

            # Human-in-the-loop gate for medium/high-risk tools (e.g., nmap -T2).
            if mode == "recommend_approval":
                pol = self.db.get_tool_policy(tool)
                if queue_gated_followups and pol and pol["enabled"]:
                    apr = self.db.enqueue_approval(
                        engagement_id=engagement_id,
                        request_type="tool_scan",
                        target=root_target,
                        tool_or_script=tool,
                        payload={
                            "tool_name": tool,
                            "params": step.get("params", {}),
                            "timeout_sec": int(pol["max_timeout"]),
                            "risk_level": pol["risk_level"],
                            "origin_recon_run": run_id,
                        },
                        requested_by=operator_id,
                    )
                    queued_approvals.append(str(apr["request_id"]))
                    steps_log.append(
                        {
                            "stage": stage,
                            "tool": tool,
                            "status": "queued_for_approval",
                            "approval_id": apr["request_id"],
                            "detail": f"Paused for Two-Person human approval ({apr['request_id']}).",
                        }
                    )
                else:
                    steps_log.append(
                        {
                            "stage": stage,
                            "tool": tool,
                            "status": "skipped",
                            "detail": "Approval follow-up queueing disabled for this run.",
                        }
                    )
                continue

            # Optional Layer 3 Go Sandbox dual-verification step.
            if tool == "sandbox_script":
                lang = str(step.get("params", {}).get("language", "go"))
                obj = str(
                    step.get("params", {}).get(
                        "objective", "Verify HTTP security headers and report missing controls"
                    )
                )
                # Build full verification URL so Layer 3 Go Sandbox hits exact scheme/port/path
                default_local_port = int(os.environ.get("REDGATE_GATEWAY_PORT", "8000"))
                sb_scheme = http_scheme_override or ("https" if 443 in open_ports else "http")
                if http_port_override:
                    sb_port = http_port_override
                    sb_path = http_path_override or "/"
                elif root_target == "127.0.0.1":
                    sb_port = default_local_port
                    sb_path = http_path_override or "/probe/headers"
                else:
                    sb_port = 443 if sb_scheme == "https" else (8000 if 8000 in open_ports and 80 not in open_ports else 80)
                    sb_path = http_path_override or "/"
                sb_host_fmt = f"[{root_target}]" if ":" in root_target else root_target
                sb_url = (
                    f"{sb_scheme}://{sb_host_fmt}{sb_path}"
                    if (sb_scheme == "http" and sb_port == 80) or (sb_scheme == "https" and sb_port == 443)
                    else f"{sb_scheme}://{sb_host_fmt}:{sb_port}{sb_path}"
                )
                sb_step = await self._run_sandbox_verification(
                    operator_id=operator_id,
                    quota_period=quota_period,
                    engagement_id=engagement_id,
                    scope_res=root_scope,
                    target_url=sb_url,
                    language=lang,
                    objective=obj,
                )
                steps_log.append({"stage": stage, "tool": f"sandbox:{lang}", **sb_step})
                if sb_step.get("status") == "completed":
                    sandbox_ran_ok = True
                    sandbox_confirmed_missing.update(sb_step.get("confirmed_missing", []))
                continue

            # Standard enabled low-risk Layer 2 MCP tool invocation.
            pol = self.db.get_tool_policy(tool)
            if not pol or not pol["enabled"]:
                steps_log.append(
                    {"stage": stage, "tool": tool, "status": "blocked", "detail": "Disabled by tool_policy."}
                )
                continue
            if pol["requires_approval"]:
                steps_log.append(
                    {
                        "stage": stage,
                        "tool": tool,
                        "status": "blocked",
                        "detail": "Requires explicit Two-Person approval; skipped autonomous execution.",
                    }
                )
                continue

            call_params = self._build_mcp_step_params(
                tool=tool,
                base_params=dict(step.get("params") or {}),
                target=root_target,
                open_ports=open_ports,
                http_port_override=http_port_override,
                http_scheme_override=http_scheme_override,
                http_path_override=http_path_override,
            )

            try:
                exec_res = await self.mcp.call_tool(
                    tool_name=tool,
                    target=root_target,
                    params=call_params,
                    max_timeout=min(int(pol["max_timeout"]), 20),
                    allowed_params=pol["allowed_params"],
                    pinned_ips=root_scope.resolved_ips,
                )
                exit_code = int(exec_res.get("exit_code", 1))
                stdout = str(exec_res.get("stdout", "")).strip()
                stderr = str(exec_res.get("stderr", "")).strip()
                step_status = "completed" if exit_code == 0 else "failed"
                steps_log.append(
                    {
                        "stage": stage,
                        "tool": tool,
                        "params": call_params,
                        "status": step_status,
                        "duration_ms": int(exec_res.get("duration_ms", 0)),
                        "detail": (stdout[:220] if exit_code == 0 else stderr[:220]),
                    }
                )
                self.db.write_audit_log(
                    engagement_id=engagement_id,
                    operator_id=operator_id,
                    target=root_target,
                    resolved_ips=root_scope.resolved_ips,
                    tool_or_script=f"agent:{run_id}:tool:{tool}",
                    params=call_params,
                    duration_ms=int(exec_res.get("duration_ms", 0)),
                    exit_code=exit_code,
                    stdout_summary=stdout or stderr,
                    status=step_status,
                    rejection_reason=stderr if exit_code != 0 else None,
                )
                if exit_code == 0:
                    if tool == "dns_lookup":
                        dns_observation = stdout
                    elif tool == "tcp_port_probe":
                        parsed = json.loads(stdout)
                        open_ports = [
                            int(r["port"])
                            for r in parsed.get("results", [])
                            if r.get("state") == "open"
                        ]
                    elif tool == "http_headers":
                        http_observation = json.loads(stdout)
                    elif tool == "tls_inspect":
                        tls_observation = json.loads(stdout)
            except (MCPClientError, json.JSONDecodeError) as exc:
                steps_log.append(
                    {"stage": stage, "tool": tool, "status": "failed", "detail": str(exc)[:220]}
                )

        # ------------------------------------------------------------------
        # Stage 4: Evidence Correlation, Dual-Verification & Memory Triage
        # ------------------------------------------------------------------
        raw_findings = self._derive_findings(
            target=root_target,
            dns_obs=dns_observation,
            open_ports=open_ports,
            http_obs=http_observation,
            tls_obs=tls_observation,
            sandbox_ran_ok=sandbox_ran_ok,
            sandbox_missing=sandbox_confirmed_missing,
            prio_rules=prio_rules,
        )
        triaged_findings, memories_applied = self.memory.apply_false_positive_memories(
            raw_findings, recalled_memories
        )
        triaged_findings.sort(key=lambda f: int(f["priority_score"]), reverse=True)

        # ------------------------------------------------------------------
        # Stage 5: Local LLM Synthesis + Exportable Markdown Report
        # ------------------------------------------------------------------
        clean_focus, _ = self.llm.scrub_secrets(operator_focus)
        mem_context = self.memory.format_prompt_context(recalled_memories)
        synthesis, tokens_used, provider_used, model_used = await self.llm.synthesize_recon_triage(
            engagement_id=engagement_id,
            target=root_target,
            skill_name=str(skill_record["name"]),
            report_focus=f"{spec.get('report_focus', '')} {clean_focus}".strip(),
            memory_context=mem_context,
            findings=triaged_findings,
            discovered_assets=discovered_assets,
        )
        self.db.record_llm_tokens(operator_id, quota_period, tokens_used)

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in triaged_findings:
            sv = str(f["severity"])
            sev_counts[sv] = sev_counts.get(sv, 0) + 1

        human_review_count = sum(1 for f in triaged_findings if f.get("requires_human_judgment"))
        suppressed_count = sum(1 for f in triaged_findings if f.get("suppressed_by_memory"))
        dual_count = sum(1 for f in triaged_findings if f.get("dual_verified"))

        summary_stats = {
            "total_findings": len(triaged_findings),
            "severity_counts": sev_counts,
            "requires_human_judgment": human_review_count,
            "dual_verified_count": dual_count,
            "suppressed_by_memory_count": suppressed_count,
            "in_scope_assets": sum(1 for a in discovered_assets if a["in_scope"]),
            "out_of_scope_skipped": sum(1 for a in discovered_assets if not a["in_scope"]),
            "steps_executed": len(steps_log),
            "queued_approvals": len(queued_approvals),
            "llm_tokens_used": tokens_used,
        }

        finished_at = utc_now_iso()
        duration_ms = int((time.monotonic() - t0) * 1000)

        report_md = self._render_markdown_report(
            run_id=run_id,
            engagement_id=engagement_id,
            operator_id=operator_id,
            target=root_target,
            skill_record=skill_record,
            provider_used=provider_used,
            model_used=model_used,
            started_at=started_at,
            duration_ms=duration_ms,
            assets=discovered_assets,
            steps=steps_log,
            findings=triaged_findings,
            memories_applied=memories_applied,
            queued_approvals=queued_approvals,
            synthesis=synthesis,
            stats=summary_stats,
        )

        saved_run = self.db.save_recon_run(
            run_id=run_id,
            engagement_id=engagement_id,
            operator_id=operator_id,
            root_target=root_target,
            skill_id=str(skill_record["skill_id"]),
            llm_provider=provider_used,
            llm_model=model_used,
            status="completed",
            discovered_assets=discovered_assets,
            steps=steps_log,
            memories_applied=memories_applied,
            queued_approvals=queued_approvals,
            summary_stats=summary_stats,
            ai_synthesis=synthesis,
            report_markdown=report_md,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            findings=triaged_findings,
        )

        # Persist compact engagement-scoped baseline memory for longitudinal comparison.
        self.db.add_memory(
            operator_id=operator_id,
            engagement_id=engagement_id,
            memory_type="run_summary",
            title=f"Recon baseline {root_target} ({run_id})",
            content=(
                f"Skill={skill_record['skill_id']}, open_ports={open_ports}, "
                f"findings={len(triaged_findings)} (H:{sev_counts['high']}/M:{sev_counts['medium']}/"
                f"L:{sev_counts['low']}), memory_suppressed={suppressed_count}."
            ),
            tags=[root_target, str(skill_record["skill_id"]), "auto-baseline"],
        )

        audit = self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=operator_id,
            target=root_target,
            resolved_ips=root_scope.resolved_ips,
            tool_or_script=f"agent:recon:{run_id}",
            params={
                "skill_id": skill_record["skill_id"],
                "llm_provider": provider_used,
                "llm_model": model_used,
                "tokens_used": tokens_used,
                "queued_approvals": queued_approvals,
            },
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            exit_code=0,
            stdout_summary=(
                f"Recon {run_id} completed: {len(triaged_findings)} findings "
                f"({dual_count} dual-verified, {suppressed_count} downgraded by memory, "
                f"{human_review_count} flagged for human judgment)."
            ),
            status="completed",
        )
        saved_run["audit_id"] = audit["id"]
        saved_run["audit_hash"] = audit["entry_hash"]
        return saved_run

    async def _run_sandbox_verification(
        self,
        *,
        operator_id: str,
        quota_period: str,
        engagement_id: str,
        scope_res: Any,
        target_url: str,
        language: str,
        objective: str,
    ) -> dict[str, Any]:
        s_pol = self.db.get_script_policy(language)
        if not s_pol or not s_pol["enabled"]:
            return {"status": "skipped", "detail": f"Language '{language}' disabled."}
        try:
            artifact = await self.llm.generate_script(
                engagement_id=engagement_id,
                target=target_url,
                language=language,
                objective=objective,
                script_policy=s_pol,
            )
            self.db.record_llm_tokens(operator_id, quota_period, artifact.tokens_used)
            val = self.validator.validate(
                language=language,
                script=artifact.script,
                script_policy=s_pol,
                is_host_allowed=lambda h: self.scope.is_literal_host_in_scope(engagement_id, h),
            )
            if not val.passed:
                return {"status": "validation_failed", "detail": val.rejection_summary() or "rejected"}

            sb_res = await self.sandbox.execute_script(
                language=language,
                script=artifact.script,
                expected_sha256=val.sha256,
                target=scope_res.normalized_target,
                pinned_ips=scope_res.resolved_ips,
                egress_allowlist=scope_res.egress_allowlist,
                timeout_sec=min(artifact.expected_runtime_sec, int(s_pol["max_runtime_sec"])),
                memory_limit_mb=self.sandbox_mem_mb,
                max_output_bytes=self.sandbox_max_output,
            )
            exit_code = int(sb_res.get("exit_code", 1))
            stdout = str(sb_res.get("stdout", "")).strip()
            self.db.write_audit_log(
                engagement_id=engagement_id,
                operator_id=operator_id,
                target=scope_res.normalized_target,
                resolved_ips=scope_res.resolved_ips,
                tool_or_script="agent:sandbox_verify",
                language=language,
                params={"sha256": val.sha256},
                duration_ms=int(sb_res.get("duration_ms", 0)),
                exit_code=exit_code,
                stdout_summary=stdout[:1024],
                status="completed" if exit_code == 0 else "failed",
            )
            confirmed: list[str] = []
            if exit_code == 0 and stdout.startswith("{"):
                try:
                    parsed = json.loads(stdout)
                    confirmed = [str(h).lower() for h in parsed.get("missing", [])]
                except json.JSONDecodeError:
                    pass
            return {
                "status": "completed" if exit_code == 0 else "failed",
                "duration_ms": int(sb_res.get("duration_ms", 0)),
                "confirmed_missing": confirmed,
                "detail": f"Validated & ran {language} script in Go sandbox (sha256={val.sha256[:10]}…, confirmed {len(confirmed)} missing headers).",
            }
        except (LLMProxyError, SandboxClientError) as exc:
            return {"status": "failed", "detail": str(exc)[:220]}

    @staticmethod
    def _build_mcp_step_params(
        *,
        tool: str,
        base_params: dict[str, Any],
        target: str,
        open_ports: list[int],
        http_port_override: int | None,
        http_scheme_override: str | None,
        http_path_override: str | None,
    ) -> dict[str, Any]:
        if tool != "http_headers":
            return base_params
        if target == "127.0.0.1":
            scheme = http_scheme_override or "http"
            port = http_port_override or int(os.environ.get("REDGATE_GATEWAY_PORT", "8000"))
            path = http_path_override or "/probe/headers"
        else:
            if http_port_override:
                port = http_port_override
                scheme = http_scheme_override or ("https" if port in {443, 8443} else "http")
            elif 443 in open_ports or not open_ports:
                port = 443
                scheme = http_scheme_override or "https"
            elif 80 in open_ports:
                port = 80
                scheme = http_scheme_override or "http"
            else:
                port = open_ports[0]
                scheme = http_scheme_override or ("https" if port == 8443 else "http")
            path = http_path_override or str(base_params.get("path", "/"))
        return {
            "scheme": scheme,
            "method": str(base_params.get("method", "GET")),
            "port": port,
            "path": path,
        }

    @staticmethod
    def _derive_findings(
        *,
        target: str,
        dns_obs: str,
        open_ports: list[int],
        http_obs: dict[str, Any] | None,
        tls_obs: dict[str, Any] | None,
        sandbox_ran_ok: bool,
        sandbox_missing: set[str],
        prio_rules: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        # 1. HTTP defensive header findings with Skill calibration + Sandbox dual-verification.
        if http_obs:
            url = str(http_obs.get("url", target))
            status_code = http_obs.get("status_code")
            present = dict(http_obs.get("present_security_headers") or {})
            for hdr in http_obs.get("missing_recommended_headers", []):
                h_low = str(hdr).lower()
                meta = HEADER_REMEDIATIONS.get(h_low)
                if not meta:
                    continue
                title, remediation, needs_human, human_why = meta
                sev = _header_severity(h_low, prio_rules)
                dual = sandbox_ran_ok and (h_low in sandbox_missing)
                confidence = 0.95 if dual else 0.78
                score = min(99, SEVERITY_BASE_SCORE[sev] + (8 if dual else 0))
                ev_suffix = (
                    " Independently cross-confirmed by validated Go script in Layer 3 Sandbox."
                    if dual
                    else ""
                )
                findings.append(
                    {
                        "asset": target,
                        "category": "http_hardening",
                        "finding_key": f"missing:{h_low}",
                        "title": title,
                        "severity": sev,
                        "priority_score": score,
                        "ai_confidence": confidence,
                        "dual_verified": dual,
                        "evidence": (
                            f"{url} returned HTTP {status_code} without `{h_low}` "
                            f"(present: {', '.join(sorted(present.keys())) or 'none'}).{ev_suffix}"
                        ),
                        "remediation": remediation,
                        "requires_human_judgment": needs_human,
                        "human_judgment_reason": human_why,
                    }
                )

            if "server" in present:
                findings.append(
                    {
                        "asset": target,
                        "category": "fingerprinting",
                        "finding_key": "exposed:server-banner",
                        "title": "Server Software Banner Disclosed in HTTP Header",
                        "severity": "info",
                        "priority_score": 18,
                        "ai_confidence": 0.90,
                        "dual_verified": False,
                        "evidence": f"{url} advertised `Server: {present['server']}`.",
                        "remediation": "Suppress version-specific `Server` tokens at reverse proxy if policy requires.",
                        "requires_human_judgment": True,
                        "human_judgment_reason": "Often a generic CDN/proxy label rather than a real vulnerability; verify if an exact outdated version is leaked.",
                    }
                )

        # 2. TLS certificate & protocol posture.
        if tls_obs:
            tls_ver = str(tls_obs.get("tls_version") or "")
            days_left = tls_obs.get("days_until_expiry")
            if tls_ver in {"TLSv1", "TLSv1.1"}:
                sev = str(prio_rules.get("legacy_tls_severity", "high"))
                findings.append(
                    {
                        "asset": target,
                        "category": "tls_posture",
                        "finding_key": f"tls:legacy-{tls_ver.lower()}",
                        "title": f"Deprecated TLS Protocol Negotiated ({tls_ver})",
                        "severity": sev,
                        "priority_score": SEVERITY_BASE_SCORE[sev] + 5,
                        "ai_confidence": 0.93,
                        "dual_verified": False,
                        "evidence": f"{target}:{tls_obs.get('port')} negotiated {tls_ver} ({tls_obs.get('cipher_suite')}).",
                        "remediation": "Disable TLS 1.0/1.1 and enforce TLS 1.2+ (prefer TLS 1.3).",
                        "requires_human_judgment": True,
                        "human_judgment_reason": "Verify if legacy industrial/partner clients require a compensating migration window.",
                    }
                )
            if isinstance(days_left, int) and days_left <= int(prio_rules.get("expiring_cert_days_medium", 30)):
                high_thr = int(prio_rules.get("expiring_cert_days_high", 14))
                sev = "high" if days_left <= high_thr else "medium"
                findings.append(
                    {
                        "asset": target,
                        "category": "tls_posture",
                        "finding_key": "tls:cert-expiring-soon",
                        "title": f"TLS Certificate Expires in {days_left} Days",
                        "severity": sev,
                        "priority_score": SEVERITY_BASE_SCORE[sev],
                        "ai_confidence": 0.97,
                        "dual_verified": False,
                        "evidence": f"Leaf certificate `notAfter={tls_obs.get('not_after')}` ({days_left} days remaining).",
                        "remediation": "Verify automated ACME/PKI renewal pipeline before certificate expiry.",
                        "requires_human_judgment": True,
                        "human_judgment_reason": "Short-lived automated certs (e.g. Let's Encrypt) renew at <30 days normally; check auto-renewal status.",
                    }
                )

        # 3. Exposed non-standard TCP ports baseline.
        non_std = [p for p in open_ports if p not in {80, 443}]
        if non_std:
            findings.append(
                {
                    "asset": target,
                    "category": "attack_surface",
                    "finding_key": "ports:non-standard-open",
                    "title": f"Non-Standard TCP Service Port(s) Open: {', '.join(map(str, non_std))}",
                    "severity": "low",
                    "priority_score": 38,
                    "ai_confidence": 0.88,
                    "dual_verified": False,
                    "evidence": f"Paced TCP probe found open port(s) {open_ports} on {target}.",
                    "remediation": "Confirm each non-443 listener is intentionally exposed and protected by authentication + network ACLs.",
                    "requires_human_judgment": True,
                    "human_judgment_reason": "Only a human operator with engagement context knows whether alternate ports are intended admin/staging interfaces.",
                }
            )

        if dns_obs and not findings:
            findings.append(
                {
                    "asset": target,
                    "category": "dns_baseline",
                    "finding_key": "dns:resolved-records",
                    "title": "DNS Surface Baseline Recorded",
                    "severity": "info",
                    "priority_score": 12,
                    "ai_confidence": 0.95,
                    "dual_verified": False,
                    "evidence": f"Resolved records: {dns_obs.replace(chr(10), ', ')[:200]}",
                    "remediation": "Review resolved IPs for unexpected third-party or dangling subdomain mappings.",
                    "requires_human_judgment": True,
                    "human_judgment_reason": "Confirm ownership of every resolved subnet against asset inventory.",
                }
            )

        return findings

    @staticmethod
    def _render_markdown_report(
        *,
        run_id: str,
        engagement_id: str,
        operator_id: str,
        target: str,
        skill_record: dict[str, Any],
        provider_used: str,
        model_used: str,
        started_at: str,
        duration_ms: int,
        assets: list[dict[str, Any]],
        steps: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        memories_applied: list[dict[str, Any]],
        queued_approvals: list[str],
        synthesis: str,
        stats: dict[str, Any],
    ) -> str:
        sc = stats["severity_counts"]
        lines = [
            f"# RedGate Automated Recon & Triage Report — `{run_id}`",
            "",
            f"- **Engagement**: `{engagement_id}` | **Primary Target**: `{target}`",
            f"- **Operator**: `{operator_id}` | **Skill Playbook**: `{skill_record['name']}` (`{skill_record['skill_id']}`)",
            f"- **Local AI Engine**: `{provider_used}` / `{model_used}` (Tokens: `{stats['llm_tokens_used']}`, Offline/Private Ready)",
            f"- **Started (UTC)**: `{started_at}` | **Duration**: `{duration_ms} ms`",
            f"- **Summary**: **{stats['total_findings']}** findings (`High: {sc['high']}`, `Medium: {sc['medium']}`, `Low: {sc['low']}`, `Info: {sc['info']}`) · **{stats['dual_verified_count']}** dual-verified in Go Sandbox · **{stats['suppressed_by_memory_count']}** adjusted by Memory",
            "",
            "---",
            "",
            "## 1. AI Analyst Synthesis (Personalized by Skill & Memory)",
            "",
            synthesis,
            "",
            "## 2. Scope & Subdomain Verification",
            "",
            "| Asset | Source | In Scope | Matched Rule | Pinned IPs / Note |",
            "|---|---|---|---|---|",
        ]
        for a in assets:
            note = ", ".join(a.get("resolved_ips") or []) or (a.get("note") or "—")
            lines.append(
                f"| `{a['asset']}` | {a['source']} | {'YES' if a['in_scope'] else 'BLOCKED'} | "
                f"`{a.get('matched_rule') or '—'}` | {note} |"
            )

        lines.extend(
            [
                "",
                "## 3. Prioritized Findings",
                "",
                "| Priority | Severity | Finding | Confidence | Dual-Verified | Human Judgment |",
                "|---:|---|---|---:|---|---|",
            ]
        )
        for f in findings:
            sup = " *(Memory rule)*" if f.get("suppressed_by_memory") else ""
            lines.append(
                f"| **{f['priority_score']}** | `{f['severity'].upper()}` | {f['title']}{sup} | "
                f"`{int(float(f['ai_confidence']) * 100)}%` | {'YES (MCP+Go)' if f['dual_verified'] else 'MCP'} | "
                f"{'REQUIRED' if f['requires_human_judgment'] else 'Optional'} |"
            )

        lines.extend(["", "### Detailed Evidence & Where Human Judgment Is Irreplaceable", ""])
        for idx, f in enumerate(findings, start=1):
            lines.append(f"#### {idx}. [{f['severity'].upper()} · Score {f['priority_score']}] {f['title']}")
            lines.append(f"- **Evidence**: {f['evidence']}")
            if f.get("suppressed_by_memory"):
                lines.append(f"- **Memory Adjustment**: {f['suppressed_by_memory']}")
            lines.append(f"- **Remediation**: {f['remediation']}")
            lines.append(f"- **Human Analyst Check**: {f['human_judgment_reason']}")
            lines.append("")

        lines.append("## 4. Operator Memory Applied")
        if memories_applied:
            for m in memories_applied:
                lines.append(f"- **[`{m['memory_type']}`]** {m['title']} — *{m['effect']}*")
        else:
            lines.append("- No custom operator memory rules matched on this run.")

        lines.extend(["", "## 5. Execution Trace & Two-Person Approval Gates", ""])
        for s in steps:
            lines.append(f"- **`{s['stage']}`** (`{s['tool']}`) → `{s['status']}`: {s.get('detail', '')}")
        if queued_approvals:
            lines.append(
                f"\n> **Pending Human Approval**: Deeper service checks paused in `approval_queue` as `{', '.join(queued_approvals)}` (Two-Person Rule enforced)."
            )

        lines.extend(
            [
                "",
                "---",
                "*Notice: Automated reconnaissance cannot evaluate business logic, authorization (IDOR/BOLA), or compensating controls, and provides no stealth guarantee. Review every `REQUIRED` item before reporting.*",
            ]
        )
        return "\n".join(lines)


def _header_severity(header_name: str, rules: dict[str, Any]) -> str:
    mapping = {
        "strict-transport-security": str(rules.get("missing_hsts_severity", "medium")),
        "content-security-policy": str(rules.get("missing_csp_severity", "medium")),
        "x-frame-options": "low",
        "x-content-type-options": str(rules.get("missing_xcto_severity", "low")),
        "referrer-policy": "low",
        "permissions-policy": str(rules.get("missing_permissions_policy_severity", "low")),
        "cross-origin-opener-policy": str(rules.get("missing_coop_severity", "info")),
    }
    return mapping.get(header_name, "low")
