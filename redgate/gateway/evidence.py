"""Anonymous, scope-bound, redacted HTTP observations and conservative retests.

No browser cookies, authentication headers, arbitrary replay, MITM root CA, or
raw credential store is introduced. A checksum covers the REDACTED snapshot;
its digest is also anchored in the append-only audit chain.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

from gateway.auth import OperatorPrincipal
from gateway.db import Database
from gateway.policy import ScopePolicyEngine
from gateway.sandbox_client import GoSandboxClient, SandboxClientError
from gateway.workspace_models import HTTPObservation, HTTPSettings
from gateway.workspace_store import WorkspaceStore
from mcp_server.tools import SECURITY_HEADERS_OF_INTEREST, validate_tool_params

REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[-_]?key|authorization|cookie|session(?:[-_]?id)?|private[-_]?key)"
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[-_]?key|authorization|cookie|session(?:[-_]?id)?)"
    # Also handle quoted keys and incomplete JSON previews cut at the byte cap.
    r"[\"']?\s*[:=]\s*(?:\"[^\"]*(?:\"|$)|'[^']*(?:'|$)|[^\s,;<>]+)"
)
_PATTERNS = (
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\-/=]+"),
    re.compile(
        r"\b(?:sk-[A-Za-z0-9_\-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]+)\b"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)"),
)
_SAFE_HEADERS = frozenset(
    {
        *SECURITY_HEADERS_OF_INTEREST,
        "content-type",
        "content-length",
        "content-encoding",
        "cache-control",
        "date",
        "location",
        "cross-origin-resource-policy",
    }
) - {"server"}


def redact_url(raw: str) -> str:
    try:
        u = urlsplit(raw)
        host = u.hostname or ""
        host = f"[{host}]" if ":" in host else host
        netloc = f"{host}:{u.port}" if u.port else host
        return urlunsplit((u.scheme, netloc, u.path, "REDACTED" if u.query else "", ""))
    except ValueError:
        return REDACTED


def redact_text(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    return re.sub(r"https?://[^\s\"'<>]+", lambda m: redact_url(m.group()), text)


def redact_body(text: str) -> str:
    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: REDACTED if _SECRET_KEY.search(k) else walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return redact_text(value) if isinstance(value, str) else value

    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return redact_text(text)
    try:
        return json.dumps(walk(value), ensure_ascii=True, allow_nan=False)
    except (ValueError, RecursionError):
        # Deeply nested or incomplete documents are never trusted to the parser.
        return REDACTED


def retest_settings(finding: dict[str, Any], run: dict[str, Any] | None) -> HTTPSettings:
    """Resolve ONLY the original, successful HTTP step; never accept a replay URL."""
    key = str(finding["finding_key"])
    header = key.removeprefix("missing:")
    if not key.startswith("missing:") or header not in set(SECURITY_HEADERS_OF_INTEREST) - {
        "server"
    }:
        raise ValueError(
            "Automatic retest supports missing HTTP security headers only; other findings require a manual assessment."
        )
    if (
        not run
        or run["engagement_id"] != finding["engagement_id"]
        or run["root_target"] != finding["asset"]
    ):
        raise ValueError("The finding is not bound to its original engagement and target.")
    step = next(
        (
            s
            for s in run.get("steps", [])
            if s.get("tool") == "http_headers" and s.get("status") == "completed"
        ),
        None,
    )
    if not step or not step.get("params"):
        raise ValueError(
            "The original HTTP endpoint is unavailable; an arbitrary replacement target is not accepted."
        )
    try:
        return HTTPSettings(**{k: step["params"][k] for k in ("scheme", "port", "path", "method")})
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "The original HTTP endpoint is not eligible for an anonymous retest."
        ) from exc


class EvidenceService:
    def __init__(
        self,
        *,
        db: Database,
        store: WorkspaceStore,
        scope: ScopePolicyEngine,
        sandbox: GoSandboxClient,
    ) -> None:
        self.db, self.store, self.scope, self.sandbox = db, store, scope, sandbox

    def consume_quota(self, principal: OperatorPrincipal) -> None:
        ok, reason, _ = self.db.check_and_consume_quota(
            operator_id=principal.operator_id,
            period=principal.quota_period,
            max_calls=principal.quota_max_calls,
            max_tokens=principal.quota_max_tokens,
            calls_delta=1,
        )
        if not ok:
            raise PermissionError(reason or "Operator quota exhausted.")

    async def capture(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        target: str,
        settings: HTTPSettings,
        mission_id: str | None = None,
        run_id: str | None = None,
        before_io: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> dict[str, Any]:
        if not principal.can_access_engagement(engagement_id):
            raise PermissionError("This engagement is not assigned to the operator.")
        scope = await asyncio.to_thread(
            self.scope.evaluate_target, engagement_id, target, resolve_dns=True
        )
        if not scope.allowed:
            raise PermissionError(scope.reason)
        # Unlike legacy tools, evidence never falls back to a fresh resolver at
        # dial time, even when strict DNS mode is disabled for local/offline demos.
        if not scope.resolved_ips:
            raise PermissionError("No safe DNS pin is available; evidence collection fails closed.")
        policy = self.db.get_tool_policy("http_headers")
        if (
            not policy
            or not policy["enabled"]
            or policy["requires_approval"]
            or policy["risk_level"] != "low"
        ):
            raise PermissionError(
                "HTTP evidence requires an enabled, low-risk, non-gated http_headers policy."
            )
        params = validate_tool_params(
            "http_headers", settings.tool_params(), policy["allowed_params"]
        )
        if before_io:
            await before_io("http_evidence", "http_headers")
        else:
            self.consume_quota(principal)
        try:
            raw = await self.sandbox.capture_http(
                target=scope.normalized_target,
                pinned_ips=scope.resolved_ips,
                **params,
                timeout_sec=min(int(policy["max_timeout"]), 15),
                max_body_bytes=settings.body_preview_bytes,
            )
            observation = HTTPObservation.model_validate(raw)
            u = urlsplit(observation.url)
            expected = settings.tool_params()
            if (
                u.hostname != scope.normalized_target
                or u.scheme != settings.scheme
                or (u.port or (443 if u.scheme == "https" else 80)) != expected["port"]
                or (u.path or "/") != settings.path
                or u.query
                or u.fragment
                or u.username is not None
                or u.password is not None
                or observation.method != settings.method
                or ipaddress.ip_address(observation.connected_ip)
                not in {ipaddress.ip_address(p) for p in scope.resolved_ips}
            ):
                raise ValueError(
                    "Evidence worker returned a different endpoint or destination pin."
                )
            response_headers = {
                k.lower(): (redact_url(str(v)) if k.lower() == "location" else redact_text(str(v)))[
                    :8192
                ]
                for k, v in observation.response_headers.items()
                if k.lower() in _SAFE_HEADERS
            }
            if sum(len(v) for v in response_headers.values()) > 32768:
                raise ValueError("Evidence headers exceed their bounded contract.")
            preview = redact_body(observation.body_preview) if settings.body_preview_bytes else ""
            preview_bytes = preview.encode("utf-8")
            cap = settings.body_preview_bytes
            payload = {
                "source": "redgate:go-http-evidence",
                "url": observation.url,
                "method": observation.method,
                "connected_ip": observation.connected_ip,
                "status_code": observation.status_code,
                "request_headers": {
                    "user-agent": "Redstrike/2.1 (Authorized Read-Only Assessment)",
                    "accept-encoding": "identity",
                },
                "response_headers": response_headers,
                "missing_recommended_headers": [
                    h
                    for h in SECURITY_HEADERS_OF_INTEREST
                    if h != "server" and h not in response_headers
                ],
                "body_preview": preview_bytes[:cap].decode("utf-8", errors="ignore") if cap else "",
                "body_truncated": observation.body_truncated or len(preview_bytes) > cap,
                "body_omitted": observation.body_omitted,
                "captured_at": observation.captured_at.isoformat(),
                "duration_ms": observation.duration_ms,
                "redacted": True,
                "tls_verified": settings.scheme == "https",
                "redirects_followed": False,
            }
        except (SandboxClientError, ValueError, TypeError) as exc:
            self.db.write_audit_log(
                engagement_id=engagement_id,
                operator_id=principal.operator_id,
                target=scope.normalized_target,
                tool_or_script="evidence:capture",
                status="error",
                rejection_reason="Evidence worker failed or returned an invalid observation.",
            )
            raise SandboxClientError(
                "Evidence could not be collected or validated; no snapshot was saved."
            ) from exc
        saved = self.store.save_evidence(
            engagement_id=engagement_id,
            captured_by=principal.operator_id,
            target=scope.normalized_target,
            payload=payload,
            mission_id=mission_id,
            run_id=run_id,
        )
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=scope.normalized_target,
            resolved_ips=scope.resolved_ips,
            tool_or_script="evidence:capture",
            status="completed",
            exit_code=0,
            params={
                "evidence_id": saved["evidence_id"],
                "sha256": saved["sha256"],
                "mission_id": mission_id,
                "method": settings.method,
                "body_preview_bytes": settings.body_preview_bytes,
            },
            stdout_summary=f"Redacted HTTP snapshot {saved['evidence_id']} (HTTP {observation.status_code}).",
        )
        return saved

    async def retest(
        self, finding: dict[str, Any], principal: OperatorPrincipal, note: str = ""
    ) -> dict[str, Any]:
        if not principal.can_access_engagement(str(finding["engagement_id"])):
            raise PermissionError("This engagement is not assigned to the operator.")
        run = self.db.get_recon_run(str(finding["run_id"]))
        settings = retest_settings(finding, run)
        header = str(finding["finding_key"]).removeprefix("missing:")
        evidence = await self.capture(
            principal=principal,
            engagement_id=str(finding["engagement_id"]),
            target=str(finding["asset"]),
            settings=settings,
            run_id=str(finding["run_id"]),
        )
        payload = evidence["payload"]
        outcome = "inconclusive"
        explanation = (
            "Non-success HTTP responses do not establish whether the original issue was fixed."
        )
        if 200 <= payload["status_code"] < 300:
            if header == "strict-transport-security" and settings.scheme != "https":
                explanation = "HSTS must be assessed on HTTPS; a plaintext observation cannot establish a fix."
            else:
                outcome = (
                    "not_observed" if header in payload["response_headers"] else "still_present"
                )
                explanation = (
                    "The header is now present; effectiveness and business impact still need human review."
                    if outcome == "not_observed"
                    else "The expected response header is still absent."
                )
        retest = self.store.save_retest(
            finding_id=int(finding["id"]),
            engagement_id=str(finding["engagement_id"]),
            requested_by=principal.operator_id,
            evidence_id=evidence["evidence_id"],
            outcome=outcome,
            note=redact_text(f"{explanation} {note}".strip())[:1000],
        )
        self.db.write_audit_log(
            engagement_id=str(finding["engagement_id"]),
            operator_id=principal.operator_id,
            target=str(finding["asset"]),
            tool_or_script="finding:retest",
            status="completed",
            exit_code=0,
            params={
                "finding_id": finding["id"],
                "retest_id": retest["retest_id"],
                "evidence_id": evidence["evidence_id"],
                "sha256": evidence["sha256"],
                "outcome": outcome,
            },
            stdout_summary="Retest appended; original evidence and analyst verdict were not changed.",
        )
        return {"retest": retest, "evidence": evidence, "requires_human_judgment": True}
