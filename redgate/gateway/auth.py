"""Bearer token SHA-256 authentication, RBAC authorization, and sliding-window rate limiting."""

from __future__ import annotations

import collections
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status


@dataclass(frozen=True)
class OperatorPrincipal:
    """Authenticated operator identity resolved from a Bearer token digest."""

    operator_id: str
    display_name: str
    role: str  # "operator" | "approver" | "admin"
    rate_limit_rpm: int
    quota_period: str
    quota_max_calls: int
    quota_max_tokens: int
    allowed_engagements: tuple[str, ...]

    def can_access_engagement(self, engagement_id: str) -> bool:
        return "*" in self.allowed_engagements or engagement_id in self.allowed_engagements

    def can_approve(self) -> bool:
        return self.role in {"approver", "admin"}

    def is_admin(self) -> bool:
        return self.role == "admin"


class SlidingWindowRateLimiter:
    """Thread-safe per-operator sliding 60-second request rate limiter."""

    def __init__(self, window_sec: float = 60.0) -> None:
        self._window_sec = window_sec
        self._events: dict[str, collections.deque[float]] = collections.defaultdict(
            collections.deque
        )
        self._lock = threading.Lock()

    def allow(self, operator_id: str, max_requests: int) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - self._window_sec
        with self._lock:
            bucket = self._events[operator_id]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= max_requests:
                retry_after = max(1, int(self._window_sec - (now - bucket[0])) + 1)
                return False, retry_after
            bucket.append(now)
            return True, 0


class AuthManager:
    """Resolves Bearer tokens against SHA-256 digests loaded from environment variables."""

    def __init__(self, operators_cfg: dict[str, Any], default_rpm: int = 10) -> None:
        self._principals: list[tuple[str, OperatorPrincipal]] = []
        self._by_id: dict[str, OperatorPrincipal] = {}
        self.rate_limiter = SlidingWindowRateLimiter(window_sec=60.0)

        for entry in operators_cfg.get("operators", []):
            hash_env = str(entry["token_hash_env"])
            token_hash = os.environ.get(hash_env, "").strip().lower()
            q = entry.get("quota", {})
            principal = OperatorPrincipal(
                operator_id=str(entry["operator_id"]),
                display_name=str(entry.get("display_name", entry["operator_id"])),
                role=str(entry.get("role", "operator")),
                rate_limit_rpm=int(entry.get("rate_limit_rpm", default_rpm)),
                quota_period=str(q.get("period", "daily")),
                quota_max_calls=int(q.get("max_calls", 50)),
                quota_max_tokens=int(q.get("max_tokens", 40000)),
                allowed_engagements=tuple(entry.get("allowed_engagements", [])),
            )
            self._by_id[principal.operator_id] = principal
            if len(token_hash) == 64:
                self._principals.append((token_hash, principal))

    def authenticate(self, authorization_header: str | None) -> OperatorPrincipal:
        """Validate `Authorization: Bearer <token>` using constant-time SHA-256 comparison."""
        if not authorization_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization Bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        parts = authorization_header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Authorization header; expected 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        candidate_digest = hashlib.sha256(parts[1].strip().encode("utf-8")).hexdigest()
        matched: OperatorPrincipal | None = None
        for expected_digest, principal in self._principals:
            if hmac.compare_digest(candidate_digest, expected_digest):
                matched = principal
        if matched is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked operator Bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return matched

    def enforce_rate_limit(self, principal: OperatorPrincipal) -> None:
        """Raise HTTP 429 when operator exceeds their configured RPM threshold."""
        allowed, retry_after = self.rate_limiter.allow(
            principal.operator_id, principal.rate_limit_rpm
        )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded for '{principal.operator_id}' "
                    f"({principal.rate_limit_rpm} req/min). Retry in {retry_after}s."
                ),
                headers={"Retry-After": str(retry_after)},
            )

    def list_operators_public(self) -> list[dict[str, Any]]:
        """Return non-sensitive operator metadata (never returns token hashes)."""
        return [
            {
                "operator_id": p.operator_id,
                "display_name": p.display_name,
                "role": p.role,
                "rate_limit_rpm": p.rate_limit_rpm,
                "allowed_engagements": list(p.allowed_engagements),
            }
            for p in self._by_id.values()
        ]
