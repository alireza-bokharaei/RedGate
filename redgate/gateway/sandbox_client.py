"""Authenticated client from Layer 1 Gateway to Layer 3 Go Sandbox Runner."""

from __future__ import annotations

import uuid
from typing import Any

import httpx


class SandboxClientError(RuntimeError):
    """Raised when the Go sandbox runner is unreachable or refuses a payload."""


class GoSandboxClient:
    """Dispatches SHA-256-verified scripts to the isolated Go sandbox service."""

    def __init__(self, base_url: str, internal_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._internal_token = internal_token

    async def health(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=3.0, trust_env=False) as client:
                resp = await client.get(f"{self.base_url}/health")
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            return {"status": "unreachable", "error": str(exc)}

    async def capture_http(
        self, *, target: str, pinned_ips: list[str], scheme: str, port: int,
        path: str, method: str, timeout_sec: int = 10, max_body_bytes: int = 0,
    ) -> dict[str, Any]:
        """Invoke the fixed read-only Go collector, never an unvalidated script."""
        try:
            async with httpx.AsyncClient(timeout=float(timeout_sec + 3), trust_env=False) as client:
                response = await client.post(
                    f"{self.base_url}/http-evidence",
                    headers={"X-Internal-Service-Token": self._internal_token},
                    json={"target": target, "pinned_ips": pinned_ips, "scheme": scheme,
                          "port": port, "path": path, "method": method,
                          "timeout_sec": timeout_sec, "max_body_bytes": max_body_bytes},
                )
            response.raise_for_status()
            return dict(response.json())
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise SandboxClientError("Go HTTP evidence collector is unavailable or refused the request.") from exc

    async def execute_script(
        self,
        *,
        language: str,
        script: str,
        expected_sha256: str,
        target: str,
        pinned_ips: list[str],
        egress_allowlist: list[str],
        timeout_sec: int,
        memory_limit_mb: int = 128,
        max_output_bytes: int = 65536,
    ) -> dict[str, Any]:
        payload = {
            "job_id": f"job-{uuid.uuid4().hex[:10]}",
            "language": language,
            "script": script,
            "expected_sha256": expected_sha256,
            "target": target,
            "pinned_ips": pinned_ips,
            "egress_allowlist": egress_allowlist,
            "timeout_sec": timeout_sec,
            "memory_limit_mb": memory_limit_mb,
            "max_output_bytes": max_output_bytes,
        }
        try:
            async with httpx.AsyncClient(timeout=float(timeout_sec + 25), trust_env=False) as client:
                resp = await client.post(
                    f"{self.base_url}/execute",
                    headers={"X-Internal-Service-Token": self._internal_token},
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise SandboxClientError(f"Layer 3 Go sandbox runner unreachable: {exc}") from exc

        data = resp.json()
        if resp.status_code >= 500:
            raise SandboxClientError(f"Sandbox runner failure: {data}")
        return dict(data)
