"""Authenticated client from Layer 1 Gateway to Layer 2 MCP Tool Server."""

from __future__ import annotations

import uuid
from typing import Any

import httpx


class MCPClientError(RuntimeError):
    """Raised on MCP transport failure or JSON-RPC parameter rejection."""

    def __init__(self, message: str, is_param_error: bool = False) -> None:
        super().__init__(message)
        self.is_param_error = is_param_error


class MCPBridgeClient:
    """Invokes Layer 2 MCP tools over JSON-RPC 2.0 with internal service auth."""

    def __init__(self, base_url: str, internal_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._internal_token = internal_token

    async def health(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            return {"status": "unreachable", "error": str(exc)}

    async def list_tools(self) -> list[dict[str, Any]]:
        payload = {"jsonrpc": "2.0", "id": uuid.uuid4().hex[:8], "method": "tools/list", "params": {}}
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{self.base_url}/mcp",
                headers={"X-Internal-Service-Token": self._internal_token},
                json=payload,
            )
            resp.raise_for_status()
            return list(resp.json().get("result", {}).get("tools", []))

    async def call_tool(
        self,
        *,
        tool_name: str,
        target: str,
        params: dict[str, Any],
        max_timeout: int,
        allowed_params: dict[str, Any],
        pinned_ips: list[str],
    ) -> dict[str, Any]:
        arguments = {**params, "target": target}
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex[:10],
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
                "_policy": {
                    "max_timeout": max_timeout,
                    "allowed_params": allowed_params,
                    "pinned_ips": pinned_ips,
                },
            },
        }
        try:
            async with httpx.AsyncClient(timeout=float(max_timeout + 10)) as client:
                resp = await client.post(
                    f"{self.base_url}/mcp",
                    headers={"X-Internal-Service-Token": self._internal_token},
                    json=rpc_payload,
                )
        except httpx.HTTPError as exc:
            raise MCPClientError(f"Layer 2 MCP server unreachable: {exc}") from exc

        if resp.status_code >= 400:
            raise MCPClientError(f"Layer 2 MCP server returned HTTP {resp.status_code}.")
        data = resp.json()
        if "error" in data:
            err = data["error"]
            raise MCPClientError(
                str(err.get("message", "MCP error")),
                is_param_error=(int(err.get("code", 0)) == -32602),
            )
        return dict(data["result"]["execution"])
