"""Live loopback HTTP/TLS regression tests; no external domain is resolved."""

from __future__ import annotations

import asyncio
import json
import secrets
import shutil
import ssl
import subprocess
from contextlib import asynccontextmanager

import httpx
import pytest

from gateway.mcp_client import MCPBridgeClient
from gateway.sandbox_client import GoSandboxClient
from mcp_server.executor import MCPToolExecutor
from mcp_server.tools import ToolParamValidationError


@asynccontextmanager
async def local_http(*, status=200, headers=None, tls=None):
    requests = []

    async def respond(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
            requests.append(request.decode("ascii"))
            fields = {"Content-Length": "0", "Connection": "close", **(headers or {})}
            wire = (
                f"HTTP/1.1 {status} Fixture\r\n"
                + "\r\n".join(f"{k}: {v}" for k, v in fields.items())
                + "\r\n\r\n"
            )
            writer.write(wire.encode())
            await writer.drain()
            # No body is ever sent, including when a huge length is advertised.
            await asyncio.wait_for(reader.read(), timeout=3)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(respond, "127.0.0.1", 0, ssl=tls)
    try:
        yield server.sockets[0].getsockname()[1], requests
    finally:
        server.close()
        await server.wait_closed()


async def probe(port, method="HEAD", scheme="http", pins=None):
    return await MCPToolExecutor().execute(
        tool_name="http_headers",
        target="pin-test.invalid",
        params={"scheme": scheme, "method": method, "port": port, "path": "/original"},
        pinned_ips=["127.0.0.1"] if pins is None else pins,
        timeout_sec=2,
        allowed_params_policy={"allowed_ports": [port]},
    )


async def test_actual_dial_is_pinned_preserves_host_and_does_not_buffer_body():
    async with local_http(
        headers={"Content-Length": "50000000", "X-Content-Type-Options": "nosniff"}
    ) as (port, requests):
        result = await probe(port, method="GET")
        assert result.exit_code == 0 and not result.timed_out, result.stderr
        report = json.loads(result.stdout)
        assert report["connected_ip"] == "127.0.0.1" and report["status_code"] == 200
        assert report["present_security_headers"]["x-content-type-options"] == "nosniff"
        assert f"Host: pin-test.invalid:{port}\r\n" in requests[0]
        assert "Authorization:" not in requests[0] and "Cookie:" not in requests[0]


async def test_pinned_http_does_not_follow_redirects_or_environment_proxies(monkeypatch):
    async with (
        local_http() as (destination, destination_requests),
        local_http() as (proxy, proxy_requests),
    ):
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        async with local_http(
            status=302, headers={"Location": f"http://127.0.0.1:{destination}/"}
        ) as (port, _):
            result = await probe(port)
            assert result.exit_code == 0 and json.loads(result.stdout)["status_code"] == 302
        assert not destination_requests and not proxy_requests


async def test_domain_without_gateway_pin_fails_closed():
    with pytest.raises(ToolParamValidationError, match="DNS pin"):
        await probe(8080, pins=[])


async def test_tls_certificate_is_verified_against_logical_host_and_sni(tmp_path, monkeypatch):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl CLI required to create a disposable TLS certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=pin-test.invalid",
            "-addext",
            "subjectAltName=DNS:pin-test.invalid",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    names = []
    server_context.set_servername_callback(lambda sock, name, context: names.append(name))
    async with local_http(tls=server_context) as (port, requests):
        untrusted = await probe(port, scheme="https")
        assert untrusted.exit_code != 0 and "CERTIFICATE_VERIFY_FAILED" in untrusted.stderr
        original_client = httpx.AsyncClient

        def trust_fixture_ca(**kwargs):
            assert kwargs["verify"] is True and kwargs["trust_env"] is False
            kwargs["verify"] = ssl.create_default_context(cafile=str(cert))
            return original_client(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", trust_fixture_ca)
        trusted = await probe(port, scheme="https")
        assert trusted.exit_code == 0, trusted.stderr
        assert names[-1] == "pin-test.invalid"
        assert f"Host: pin-test.invalid:{port}" in requests[0]


async def test_private_service_tokens_never_use_environment_proxy_transport(monkeypatch):
    token = secrets.token_hex(24)
    requests, settings = [], []

    async def handle(request):
        requests.append(request)
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        assert request.headers["X-Internal-Service-Token"] == token
        if request.url.path == "/mcp":
            data = json.loads(request.content)
            result = (
                {"tools": []} if data["method"] == "tools/list" else {"execution": {"exit_code": 0}}
            )
            return httpx.Response(200, json={"result": result})
        return httpx.Response(200, json={"exit_code": 0})

    original = httpx.AsyncClient

    def client(**kwargs):
        settings.append(kwargs)
        assert kwargs.get("trust_env") is False
        return original(**kwargs, transport=httpx.MockTransport(handle))

    monkeypatch.setattr(httpx, "AsyncClient", client)
    mcp = MCPBridgeClient("http://internal.invalid", token)
    sandbox = GoSandboxClient("http://internal.invalid", token)
    await mcp.health()
    await mcp.list_tools()
    await mcp.call_tool(
        tool_name="http_headers",
        target="127.0.0.1",
        params={},
        max_timeout=1,
        allowed_params={},
        pinned_ips=["127.0.0.1"],
    )
    await sandbox.health()
    await sandbox.capture_http(
        target="127.0.0.1",
        pinned_ips=["127.0.0.1"],
        scheme="http",
        port=8080,
        path="/",
        method="HEAD",
    )
    await sandbox.execute_script(
        language="python",
        script="print('fixture')",
        expected_sha256="a" * 64,
        target="127.0.0.1",
        pinned_ips=["127.0.0.1"],
        egress_allowlist=[],
        timeout_sec=1,
    )
    assert len(requests) == len(settings) == 6
