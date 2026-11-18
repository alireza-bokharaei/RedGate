"""Real Gateway -> Go collector -> disposable loopback HTTP integration.

The compiled runner is started by the fixture in evidence-only mode; no external
host, proxy, DNS resolver, model service, browser cookie or Docker is needed.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

from gateway.sandbox_client import GoSandboxClient

ROOT = Path(__file__).parents[1]


@pytest.fixture
async def collector(tmp_path, unused_tcp_port):
    binary = ROOT / "bin/sandbox-runner"
    assert binary.is_file(), "Build bin/sandbox-runner first, or use scripts/verify.sh."
    token = secrets.token_hex(32)
    base = f"http://127.0.0.1:{unused_tcp_port}"
    env = {
        **os.environ,
        "REDGATE_INTERNAL_TOKEN": token,
        "REDGATE_SANDBOX_ADDR": f"127.0.0.1:{unused_tcp_port}",
        "REDGATE_SANDBOX_ROOT": str(tmp_path / "workspace"),
        "REDGATE_SANDBOX_EVIDENCE_ONLY": "true",
        "REDGATE_ENFORCE_IPTABLES": "false",
    }
    process = subprocess.Popen(
        [str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    client = GoSandboxClient(base, token)
    try:
        async with asyncio.timeout(8):
            while (await client.health()).get("status") != "ok":
                assert process.poll() is None, "Collector exited during startup."
                await asyncio.sleep(0.05)
        yield client, token
    finally:
        process.terminate()
        await asyncio.to_thread(process.wait, timeout=5)


@asynccontextmanager
async def target(*, redirect=False):
    requests = []
    security_headers = {}

    async def respond(reader, writer):
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
            requests.append(raw.decode("ascii"))
            body = json.dumps({"password": "fixture-private-password", "safe": "visible"}).encode()
            status = 302 if redirect else 200
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Set-Cookie": "session=fixture-private-cookie",
                "Connection": "close",
                **security_headers,
            }
            if redirect:
                headers["Location"] = "/never-follow?token=fixture-private-query"
            wire = (
                f"HTTP/1.1 {status} Fixture\r\n"
                + "\r\n".join(f"{k}: {v}" for k, v in headers.items())
                + "\r\n\r\n"
            )
            writer.write(wire.encode())
            if not raw.startswith(b"HEAD "):
                writer.write(body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(respond, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1], requests, security_headers
    finally:
        server.close()
        await server.wait_closed()


def allow_test_port(ws, port, client):
    policy = ws.db.get_tool_policy("http_headers")
    ws.db.upsert_tool_policy(
        tool_name="http_headers",
        enabled=True,
        max_timeout=5,
        allowed_params={**policy["allowed_params"], "allowed_ports": [port]},
        risk_level="low",
        requires_approval=False,
        description="Ephemeral local fixture",
    )
    ws.service.evidence.sandbox = client


async def test_real_gateway_go_capture_redacts_without_forwarding_secrets(ws, collector):
    client, token = collector
    async with target() as (port, requests, _):
        allow_test_port(ws, port, client)
        for method, cap in (("HEAD", 0), ("GET", 1024)):
            result = await ws.client.post(
                "/api/v1/evidence/capture",
                headers=ws.headers["owner"],
                json={
                    "engagement_id": "ENG-A",
                    "target": "127.0.0.1",
                    "scheme": "http",
                    "port": port,
                    "path": "/original",
                    "method": method,
                    "body_preview_bytes": cap,
                },
            )
            assert result.status_code == 201, result.text
            evidence = result.json()["evidence"]
            assert (
                evidence["integrity_valid"] and evidence["payload"]["connected_ip"] == "127.0.0.1"
            )
            assert (
                evidence["payload"]["method"] == method
                and evidence["payload"]["status_code"] == 200
            )
            assert evidence["payload"]["source"] == "redgate:go-http-evidence"
            serialized = json.dumps(evidence)
            assert token not in serialized and "fixture-private" not in serialized
            assert (
                "visible" in evidence["payload"]["body_preview"]
                if cap
                else evidence["payload"]["body_preview"] == ""
            )
        assert len(requests) == 2
        for request in requests:
            assert (
                "X-Internal-Service-Token:" not in request
                and "Authorization:" not in request
                and "Cookie:" not in request
            )
            assert f"Host: 127.0.0.1:{port}" in request
        assert ws.db.verify_audit_chain()["valid"]


async def test_real_go_redirect_is_recorded_not_followed(ws, collector):
    client, _ = collector
    async with target(redirect=True) as (port, requests, _):
        allow_test_port(ws, port, client)
        response = await ws.client.post(
            "/api/v1/evidence/capture",
            headers=ws.headers["owner"],
            json={
                "engagement_id": "ENG-A",
                "target": "127.0.0.1",
                "scheme": "http",
                "port": port,
                "path": "/original",
            },
        )
        assert response.status_code == 201, response.text
        payload = response.json()["evidence"]["payload"]
        assert payload["status_code"] == 302 and not payload["redirects_followed"]
        assert payload["response_headers"]["location"] == "/never-follow?REDACTED"
        assert len(requests) == 1 and "never-follow" not in requests[0]


async def test_real_header_retest_appends_both_outcomes_without_changing_verdict(ws, collector):
    client, _ = collector
    async with target() as (port, requests, headers):
        allow_test_port(ws, port, client)
        run = ws.run(scheme="http", port=port)
        finding = run["findings"][0]
        original = ws.db.get_finding(finding["id"])
        first = await ws.client.post(
            f"/api/v1/recon/findings/{finding['id']}/retest",
            headers=ws.headers["owner"],
            json={"note": "Local fixture"},
        )
        assert first.status_code == 201, first.text
        assert first.json()["retest"]["outcome"] == "still_present"
        headers["Content-Security-Policy"] = "default-src 'none'"
        second = await ws.client.post(
            f"/api/v1/recon/findings/{finding['id']}/retest", headers=ws.headers["owner"], json={}
        )
        assert second.status_code == 201, second.text
        assert second.json()["retest"]["outcome"] == "not_observed"
        assert len(ws.service.store.list_retests(finding["id"])) == 2
        assert ws.db.get_finding(finding["id"]) == original
        assert len(requests) == 2 and all(r.startswith("HEAD /original ") for r in requests)


async def test_real_evidence_only_runner_reports_no_languages_and_denies_scripts(collector):
    client, token = collector
    health = await client.health()
    assert health["evidence_only"] and health["languages"] == [] and health["http_evidence"]
    async with httpx.AsyncClient(base_url=client.base_url, trust_env=False) as http:
        assert (await http.post("/execute", json={})).status_code == 401
        assert (
            await http.post("/execute", headers={"X-Internal-Service-Token": token}, json={})
        ).status_code == 403
        assert (await http.post("/http-evidence", json={})).status_code == 401
