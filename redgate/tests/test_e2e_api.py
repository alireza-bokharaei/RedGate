"""End-to-end integration test across all 3 layers + AI Proxy + Audit Chain.

Spins up the compiled Layer 3 Go sandbox-runner binary and Layer 2 MCP Server
against a temporary SQLite database, then drives Layer 1 FastAPI Gateway through:
  - Out-of-scope rejection + disabled high-risk tool rejection
  - Live MCP tool execution (http_headers / tcp_port_probe)
  - Multi-language AI script generation + validation + Go sandbox execution (Py/Bash/Go/JS)
  - Two-person approval queue workflow (self-approval blocked -> lead approves)
  - Full cryptographic SHA-256 audit chain verification
"""

from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def live_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, object]]:
    tmp = tmp_path_factory.mktemp("e2e")
    internal_tok = secrets.token_hex(24)
    tok_alice = "rg_test_op_" + secrets.token_hex(12)
    tok_sara = "rg_test_lead_" + secrets.token_hex(12)
    tok_kaveh = "rg_test_adm_" + secrets.token_hex(12)

    env = {
        **os.environ,
        "REDGATE_INTERNAL_TOKEN": internal_tok,
        "REDGATE_SANDBOX_ADDR": "127.0.0.1:28002",
        "REDGATE_SANDBOX_URL": "http://127.0.0.1:28002",
        "REDGATE_MCP_URL": "http://127.0.0.1:28001",
        "REDGATE_CONFIG_DIR": str(ROOT_DIR / "config"),
        "REDGATE_DB_PATH": str(tmp / "e2e.db"),
        "REDGATE_TOKEN_HASH_OP_ALICE": _sha256(tok_alice),
        "REDGATE_TOKEN_HASH_LEAD_SARA": _sha256(tok_sara),
        "REDGATE_TOKEN_HASH_ADMIN_KAVEH": _sha256(tok_kaveh),
        "REDGATE_LLM_MODE": "mock",
        "REDGATE_DEMO_MODE": "false",
    }

    sb_proc = subprocess.Popen(
        [str(ROOT_DIR / "bin" / "sandbox-runner")],
        cwd=str(ROOT_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    mcp_proc = subprocess.Popen(
        [
            "python3",
            "-m",
            "uvicorn",
            "mcp_server.http_server:app",
            "--host",
            "127.0.0.1",
            "--port",
            "28001",
            "--log-level",
            "error",
        ],
        cwd=str(ROOT_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for L2 & L3 health endpoints.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            r1 = httpx.get("http://127.0.0.1:28001/health", timeout=1.0)
            r2 = httpx.get("http://127.0.0.1:28002/health", timeout=1.0)
            if r1.status_code == 200 and r2.status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.15)
    else:
        sb_proc.terminate()
        mcp_proc.terminate()
        pytest.fail("Layer 2 or Layer 3 service failed to start in time.")

    # Apply env and construct Gateway TestClient.
    old_env = os.environ.copy()
    os.environ.update(env)
    from gateway.main import build_runtime, create_app

    client = TestClient(create_app(build_runtime()))
    try:
        yield {
            "client": client,
            "alice": {"Authorization": f"Bearer {tok_alice}"},
            "sara": {"Authorization": f"Bearer {tok_sara}"},
            "kaveh": {"Authorization": f"Bearer {tok_kaveh}"},
        }
    finally:
        os.environ.clear()
        os.environ.update(old_env)
        sb_proc.terminate()
        mcp_proc.terminate()
        sb_proc.wait(timeout=5)
        mcp_proc.wait(timeout=5)


def test_full_end_to_end_platform_flow(live_stack: dict[str, object]) -> None:
    client: TestClient = live_stack["client"]  # type: ignore[assignment]
    alice: dict[str, str] = live_stack["alice"]  # type: ignore[assignment]
    sara: dict[str, str] = live_stack["sara"]  # type: ignore[assignment]
    kaveh: dict[str, str] = live_stack["kaveh"]  # type: ignore[assignment]

    # 1. Health reports all 3 layers healthy and demo_mode disabled in production config.
    h = client.get("/api/v1/health").json()
    assert h["mcp_server"]["status"] == "ok"
    assert h["sandbox_runner"]["status"] == "ok"
    assert h["demo_mode"] is False
    assert client.get("/api/v1/demo/bootstrap").status_code == 404

    # 2. Unauthenticated call denied; disabled high-risk tool denied; out-of-scope denied.
    assert client.get("/api/v1/audit").status_code == 401
    r_hydra = client.post(
        "/api/v1/scan",
        headers=alice,
        json={"engagement_id": "ENG-2026-001", "target": "198.51.100.10", "tool_name": "hydra"},
    )
    assert r_hydra.status_code == 403
    r_oos = client.post(
        "/api/v1/scan",
        headers=alice,
        json={"engagement_id": "ENG-2026-001", "target": "203.0.113.77", "tool_name": "http_headers"},
    )
    assert r_oos.status_code == 403

    # 3. Live MCP tool execution: tcp_port_probe against ENG-LOCAL-LAB 127.0.0.1.
    r_probe = client.post(
        "/api/v1/scan",
        headers=alice,
        json={
            "engagement_id": "ENG-LOCAL-LAB",
            "target": "127.0.0.1",
            "tool_name": "tcp_port_probe",
            "params": {"ports": [28001, 28002]},
        },
    )
    assert r_probe.status_code == 200
    assert r_probe.json()["status"] == "completed"
    assert '"state": "open"' in r_probe.json()["execution"]["stdout"]

    # 4. Multi-language AI script generation + secret scrubbing + validation + Go sandbox run
    #    across ALL FOUR required languages: python, bash, go, javascript!
    for lang in ("python", "bash", "go", "javascript"):
        r_gen = client.post(
            "/api/v1/script/generate",
            headers=sara,
            json={
                "engagement_id": "ENG-LOCAL-LAB",
                "target": "127.0.0.1",
                "language": lang,
                "objective": f"Verify HTTP security headers in {lang} (token=secretToken12345)",
                "auto_run": True,
            },
        )
        assert r_gen.status_code == 200, f"{lang} failed: {r_gen.text}"
        body = r_gen.json()
        assert body["validation"]["passed"] is True
        assert len(body["metadata"]["scrubbed_secrets"]) >= 1
        assert body["execution"]["sandbox"]["exit_code"] == 0, body["execution"]

    # 5. Gated tool (nmap) enters approval_queue -> self-approve fails -> admin approves.
    r_nmap = client.post(
        "/api/v1/scan",
        headers=sara,
        json={
            "engagement_id": "ENG-2026-001",
            "target": "198.51.100.10",
            "tool_name": "nmap",
            "params": {"flags": ["-sV", "-T2", "--open"], "ports": "80,443"},
        },
    )
    assert r_nmap.status_code == 202
    req_id = r_nmap.json()["approval"]["request_id"]

    # Sara cannot approve her own request (Two-Person Rule).
    r_self = client.post(
        f"/api/v1/approvals/{req_id}/decide",
        headers=sara,
        json={"decision": "approved", "execute_immediately": False},
    )
    assert r_self.status_code == 403

    # Kaveh (distinct admin) approves cleanly.
    r_ok = client.post(
        f"/api/v1/approvals/{req_id}/decide",
        headers=kaveh,
        json={"decision": "approved", "note": "Approved for low-noise -T2", "execute_immediately": False},
    )
    assert r_ok.status_code == 200
    assert r_ok.json()["approval"]["status"] == "approved"

    # 6. Cryptographic audit chain integrity holds across all operations!
    chain = client.get("/api/v1/audit/verify", headers=kaveh).json()
    assert chain["valid"] is True
    assert chain["checked_entries"] >= 12
