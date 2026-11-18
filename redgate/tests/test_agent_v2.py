"""Tests for Redstrike v2 Personalized Agent, Local Model Hub, Quantization,
Skills, Persistent Memory, Subdomain-to-Report Recon Pipeline, and Human-Judgment Loop.
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

from gateway.config_loader import load_platform_config
from gateway.model_hub import LocalModelHub, validate_llm_endpoint_url
from gateway.skills import SkillValidationError, validate_skill_spec

ROOT_DIR = Path(__file__).resolve().parent.parent


def _sha256(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def test_quantization_calculator_and_hf_gguf_recommendations() -> None:
    cfg = load_platform_config(ROOT_DIR / "config")
    hub = LocalModelHub(cfg.local_models)

    # Consumer system (8 GB VRAM + 16 GB RAM) gets quantized Q4_K_M/Q5_K_M options with HF pull commands
    res = hub.recommend_quantized_models(
        vram_gb=8.0,
        system_ram_gb=16.0,
        context_length=8192,
        task="script_generation",
        custom_hf_repo="Qwen/Qwen2.5-Coder-7B-Instruct-GGUF",
        custom_params_b=7.6,
    )
    assert len(res["recommendations"]) >= 3
    top = res["recommendations"][0]
    assert top["quantization"] in {"Q4_K_M", "Q5_K_M", "Q6_K", "Q8_0"}
    assert "ollama pull hf.co/" in top["commands"]["ollama_pull_hf"]
    assert "lms get " in top["commands"]["lm_studio_cli"]
    assert "PARAMETER num_ctx 8192" in top["modelfile_snippet"]

    # Cloud metadata SSRF blocked on LLM endpoint URL
    with pytest.raises(ValueError, match="metadata"):
        validate_llm_endpoint_url("http://169.254.169.254/v1", "ollama")

    # Ollama and LM Studio localhost endpoints normalize cleanly
    openai_u, native_u = validate_llm_endpoint_url("http://127.0.0.1:11434", "ollama")
    assert openai_u == "http://127.0.0.1:11434/v1"
    assert native_u == "http://127.0.0.1:11434"
    lms_u, _ = validate_llm_endpoint_url("http://127.0.0.1:1234/v1", "lm_studio")
    assert lms_u == "http://127.0.0.1:1234/v1"


def test_skill_validator_blocks_high_risk_tools_and_forces_approval() -> None:
    # Prohibited high-risk tool rejected
    with pytest.raises(SkillValidationError, match="prohibited"):
        validate_skill_spec({"steps": [{"stage": "bad", "tool": "sqlmap", "params": {}}]})

    # Nmap is automatically forced into recommend_approval mode even if mode='execute'
    clean = validate_skill_spec(
        {
            "steps": [
                {"stage": "headers", "tool": "http_headers", "mode": "execute"},
                {"stage": "svc", "tool": "nmap", "mode": "execute"},
            ]
        }
    )
    assert clean["steps"][1]["mode"] == "recommend_approval"


@pytest.fixture(scope="module")
def v2_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, object]]:
    tmp = tmp_path_factory.mktemp("v2")
    internal_tok = secrets.token_hex(24)
    tok_alice = "rg_v2_op_" + secrets.token_hex(12)
    tok_sara = "rg_v2_lead_" + secrets.token_hex(12)
    tok_kaveh = "rg_v2_adm_" + secrets.token_hex(12)

    env = {
        **os.environ,
        "REDGATE_INTERNAL_TOKEN": internal_tok,
        "REDGATE_SANDBOX_ADDR": "127.0.0.1:19002",
        "REDGATE_SANDBOX_URL": "http://127.0.0.1:19002",
        "REDGATE_MCP_URL": "http://127.0.0.1:19001",
        "REDGATE_CONFIG_DIR": str(ROOT_DIR / "config"),
        "REDGATE_SKILLS_DIR": str(ROOT_DIR / "skills"),
        "REDGATE_DB_PATH": str(tmp / "v2.db"),
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
            "19001",
            "--log-level",
            "error",
        ],
        cwd=str(ROOT_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            if (
                httpx.get("http://127.0.0.1:19001/health", timeout=1.0).status_code == 200
                and httpx.get("http://127.0.0.1:19002/health", timeout=1.0).status_code == 200
            ):
                break
        except httpx.HTTPError:
            time.sleep(0.15)
    else:
        sb_proc.terminate()
        mcp_proc.terminate()
        pytest.fail("L2/L3 services failed to start.")

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


def test_memory_learning_skills_model_switch_and_recon_report(
    v2_stack: dict[str, object],
) -> None:
    client: TestClient = v2_stack["client"]  # type: ignore[assignment]
    alice: dict[str, str] = v2_stack["alice"]  # type: ignore[assignment]
    sara: dict[str, str] = v2_stack["sara"]  # type: ignore[assignment]
    kaveh: dict[str, str] = v2_stack["kaveh"]  # type: ignore[assignment]

    # 1. All 4 built-in skills loaded + operator creates a personalized skill.
    skills = client.get("/api/v1/skills", headers=alice).json()["skills"]
    assert len(skills) >= 4
    r_skill = client.post(
        "/api/v1/skills",
        headers=alice,
        json={
            "skill_id": "alice-port-and-header-hunt",
            "name": "Alice Port + Header Recon",
            "description": "Custom paced port check + gated nmap escalation",
            "steps": [
                {"stage": "ports", "tool": "tcp_port_probe", "params": {"ports": [19001, 19002]}},
                {"stage": "svc", "tool": "nmap", "params": {"flags": ["-sV", "-T2"], "ports": "80"}},
            ],
            "prioritization_rules": {"missing_hsts_severity": "high"},
            "report_focus": "Highlight exposed internal service ports for manual verification.",
        },
    )
    assert r_skill.status_code == 201

    # 2. Save operator memory (verify secret scrubbing + engagement scope isolation).
    r_mem = client.post(
        "/api/v1/memory",
        headers=alice,
        json={
            "engagement_id": "ENG-LOCAL-LAB",
            "memory_type": "target_note",
            "title": "Internal lab architecture",
            "content": "Ports 19001/19002 host lab services; api_key=" + "sk-" + "dummyScrubTestOnly9999999",
            "tags": ["lab", "ports"],
        },
    )
    assert r_mem.status_code == 201
    assert "[REDACTED_SECRET]" in r_mem.json()["memory"]["content"]
    assert len(r_mem.json()["scrubbed_secrets"]) >= 1

    # Engagement isolation: ENG-LOCAL-LAB target_note must NOT appear in ENG-2026-001.
    eng1_mems = client.get(
        "/api/v1/memory?engagement_id=ENG-2026-001", headers=alice
    ).json()["memories"]
    assert all(m["engagement_id"] != "ENG-LOCAL-LAB" for m in eng1_mems)

    # Operator isolation: Sara cannot disable Alice's private memory.
    mem_id = r_mem.json()["memory"]["id"]
    assert (
        client.patch(f"/api/v1/memory/{mem_id}", headers=sara, json={"active": False}).status_code
        == 403
    )

    # 3. Run automated recon pipeline with candidate subdomains (in-scope vs out-of-scope).
    r_run1 = client.post(
        "/api/v1/recon/run",
        headers=alice,
        json={
            "engagement_id": "ENG-LOCAL-LAB",
            "target": "127.0.0.1",
            "skill_id": "alice-port-and-header-hunt",
            "candidate_subdomains": ["evil-unscoped.org"],
            "queue_gated_followups": True,
            "operator_focus": "Check non-standard ports and produce full Markdown report.",
        },
    )
    assert r_run1.status_code == 200, r_run1.text
    run1 = r_run1.json()["run"]
    assert run1["summary_stats"]["out_of_scope_skipped"] == 1
    assert len(run1["queued_approvals"]) == 1  # nmap paused for Two-Person review!
    assert len(run1["findings"]) >= 1
    finding = run1["findings"][0]
    assert finding["severity"] == "low"
    assert finding["requires_human_judgment"] is True

    # Markdown report download endpoint works cleanly.
    md_resp = client.get(f"/api/v1/recon/runs/{run1['run_id']}/report.md", headers=alice)
    assert md_resp.status_code == 200
    assert run1["run_id"] in md_resp.text

    # 4. Human judgment feedback loop: mark finding as false_positive + learn_false_positive_rule!
    r_rev = client.patch(
        f"/api/v1/recon/findings/{finding['id']}",
        headers=alice,
        json={
            "verdict": "false_positive",
            "note": "Verified intended internal loopback service ports.",
            "learn_false_positive_rule": True,
        },
    )
    assert r_rev.status_code == 200
    assert r_rev.json()["learned_memory"]["memory_type"] == "false_positive_rule"

    # 5. Re-run recon: Agent automatically recalls learned Memory and downgrades finding to `info`!
    r_run2 = client.post(
        "/api/v1/recon/run",
        headers=alice,
        json={
            "engagement_id": "ENG-LOCAL-LAB",
            "target": "127.0.0.1",
            "skill_id": "alice-port-and-header-hunt",
            "queue_gated_followups": False,
        },
    )
    assert r_run2.status_code == 200
    run2 = r_run2.json()["run"]
    assert run2["summary_stats"]["suppressed_by_memory_count"] == 1
    assert run2["findings"][0]["severity"] == "info"
    assert run2["findings"][0]["suppressed_by_memory"] is not None

    # 6. Hot-switch Local AI runtime to Ollama HF GGUF -> LM Studio -> back to mock (all audited).
    r_ol = client.put(
        "/api/v1/models/runtime",
        headers=kaveh,
        json={
            "provider": "ollama",
            "base_url": "http://127.0.0.1:11434/v1",
            "model": "hf.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF:Q4_K_M",
            "quantization": "Q4_K_M",
            "context_length": 8192,
        },
    )
    assert r_ol.status_code == 200
    assert r_ol.json()["active_runtime"]["active_provider"] == "ollama"

    r_lms = client.put(
        "/api/v1/models/runtime",
        headers=kaveh,
        json={
            "provider": "lm_studio",
            "base_url": "http://127.0.0.1:1234/v1",
            "model": "Qwen/Qwen2.5-Coder-7B-Instruct-GGUF",
            "quantization": "Q5_K_M",
            "context_length": 8192,
        },
    )
    assert r_lms.status_code == 200
    assert r_lms.json()["active_runtime"]["active_provider"] == "lm_studio"

    # Full SHA-256 audit chain remains 100% valid across all v2 agent actions!
    chain = client.get("/api/v1/audit/verify", headers=kaveh).json()
    assert chain["valid"] is True
    assert chain["checked_entries"] >= 8


def test_dual_verification_mcp_plus_go_sandbox_and_claude_code_stdio(
    v2_stack: dict[str, object],
) -> None:
    import json

    client: TestClient = v2_stack["client"]  # type: ignore[assignment]
    alice: dict[str, str] = v2_stack["alice"]  # type: ignore[assignment]
    kaveh: dict[str, str] = v2_stack["kaveh"]  # type: ignore[assignment]

    # Ensure offline mock runtime active for deterministic sandbox script synthesis
    r_mock = client.put(
        "/api/v1/models/runtime",
        headers=kaveh,
        json={
            "provider": "mock",
            "base_url": "http://127.0.0.1:11434/v1",
            "model": "mock-redgate-v2",
            "quantization": "Q4_K_M",
            "context_length": 8192,
        },
    )
    assert r_mock.status_code == 200

    # Spin up a tiny in-process HTTP server on allowed port 8080 with missing security headers
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _MinimalHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    srv = HTTPServer(("127.0.0.1", 8080), _MinimalHandler)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    try:
        r_dual = client.post(
            "/api/v1/recon/run",
            headers=alice,
            json={
                "engagement_id": "ENG-LOCAL-LAB",
                "target": "127.0.0.1",
                "http_scheme_override": "http",
                "http_port_override": 8080,
                "http_path_override": "/",
                "skill_id": "polyglot-sandbox-verify",
                "queue_gated_followups": False,
                "operator_focus": "Cross-confirm missing HTTP security headers with Go sandbox.",
            },
        )
    finally:
        srv.shutdown()
        srv.server_close()

    assert r_dual.status_code == 200, r_dual.text
    dual_run = r_dual.json()["run"]
    assert dual_run["status"] == "completed"
    sandbox_steps = [s for s in dual_run["steps"] if s["tool"] == "sandbox:go"]
    assert len(sandbox_steps) == 1
    assert sandbox_steps[0]["status"] == "completed", sandbox_steps[0]
    assert len(sandbox_steps[0]["confirmed_missing"]) >= 4
    assert dual_run["summary_stats"]["dual_verified_count"] >= 4
    assert any(f["ai_confidence"] >= 0.9 for f in dual_run["findings"])
    assert dual_run["run_id"] in dual_run["report_markdown"]

    # Verify Claude Code stdio MCP server exposes list_recon_skills + all built-in YAML skills
    rpc_lines = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        + "\n"
        + json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "list_recon_skills", "arguments": {}},
            }
        )
        + "\n"
    )
    proc = subprocess.run(
        ["python3", "-m", "mcp_server.stdio_server"],
        cwd=str(ROOT_DIR),
        env={**os.environ, "PYTHONPATH": str(ROOT_DIR), "REDGATE_SKILLS_DIR": str(ROOT_DIR / "skills")},
        input=rpc_lines,
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )
    responses = [json.loads(line) for line in proc.stdout.strip().splitlines() if line.strip()]
    assert len(responses) == 3
    tool_names = {t["name"] for t in responses[1]["result"]["tools"]}
    assert "list_recon_skills" in tool_names
    skills_payload = json.loads(responses[2]["result"]["content"][0]["text"])
    assert len(skills_payload["skills"]) >= 4

