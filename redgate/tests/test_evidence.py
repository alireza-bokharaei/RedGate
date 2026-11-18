"""Anonymous evidence, heuristic redaction, immutable history and safe retests."""

from __future__ import annotations

import hashlib
import json
import socket
import sqlite3

import pytest
from pydantic import ValidationError

from gateway.evidence import redact_body, redact_text
from gateway.policy import ScopeCheckResult
from gateway.sandbox_client import SandboxClientError
from gateway.workspace_models import HTTPSettings
from gateway.workspace_store import canonical_json


async def capture(ws, **changes):
    return await ws.service.evidence.capture(
        principal=ws.owner,
        engagement_id="ENG-A",
        target="127.0.0.1",
        settings=HTTPSettings(**{"scheme": "http", "port": 8080, "path": "/headers", **changes}),
    )


@pytest.mark.parametrize(
    "path",
    [
        "//other.example/",
        "https://other.example/",
        "/?token=secret",
        "/#fragment",
        "/%0a",
        "/%5cother",
        "/%3fsecret",
        "/%GG",
        "/bad\x7f",
        "/非ASCII",
    ],
)
def test_evidence_paths_cannot_carry_queries_credentials_or_control_characters(path):
    with pytest.raises(ValidationError):
        HTTPSettings(path=path)


def test_redaction_handles_nested_json_truncated_keys_and_relative_locations():
    original = json.dumps(
        {
            "password": "hidden-value",
            "nested": {"api_key": "another-value"},
            "safe": "visible",
            "links": ["https://user:pass@unit.example/a?code=third-secret#frag"],
        }
    )
    clean = redact_body(original)
    for secret in ("hidden-value", "another-value", "third-secret", "user:pass"):
        assert secret not in clean
    assert "visible" in clean
    assert "partial-secret" not in redact_body('{"password":"partial-secret')
    assert "partial-secret" not in redact_body('{"api_key": "partial-secret",')
    assert "key-material" not in redact_text("-----BEGIN PRIVATE KEY-----\nkey-material")
    assert "private-token" not in redact_text("Authorization: Bearer private-token")


async def test_capture_is_redacted_bounded_checksummed_and_audit_anchored(ws):
    ws.sandbox.override = {
        "body_preview": json.dumps({"session_id": "private-session", "safe": "visible"}),
        "response_headers": {
            "set-cookie": "session=private-cookie",
            "authorization": "secret-auth",
            "x-private-token": "private-token",
            "content-type": "application/json",
            "location": "/login?code=private-code#private-fragment",
            "content-security-policy": "report-uri https://user:pass@unit.example/report?token=private-report",
        },
    }
    evidence = await capture(ws, method="GET", body_preview_bytes=1024)
    payload = evidence["payload"]
    raw = canonical_json(payload)
    assert evidence["sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert evidence["integrity_valid"] and payload["redacted"]
    for secret in (
        "private-session",
        "private-cookie",
        "secret-auth",
        "private-token",
        "private-code",
        "private-fragment",
        "private-report",
        "user:pass",
    ):
        assert secret not in raw
    assert "visible" in payload["body_preview"]
    assert payload["response_headers"]["location"] == "/login?REDACTED"
    assert set(payload["request_headers"]) == {"user-agent", "accept-encoding"}
    assert ws.sandbox.calls[0]["pinned_ips"] == ["127.0.0.1"]
    assert ws.db.get_or_init_quota("owner", "daily", 1000, 1000000)["used_calls"] == 1
    entries = ws.db.query_audit_log(engagement_id="ENG-A")
    anchor = next(entry for entry in entries if entry["tool_or_script"] == "evidence:capture")
    assert json.loads(anchor["params"])["sha256"] == evidence["sha256"]
    assert ws.db.verify_audit_chain()["valid"]
    for sql in (
        "UPDATE http_evidence SET sha256=? WHERE evidence_id=?",
        "DELETE FROM http_evidence WHERE evidence_id=?",
    ):
        with ws.db.connection() as conn, pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute(
                sql,
                ("0" * 64, evidence["evidence_id"])
                if sql.startswith("UPDATE")
                else (evidence["evidence_id"],),
            )


async def test_default_head_never_persists_body_and_checksum_detects_corruption(ws):
    ws.sandbox.override["body_preview"] = "Do not retain this private response"
    evidence = await capture(ws)
    assert evidence["payload"]["body_preview"] == ""
    assert ws.sandbox.calls[0]["max_body_bytes"] == 0
    # Simulate out-of-band corruption in this disposable DB, bypassing its trigger.
    with ws.db.transaction() as conn:
        conn.execute("DROP TRIGGER evidence_no_update")
        conn.execute(
            "UPDATE http_evidence SET payload_json=? WHERE evidence_id=?",
            ('{"changed":true}', evidence["evidence_id"]),
        )
    assert ws.service.store.get_evidence(evidence["evidence_id"])["integrity_valid"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"connected_ip": "127.0.0.2"},
        {"connected_ip": "not-an-ip"},
        {"url": "http://other.invalid:8080/headers"},
        {"url": "http://:secret@127.0.0.1:8080/headers"},
        {"url": "http://127.0.0.1:8080/headers?token=secret"},
        {"method": "GET"},
        {"status_code": 999},
        {"body_preview": "x" * 8193},
        {"extra": "field"},
    ],
)
async def test_invalid_worker_response_cannot_become_evidence(ws, change):
    ws.sandbox.override.update(change)
    with pytest.raises(SandboxClientError):
        await capture(ws)
    assert ws.service.store.list_evidence("ENG-A") == []
    assert ws.db.get_or_init_quota("owner", "daily", 1000, 1000000)["used_calls"] == 1
    assert ws.db.verify_audit_chain()["valid"]


async def test_missing_dns_pin_and_live_disabled_http_policy_fail_before_io(ws, monkeypatch):
    monkeypatch.setattr(
        ws.rt.scope,
        "evaluate_target",
        lambda *args, **kwargs: ScopeCheckResult(
            allowed=True, normalized_target="unit.lab.example", resolved_ips=[]
        ),
    )
    with pytest.raises(PermissionError, match="DNS pin"):
        await capture(ws)
    assert ws.sandbox.calls == []
    monkeypatch.undo()
    ws.db.update_tool_policy("http_headers", enabled=False)
    with pytest.raises(PermissionError, match="low-risk"):
        await capture(ws)
    assert ws.sandbox.calls == []


async def test_dns_rebinding_to_metadata_is_rejected_before_the_collector(ws, monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))
        ],
    )
    with pytest.raises(PermissionError, match="metadata"):
        await ws.service.evidence.capture(
            principal=ws.owner,
            engagement_id="ENG-A",
            target="unit.lab.example",
            settings=HTTPSettings(),
        )
    assert ws.sandbox.calls == []


@pytest.mark.parametrize(
    "scheme,status,present,outcome",
    [
        ("https", 200, False, "still_present"),
        ("https", 200, True, "not_observed"),
        ("https", 204, True, "not_observed"),
        ("https", 302, True, "inconclusive"),
        ("https", 304, False, "inconclusive"),
        ("https", 500, False, "inconclusive"),
        ("http", 200, True, "inconclusive"),
    ],
)
async def test_retest_reuses_original_endpoint_is_append_only_and_never_changes_verdict(
    ws, scheme, status, present, outcome
):
    run = ws.run(key="missing:strict-transport-security", scheme=scheme)
    finding = run["findings"][0]
    ws.db.review_finding(
        finding_id=finding["id"], verdict="confirmed", note="Original review", reviewed_by="owner"
    )
    ws.sandbox.override.update(
        {
            "status_code": status,
            "response_headers": {"strict-transport-security": "max-age=1000"} if present else {},
        }
    )
    first = await ws.service.evidence.retest(finding, ws.owner, "token=private-note")
    second = await ws.service.evidence.retest(finding, ws.owner)
    assert first["retest"]["outcome"] == second["retest"]["outcome"] == outcome
    assert first["evidence"]["evidence_id"] != second["evidence"]["evidence_id"]
    assert first["requires_human_judgment"]
    assert "private-note" not in first["retest"]["note"]
    assert all(c["path"] == "/original" and c["method"] == "HEAD" for c in ws.sandbox.calls)
    updated = ws.db.get_finding(finding["id"])
    assert (
        updated["analyst_verdict"] == "confirmed" and updated["analyst_note"] == "Original review"
    )
    assert len(ws.service.store.list_retests(finding["id"])) == 2
    for statement in ("UPDATE finding_retests SET note='changed'", "DELETE FROM finding_retests"):
        with ws.db.connection() as conn, pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute(statement)
    assert ws.db.verify_audit_chain()["valid"]


async def test_unsupported_or_missing_original_endpoint_does_not_trigger_a_probe(ws):
    for run in (ws.run(key="ports:non-standard-open"), ws.run(steps=False)):
        response = await ws.client.post(
            f"/api/v1/recon/findings/{run['findings'][0]['id']}/retest",
            headers=ws.headers["owner"],
            json={},
        )
        assert response.status_code == 422
    assert ws.sandbox.calls == []
    request = await ws.client.post(
        "/api/v1/evidence/capture",
        headers=ws.headers["owner"],
        json={"engagement_id": "ENG-A", "target": "127.0.0.1", "headers": {"Cookie": "private"}},
    )
    assert request.status_code == 422 and ws.sandbox.calls == []


async def test_finding_review_retest_and_evidence_authorize_before_mutation_or_io(ws):
    foreign = ws.run(engagement="ENG-B")
    finding_id = foreign["findings"][0]["id"]
    evidence = await ws.service.evidence.capture(
        principal=ws.outsider,
        engagement_id="ENG-B",
        target="127.0.0.1",
        settings=HTTPSettings(scheme="http", port=8080),
    )
    before = len(ws.sandbox.calls)
    for suffix in ("", "/export.json"):
        response = await ws.client.get(
            f"/api/v1/evidence/{evidence['evidence_id']}{suffix}", headers=ws.headers["owner"]
        )
        assert response.status_code == 403
    for suffix in ("/evidence", "/retests"):
        response = await ws.client.get(
            f"/api/v1/recon/findings/{finding_id}{suffix}", headers=ws.headers["owner"]
        )
        assert response.status_code == 403
    assert (
        await ws.client.post(
            f"/api/v1/recon/findings/{finding_id}/retest", headers=ws.headers["owner"], json={}
        )
    ).status_code == 403
    denied_review = await ws.client.patch(
        f"/api/v1/recon/findings/{finding_id}",
        headers=ws.headers["owner"],
        json={"verdict": "false_positive", "learn_false_positive_rule": True},
    )
    assert denied_review.status_code == 403
    assert ws.db.get_finding(finding_id)["analyst_verdict"] == "unreviewed"
    assert ws.db.list_memories(operator_id="owner") == []
    assert len(ws.sandbox.calls) == before
    assert ws.db.verify_audit_chain()["valid"]


async def test_evidence_cannot_reference_a_mission_in_another_engagement(ws):
    mission = ws.plan()
    with pytest.raises(ValueError, match="another engagement"):
        ws.service.store.save_evidence(
            engagement_id="ENG-B",
            captured_by="outsider",
            target="127.0.0.1",
            payload={"url": "http://127.0.0.1:8080/"},
            mission_id=mission["mission_id"],
        )
    assert ws.service.store.list_evidence("ENG-B") == []
