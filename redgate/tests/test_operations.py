"""Bash operation tests in disposable directories; no Docker daemon is needed."""

from __future__ import annotations

import gzip
import hashlib
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.fixture
def ops(tmp_path):
    app = tmp_path / "app"
    shutil.copytree(ROOT / "scripts", app / "scripts")
    return app


def run(app, script, *args, input=None, env=None):
    return subprocess.run(
        ["bash", str(app / "scripts" / script), *map(str, args)],
        cwd=app,
        env={**os.environ, "REDGATE_SECRETS_GID": str(os.getgid()), **(env or {})},
        capture_output=True,
        text=True,
        input=input,
        timeout=20,
    )


def test_bootstrap_stores_hashes_not_operator_tokens_and_requires_explicit_rotation(ops):
    first = run(ops, "bootstrap_env.sh")
    assert first.returncode == 0, first.stderr
    tokens = re.findall(r": (rg_\w+_[a-f0-9]+)", first.stdout)
    assert len(tokens) == 3
    config = (ops / ".env").read_text()
    assert all(
        token not in config and hashlib.sha256(token.encode()).hexdigest() in config
        for token in tokens
    )
    assert (ops / ".env").stat().st_mode & 0o777 == 0o600
    assert (ops / "secrets").stat().st_mode & 0o777 == 0o750
    assert (ops / "secrets/llm_api_key").stat().st_mode & 0o777 == 0o640
    assert "REDGATE_DEMO_MODE=false" in config and "REDGATE_STRICT_DNS_RESOLVE=true" in config
    assert run(ops, "bootstrap_env.sh").returncode != 0
    assert (ops / ".env").read_text() == config
    assert run(ops, "bootstrap_env.sh", "--force").returncode == 0
    assert (ops / ".env").read_text() != config


def test_sqlite_backup_is_consistent_with_live_wal_and_refuses_overwrite(ops):
    source, target = ops / "live.sqlite", ops / "private backups/snapshot.sqlite.gz"
    conn = sqlite3.connect(source)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE observations (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO observations(value) VALUES (?)", ("unchanged " * 50000,))
        conn.commit()
        assert Path(str(source) + "-wal").exists()
        result = run(ops, "backup_db.sh", "--local", source, target)
        assert result.returncode == 0, result.stderr
        assert target.stat().st_mode & 0o777 == 0o600
        snapshot = ops / "restored.sqlite"
        snapshot.write_bytes(gzip.decompress(target.read_bytes()))
        with sqlite3.connect(snapshot) as restored:
            assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert (
                restored.execute("SELECT value FROM observations").fetchone()
                == conn.execute("SELECT value FROM observations").fetchone()
            )
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        assert digest in result.stdout
        assert run(ops, "backup_db.sh", "--local", source, target).returncode != 0
        assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
        assert not list(target.parent.glob("*.partial.*"))
    finally:
        conn.close()


def test_rotation_is_atomic_private_and_does_not_print_the_key(ops):
    directory = ops / "private keys"
    directory.mkdir(mode=0o750)
    old, new = secrets.token_hex(24), secrets.token_hex(24)
    key = directory / "llm_api_key"
    key.write_text(old)
    key.chmod(0o640)
    result = run(
        ops, "rotate_llm_key.sh", input=new + "\n", env={"REDGATE_SECRET_DIR": str(directory)}
    )
    assert result.returncode == 0, result.stderr
    assert key.read_text() == new and key.stat().st_mode & 0o777 == 0o640
    assert old not in result.stdout and new not in result.stdout
    assert not list(directory.glob(".llm_key.*"))
    assert (
        run(
            ops, "rotate_llm_key.sh", input="short\n", env={"REDGATE_SECRET_DIR": str(directory)}
        ).returncode
        != 0
    )
    assert key.read_text() == new


def test_docker_wrapper_selects_flavor_and_down_never_deletes_volumes(ops):
    binaries, log = ops / "fake-bin", ops / "docker-calls"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text(
        '#!/usr/bin/env bash\nprintf "%s | flavor=%s\\n" "$*" "${REDGATE_IMAGE_FLAVOR:-}" >> "$MOCK_DOCKER_LOG"\n'
    )
    docker.chmod(0o700)
    env = {"PATH": str(binaries) + os.pathsep + os.environ["PATH"], "MOCK_DOCKER_LOG": str(log)}
    assert run(ops, "redgate.sh", "up", "--lite", env=env).returncode == 0
    assert "up -d --build --wait --wait-timeout 180 | flavor=lite" in log.read_text()
    assert run(ops, "redgate.sh", "down", env=env).returncode == 0
    assert "--volumes" not in log.read_text() and "volume rm" not in log.read_text()
    assert run(ops, "redgate.sh", "logs", "--malicious-option", env=env).returncode == 2


def test_compose_security_contract_and_secret_exclusion():
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for name in ("gateway", "mcp-server", "sandbox-runner"):
        service = compose["services"][name]
        assert service["read_only"] and service["init"]
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert "network_mode" not in service and "privileged" not in service
        if name != "gateway":
            assert "ports" not in service
    gateway = compose["services"]["gateway"]
    assert gateway["environment"]["REDGATE_DEMO_MODE"] == "false"
    assert "./secrets:/run/secrets:ro" in gateway["volumes"]
    assert compose["networks"]["control_net"]["internal"]
    ignored = (ROOT / ".dockerignore").read_text()
    for rule in ("**/.env*", "**/secrets", "**/data", "**/node_modules"):
        assert rule in ignored


def test_llm_setup_distinguishes_host_and_container_networks_without_downloading(ops):
    assert run(ops, "bootstrap_env.sh").returncode == 0
    before = (ops / ".env").read_text()
    result = run(ops, "setup_local_llm.sh", "ollama")
    assert result.returncode == 0, result.stderr
    assert "No model downloaded" in result.stdout
    assert "Existing SQLite runtime settings take precedence" in result.stdout
    assert "REDGATE_LLM_BASE_URL=http://ollama:11434/v1" in (ops / ".env").read_text()
    assert run(ops, "setup_local_llm.sh", "--local", "lm_studio").returncode == 0
    changed = (ops / ".env").read_text()
    assert "REDGATE_LLM_BASE_URL=http://127.0.0.1:1234/v1" in changed
    for line in before.splitlines():
        if line.startswith("REDGATE_TOKEN_HASH_") or line.startswith("REDGATE_INTERNAL_TOKEN="):
            assert line in changed
    assert (ops / ".env").stat().st_mode & 0o777 == 0o600
    assert not list(ops.glob(".env.*"))
    assert run(ops, "setup_local_llm.sh", "--compose", "lm_studio").returncode != 0
    assert (ops / ".env").read_text() == changed


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434",
        "http://localhost:11434/v1",
        "http://[::ffff:127.0.0.1]:11434/v1",
        "http://169.254.169.254/",
        "http://[::ffff:100.100.100.200]/",
        "http://user:secret@internal/v1",
        "http://internal/v1?token=secret",
        "http://internal/v1\nINJECTED=value",
        "file:///etc/passwd",
        "http://internal/${PRIVATE_KEY}",
    ],
)
def test_llm_setup_rejects_ambiguous_or_unsafe_compose_endpoints_without_mutation(ops, url):
    assert run(ops, "bootstrap_env.sh").returncode == 0
    before = (ops / ".env").read_bytes()
    result = run(ops, "setup_local_llm.sh", "--base-url", url, "ollama")
    assert result.returncode != 0
    assert (ops / ".env").read_bytes() == before
