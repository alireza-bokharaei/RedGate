"""Bash static validator: bash -n + shellcheck JSON + curl/command safety analysis."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from gateway.validators.base import ValidationResult

# Disallow data-exfiltration or arbitrary host-write flags on curl invocations.
FORBIDDEN_CURL_FLAGS_RE = re.compile(
    r"\bcurl\b[^\n]*(?:\s(?:-T|--upload-file|-F|--form|-d|--data|--data-binary|--data-raw|-K|--config)\b|"
    r"\s(?:-o|--output)\s+(?!/tmp/sandbox/|/dev/null)\S+)"
)


def validate_bash_script(
    result: ValidationResult,
    script: str,
    policy: dict[str, Any],
) -> None:
    """Validate Bash syntax, run ShellCheck, and check curl/command constraints."""
    del policy  # Forbidden command regexes are already applied by run_common_checks + below.

    if FORBIDDEN_CURL_FLAGS_RE.search(script):
        result.add_check(
            "bash_curl_safety",
            False,
            "curl uses disallowed upload/POST/config flag or writes outside /tmp/sandbox.",
        )
    else:
        result.add_check(
            "bash_curl_safety",
            True,
            "No unsafe curl upload/POST or host-filesystem output flags detected.",
        )

    with tempfile.TemporaryDirectory(prefix="redgate-val-bash-") as tmpdir:
        script_path = Path(tmpdir) / "candidate.sh"
        script_path.write_text(script, encoding="utf-8")

        # 1. bash -n parser check.
        bash_bin = shutil.which("bash")
        if bash_bin:
            proc = subprocess.run(
                [bash_bin, "-n", str(script_path)],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if proc.returncode != 0:
                result.add_check(
                    "bash_syntax",
                    False,
                    f"bash -n syntax error: {proc.stderr.strip()[:240]}",
                )
                return
            result.add_check("bash_syntax", True, "bash -n syntax check passed.")

        # 2. ShellCheck static analysis (fail closed if shellcheck is missing in strict mode).
        sc_bin = shutil.which("shellcheck")
        if not sc_bin:
            result.add_check(
                "bash_shellcheck",
                False,
                "shellcheck binary not available on gateway; refusing unverified Bash script.",
            )
            return

        sc_proc = subprocess.run(
            [sc_bin, "--shell=bash", "--format=json", "--severity=warning", str(script_path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        findings: list[dict[str, Any]] = []
        if sc_proc.stdout.strip():
            try:
                findings = json.loads(sc_proc.stdout)
            except json.JSONDecodeError:
                result.add_check("bash_shellcheck", False, "Failed to parse shellcheck JSON output.")
                return

        errors = [f for f in findings if f.get("level") == "error"]
        warnings = [f for f in findings if f.get("level") == "warning"]

        for w in warnings[:5]:
            result.warnings.append(
                f"ShellCheck SC{w.get('code')} (line {w.get('line')}): {w.get('message')}"
            )

        if errors:
            summary = "; ".join(
                f"SC{e.get('code')} line {e.get('line')}: {e.get('message')}" for e in errors[:4]
            )
            result.add_check("bash_shellcheck", False, summary)
        elif any(int(w.get("code", 0)) in {2006, 2046, 2086, 2091} for w in warnings):
            # Reject high-risk unquoted expansion / command-execution warnings.
            risky = [w for w in warnings if int(w.get("code", 0)) in {2006, 2046, 2086, 2091}]
            summary = "; ".join(
                f"SC{w.get('code')} line {w.get('line')}: {w.get('message')}" for w in risky[:4]
            )
            result.add_check("bash_shellcheck", False, f"Unsafe expansion rejected: {summary}")
        else:
            detail = (
                f"ShellCheck passed with 0 errors ({len(warnings)} benign warning(s))."
                if warnings
                else "ShellCheck passed cleanly with 0 errors and 0 warnings."
            )
            result.add_check("bash_shellcheck", True, detail)
