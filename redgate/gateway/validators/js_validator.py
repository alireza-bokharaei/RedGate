"""JavaScript (Node.js) validator: node --check + ESLint v9 + module allowlist."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from gateway.validators.base import ValidationResult

# Capture literal require('mod'), import('mod'), and import ... from 'mod'.
LITERAL_REQUIRE_RE = re.compile(r"\brequire\s*\(\s*(['\"])([^'\"]+)\1\s*\)")
DYNAMIC_REQUIRE_RE = re.compile(r"\brequire\s*\(\s*(?!['\"])")
DYNAMIC_IMPORT_RE = re.compile(r"\bimport\s*\(")
ESM_IMPORT_RE = re.compile(
    r"\bimport\s+(?:[\w*{}\s,]+\s+from\s+)?(['\"])([^'\"]+)\1"
)
UNSAFE_JS_GLOBALS_RE = re.compile(
    r"\b(?:Function\s*\(|constructor\s*\.\s*constructor|process\s*\[\s*['\"]|"
    r"globalThis\s*\[|global\s*\[|Reflect\.construct)\b"
)

ESLINT_FLAT_CONFIG = """\
export default [
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        console: "readonly",
        process: "readonly",
        Buffer: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        require: "readonly",
        module: "readonly",
        exports: "readonly"
      }
    },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-with": "error",
      "no-caller": "error",
      "no-proto": "error",
      "no-global-assign": "error",
      "no-undef": "error",
      "no-unreachable": "warn"
    }
  }
];
"""


def validate_js_script(
    result: ValidationResult,
    script: str,
    policy: dict[str, Any],
) -> None:
    """Validate Node.js syntax, enforce strict module allowlist, and run ESLint."""
    node_bin = shutil.which("node")
    if not node_bin:
        result.add_check(
            "js_toolchain",
            False,
            "node binary not installed; refusing unverified JavaScript script.",
        )
        return

    allowed_modules = set(policy.get("allowed_imports", []))

    # 1. Static module allowlist + dynamic import/prototype-escape blocking.
    mod_errors: list[str] = []
    if DYNAMIC_REQUIRE_RE.search(script):
        mod_errors.append("Computed/non-literal require() expression is prohibited.")
    if DYNAMIC_IMPORT_RE.search(script):
        mod_errors.append("Dynamic import() expression is prohibited.")
    if UNSAFE_JS_GLOBALS_RE.search(script):
        mod_errors.append("Dynamic global/constructor property access is prohibited.")

    seen_mods: list[str] = []
    for _, mod in LITERAL_REQUIRE_RE.findall(script):
        seen_mods.append(mod)
        if mod not in allowed_modules:
            mod_errors.append(f"Module '{mod}' is not in JavaScript allowlist.")
    for _, mod in ESM_IMPORT_RE.findall(script):
        seen_mods.append(mod)
        if mod not in allowed_modules:
            mod_errors.append(f"ESM import '{mod}' is not in JavaScript allowlist.")

    if mod_errors:
        result.add_check("js_module_allowlist", False, " ".join(mod_errors[:4]))
        return
    result.add_check(
        "js_module_allowlist",
        True,
        f"Verified modules: {', '.join(sorted(set(seen_mods))) if seen_mods else 'none'}.",
    )

    with tempfile.TemporaryDirectory(prefix="redgate-val-js-") as tmpdir:
        tmp = Path(tmpdir)
        script_path = tmp / "candidate.js"
        script_path.write_text(script, encoding="utf-8")

        # 2. node --check syntax verification.
        chk = subprocess.run(
            [node_bin, "--check", str(script_path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if chk.returncode != 0:
            result.add_check(
                "js_node_check",
                False,
                f"node --check failed: {chk.stderr.strip()[:260]}",
            )
            return
        result.add_check("js_node_check", True, "node --check syntax verification passed.")

        # 3. ESLint security ruleset verification.
        eslint_bin = shutil.which("eslint")
        if not eslint_bin:
            result.add_check(
                "js_eslint",
                False,
                "eslint binary not installed on gateway; refusing unverified JavaScript script.",
            )
            return

        cfg_path = tmp / "eslint.config.mjs"
        cfg_path.write_text(ESLINT_FLAT_CONFIG, encoding="utf-8")

        es_proc = subprocess.run(
            [
                eslint_bin,
                "--no-config-lookup",
                "--config",
                str(cfg_path),
                "--format",
                "json",
                str(script_path),
            ],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        messages: list[dict[str, Any]] = []
        if es_proc.stdout.strip():
            try:
                parsed = json.loads(es_proc.stdout)
                if parsed and isinstance(parsed, list):
                    messages = parsed[0].get("messages", []) or []
            except json.JSONDecodeError:
                result.add_check(
                    "js_eslint",
                    False,
                    f"ESLint returned unparseable output: {es_proc.stderr.strip()[:200]}",
                )
                return
        elif es_proc.returncode != 0:
            result.add_check(
                "js_eslint",
                False,
                f"ESLint execution error: {es_proc.stderr.strip()[:240]}",
            )
            return

        errors = [m for m in messages if int(m.get("severity", 0)) >= 2]
        warns = [m for m in messages if int(m.get("severity", 0)) == 1]
        for w in warns[:5]:
            result.warnings.append(f"ESLint {w.get('ruleId')} (line {w.get('line')}): {w.get('message')}")

        if errors:
            summary = "; ".join(
                f"{e.get('ruleId') or 'syntax'} line {e.get('line')}: {e.get('message')}"
                for e in errors[:4]
            )
            result.add_check("js_eslint", False, summary)
        else:
            result.add_check(
                "js_eslint",
                True,
                f"ESLint passed with 0 errors ({len(warns)} warning(s)).",
            )
