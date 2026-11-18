"""Multi-language validation pipeline orchestrator (Python / Bash / Go / JS)."""

from __future__ import annotations

import shutil
from typing import Any, Callable

from gateway.validators.base import ValidationResult, compute_script_sha256, run_common_checks
from gateway.validators.bash_validator import validate_bash_script
from gateway.validators.go_validator import validate_go_script
from gateway.validators.js_validator import validate_js_script
from gateway.validators.python_validator import validate_python_script

SUPPORTED_LANGUAGES: tuple[str, ...] = ("python", "bash", "go", "javascript")
LANGUAGE_ALIASES: dict[str, str] = {
    "py": "python",
    "python": "python",
    "sh": "bash",
    "bash": "bash",
    "go": "go",
    "golang": "go",
    "js": "javascript",
    "node": "javascript",
    "javascript": "javascript",
}


def normalize_language(raw: str) -> str:
    """Normalize a user-provided language identifier or raise ValueError."""
    key = raw.strip().lower()
    if key not in LANGUAGE_ALIASES:
        raise ValueError(
            f"Unsupported script language '{raw}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}."
        )
    return LANGUAGE_ALIASES[key]


class ScriptValidationOrchestrator:
    """Dispatches untrusted scripts through common and language-specific validators."""

    def __init__(self, max_script_bytes: int = 32768) -> None:
        self._max_script_bytes = max_script_bytes

    def validate(
        self,
        language: str,
        script: str,
        script_policy: dict[str, Any],
        is_host_allowed: Callable[[str], bool],
    ) -> ValidationResult:
        """Run full static pipeline and return an auditable ValidationResult."""
        try:
            lang = normalize_language(language)
        except ValueError as exc:
            res = ValidationResult(
                language=language,
                passed=False,
                sha256=compute_script_sha256(script),
            )
            res.add_check("language_support", False, str(exc))
            return res

        result = ValidationResult(
            language=lang,
            passed=True,
            sha256=compute_script_sha256(script),
        )

        if not script_policy.get("enabled", True):
            result.add_check(
                "language_policy",
                False,
                f"Script execution for language '{lang}' is disabled by script_policy.",
            )
            return result

        forbidden_patterns = list(script_policy.get("forbidden_patterns", []))
        run_common_checks(
            result=result,
            script=script,
            forbidden_patterns=forbidden_patterns,
            max_script_bytes=self._max_script_bytes,
            is_host_allowed=is_host_allowed,
        )
        # Always run language-specific validator as well (unless payload itself is invalid)
        # so the operator receives complete diagnostic feedback in a single round-trip.
        if any(c.check == "payload_sanity" and not c.passed for c in result.checks):
            return result

        if lang == "python":
            validate_python_script(result, script, script_policy)
        elif lang == "bash":
            validate_bash_script(result, script, script_policy)
        elif lang == "go":
            validate_go_script(result, script, script_policy)
        elif lang == "javascript":
            validate_js_script(result, script, script_policy)

        return result

    @staticmethod
    def toolchain_status() -> dict[str, bool]:
        """Report availability of every external static analysis tool."""
        return {
            "python_ast": True,
            "bash": shutil.which("bash") is not None,
            "shellcheck": shutil.which("shellcheck") is not None,
            "gofmt": shutil.which("gofmt") is not None,
            "go_vet_build": shutil.which("go") is not None,
            "node_check": shutil.which("node") is not None,
            "eslint": shutil.which("eslint") is not None,
        }
