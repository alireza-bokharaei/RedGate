"""Shared types and cross-language security checks for untrusted scripts."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

URL_LITERAL_RE = re.compile(r"https?://[^\s'\"`<>()\[\]{}]+", re.IGNORECASE)
IPV4_LITERAL_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SENSITIVE_FS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("/etc sensitive file", re.compile(r"/etc/(?:passwd|shadow|sudoers|hosts|ssh|crontab)", re.I)),
    ("root/home directory access", re.compile(r"(?<!\w)/(?:root|home|var/log|var/run|boot|sys)/")),
    ("/proc memory/environ access", re.compile(r"/proc/(?:self|\d+)/(?:mem|environ|maps|cmdline|fd)")),
    ("SSH/cloud credential path", re.compile(r"\.(?:ssh|aws|kube|gnupg|docker)/")),
)


@dataclass
class CheckOutcome:
    """Outcome of a single step inside a language validation pipeline."""

    check: str
    passed: bool
    detail: str


@dataclass
class ValidationResult:
    """Aggregated verdict returned by the script validation orchestrator."""

    language: str
    passed: bool
    sha256: str
    checks: list[CheckOutcome] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extracted_hosts: list[str] = field(default_factory=list)

    def add_check(self, name: str, passed: bool, detail: str) -> None:
        self.checks.append(CheckOutcome(check=name, passed=passed, detail=detail))
        if not passed:
            self.passed = False
            self.errors.append(f"[{name}] {detail}")

    def rejection_summary(self) -> str | None:
        if self.passed:
            return None
        return "; ".join(self.errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "passed": self.passed,
            "sha256": self.sha256,
            "checks": [asdict(c) for c in self.checks],
            "errors": self.errors,
            "warnings": self.warnings,
            "extracted_hosts": self.extracted_hosts,
        }


def compute_script_sha256(script: str) -> str:
    """Compute canonical SHA-256 hex digest of the exact script payload."""
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


def run_common_checks(
    result: ValidationResult,
    script: str,
    forbidden_patterns: list[str],
    max_script_bytes: int,
    is_host_allowed: Callable[[str], bool],
) -> None:
    """Apply size, forbidden-regex, filesystem-path, and egress-literal checks."""
    raw_bytes = script.encode("utf-8")
    if not script.strip():
        result.add_check("payload_sanity", False, "Script body is empty.")
        return
    if "\x00" in script:
        result.add_check("payload_sanity", False, "Script contains NUL byte.")
        return
    if len(raw_bytes) > max_script_bytes:
        result.add_check(
            "payload_sanity",
            False,
            f"Script size ({len(raw_bytes)} B) exceeds limit ({max_script_bytes} B).",
        )
        return
    result.add_check("payload_sanity", True, f"Size OK ({len(raw_bytes)} bytes), UTF-8 clean.")

    # Policy forbidden regexes.
    matched_patterns: list[str] = []
    for pat in forbidden_patterns:
        if re.search(pat, script):
            matched_patterns.append(pat)
    if matched_patterns:
        result.add_check(
            "forbidden_patterns",
            False,
            f"Matched forbidden policy pattern(s): {', '.join(matched_patterns[:4])}",
        )
    else:
        result.add_check(
            "forbidden_patterns",
            True,
            f"Cleared {len(forbidden_patterns)} forbidden policy pattern(s).",
        )

    # Sensitive filesystem paths.
    fs_hits = [label for label, rx in SENSITIVE_FS_PATTERNS if rx.search(script)]
    if fs_hits:
        result.add_check(
            "filesystem_confinement",
            False,
            f"References sensitive host path(s): {', '.join(fs_hits)} (only /tmp/sandbox allowed).",
        )
    else:
        result.add_check("filesystem_confinement", True, "No sensitive host filesystem paths detected.")

    # Literal URL/IP egress inspection against engagement allowlist.
    discovered: list[str] = []
    for raw_url in URL_LITERAL_RE.findall(script):
        cleaned_url = raw_url.rstrip(".,;:'\"\\")
        # Skip template variable URLs such as https://$TARGET or https://${host}
        if "$" in cleaned_url or "{" in cleaned_url:
            continue
        parsed = urlparse(cleaned_url)
        if parsed.hostname and parsed.hostname not in discovered:
            discovered.append(parsed.hostname.lower())

    for ip_candidate in IPV4_LITERAL_RE.findall(script):
        try:
            ip_obj = ipaddress.ip_address(ip_candidate)
        except ValueError:
            continue
        # Ignore non-routable placeholder 0.0.0.0 only if not connected; validate all real IPs.
        ip_str = str(ip_obj)
        if ip_str not in discovered:
            discovered.append(ip_str)

    result.extracted_hosts = discovered
    out_of_scope = [host for host in discovered if not is_host_allowed(host)]
    if out_of_scope:
        result.add_check(
            "target_scope_literals",
            False,
            f"Script references out-of-scope host/IP literal(s): {', '.join(out_of_scope)}.",
        )
    else:
        detail = (
            f"All literal hosts in allowlist: {', '.join(discovered)}"
            if discovered
            else "No hardcoded out-of-scope host/IP literals found."
        )
        result.add_check("target_scope_literals", True, detail)
