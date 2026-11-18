"""Scope allowlist validation, engagement RoE window check, and DNS rebinding guard."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from gateway.db import Database

# Cloud metadata endpoints are permanently denied even if an admin tries to add them.
UNCONDITIONALLY_BLOCKED_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.170.2/32"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    # IPv4-mapped IPv6 literals/CIDRs must not hide the same destinations.
    ipaddress.ip_network("::ffff:169.254.169.254/128"),
    ipaddress.ip_network("::ffff:169.254.170.2/128"),
    ipaddress.ip_network("::ffff:100.100.100.200/128"),
)

HOSTNAME_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass
class ScopeCheckResult:
    """Result of evaluating a candidate target against an engagement's allowlist."""

    allowed: bool
    normalized_target: str
    matched_rule: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    egress_allowlist: list[str] = field(default_factory=list)
    reason: str | None = None


def _parse_iso_utc(raw: str) -> dt.datetime:
    cleaned = raw.strip().replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def normalize_target_input(raw: str) -> str:
    """Normalize a target host/IP string while rejecting embedded credentials/paths."""
    text = raw.strip()
    if "://" in text:
        parsed = urlparse(text)
        if parsed.username or parsed.password:
            raise ValueError("Targets must not contain embedded userinfo credentials.")
        if not parsed.hostname:
            raise ValueError(f"Could not extract hostname from '{raw}'.")
        text = parsed.hostname
    text = text.strip().lower().rstrip(".")
    if not text or any(ch.isspace() for ch in text) or text.startswith("-"):
        raise ValueError(f"Malformed target identifier '{raw}'.")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def validate_allowlist_entry_syntax(raw_target: str) -> str:
    """Validate an IP, CIDR, exact domain, or wildcard domain before adding to DB."""
    cleaned = raw_target.strip().lower().rstrip(".")
    # Try IP address.
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        for blocked in UNCONDITIONALLY_BLOCKED_NETS:
            if ip_obj in blocked:
                raise ValueError(f"Cloud metadata address '{cleaned}' is permanently prohibited.")
        return str(ip_obj)
    except ValueError as exc:
        if "permanently prohibited" in str(exc):
            raise

    # Try CIDR network.
    if "/" in cleaned:
        net_obj = ipaddress.ip_network(cleaned, strict=False)
        for blocked in UNCONDITIONALLY_BLOCKED_NETS:
            if net_obj.version == blocked.version and net_obj.overlaps(blocked):
                raise ValueError(
                    f"CIDR '{cleaned}' overlaps blocked cloud metadata range {blocked}."
                )
        if net_obj.prefixlen < 16 and net_obj.version == 4:
            raise ValueError(
                "IPv4 CIDR broader than /16 is refused to prevent accidental overscoping."
            )
        return str(net_obj)

    # Validate exact or single-label wildcard hostname.
    if HOSTNAME_RE.match(cleaned):
        return cleaned
    raise ValueError(
        f"Invalid allowlist entry '{raw_target}'. Expected IP, CIDR (/16..32), domain, or *.domain."
    )


def _match_target_against_rules(target: str, rules: list[str]) -> str | None:
    """Return the matching allowlist rule string, or None if target is out of scope."""
    # Case 1: Target is an IP literal.
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        for rule in rules:
            rule_l = rule.strip().lower()
            try:
                if "/" in rule_l:
                    net = ipaddress.ip_network(rule_l, strict=False)
                    if ip_obj in net:
                        return rule
                else:
                    if ip_obj == ipaddress.ip_address(rule_l):
                        return rule
            except ValueError:
                continue
        return None

    # Case 2: Target is a domain name.
    for rule in rules:
        rule_l = rule.strip().lower().rstrip(".")
        if rule_l == target:
            return rule
        if rule_l.startswith("*."):
            suffix = rule_l[1:]  # e.g., ".lab.example"
            base = rule_l[2:]  # e.g., "lab.example"
            if target != base and target.endswith(suffix):
                return rule
    return None


def _is_explicitly_allowlisted_ip(ip_obj: ipaddress._BaseAddress, rules: list[str]) -> bool:
    for rule in rules:
        try:
            if "/" in rule:
                if ip_obj in ipaddress.ip_network(rule, strict=False):
                    return True
            elif ip_obj == ipaddress.ip_address(rule):
                return True
        except ValueError:
            continue
    return False


class ScopePolicyEngine:
    """Enforces engagement time windows, target allowlists, and DNS rebinding checks."""

    def __init__(self, db: Database, dns_cfg: dict[str, Any] | None = None) -> None:
        self.db = db
        cfg = dns_cfg or {}
        self.block_loopback = bool(cfg.get("block_loopback_by_default", True))
        self.block_link_local = bool(cfg.get("block_link_local_and_metadata", True))
        self.block_multicast = bool(cfg.get("block_multicast", True))
        self.resolve_domains = bool(cfg.get("resolve_domains_at_check_time", True))
        self.strict_dns = os.environ.get("REDGATE_STRICT_DNS_RESOLVE", "false").lower() == "true"

    def evaluate_target(
        self, engagement_id: str, raw_target: str, resolve_dns: bool = True
    ) -> ScopeCheckResult:
        """Check engagement validity, allowlist membership, and DNS-rebinding safety."""
        try:
            target = normalize_target_input(raw_target)
        except ValueError as exc:
            return ScopeCheckResult(allowed=False, normalized_target=raw_target, reason=str(exc))

        # 1. Verify engagement exists, is active, and is within signed RoE window.
        eng = self.db.get_engagement(engagement_id)
        if not eng:
            return ScopeCheckResult(
                allowed=False,
                normalized_target=target,
                reason=f"Engagement '{engagement_id}' does not exist.",
            )
        if not bool(eng["active"]):
            return ScopeCheckResult(
                allowed=False,
                normalized_target=target,
                reason=f"Engagement '{engagement_id}' is inactive.",
            )

        now = dt.datetime.now(dt.timezone.utc)
        valid_from = _parse_iso_utc(eng["valid_from"])
        valid_until = _parse_iso_utc(eng["valid_until"])
        if not (valid_from <= now <= valid_until):
            return ScopeCheckResult(
                allowed=False,
                normalized_target=target,
                reason=(
                    f"Current UTC time is outside signed RoE window for '{engagement_id}' "
                    f"({eng['valid_from']} .. {eng['valid_until']})."
                ),
            )

        # 2. Load active allowlist rules for this engagement ONLY (prevents cross-engagement bleed).
        entries = self.db.list_allowlist(engagement_id=engagement_id, active_only=True)
        rules = [str(e["target"]) for e in entries]
        if not rules:
            return ScopeCheckResult(
                allowed=False,
                normalized_target=target,
                reason=f"Engagement '{engagement_id}' has zero active allowlist entries.",
            )

        # 3. Unconditional metadata check for IP literals.
        ip_literal: ipaddress._BaseAddress | None = None
        try:
            ip_literal = ipaddress.ip_address(target)
        except ValueError:
            ip_literal = None

        if ip_literal is not None:
            meta_err = self._check_ip_safety(ip_literal, rules)
            if meta_err and "metadata" in meta_err:
                return ScopeCheckResult(allowed=False, normalized_target=target, reason=meta_err)

        matched = _match_target_against_rules(target, rules)
        if matched is None:
            return ScopeCheckResult(
                allowed=False,
                normalized_target=target,
                reason=f"Target '{target}' is NOT in active allowlist for engagement '{engagement_id}'.",
            )

        # Collect IP/CIDR rules for Layer 3 sandbox egress firewall.
        ip_egress_rules = [r for r in rules if self._looks_like_ip_or_cidr(r)]

        if ip_literal is not None:
            err = self._check_ip_safety(ip_literal, rules)
            if err:
                return ScopeCheckResult(allowed=False, normalized_target=target, reason=err)
            return ScopeCheckResult(
                allowed=True,
                normalized_target=target,
                matched_rule=matched,
                resolved_ips=[str(ip_literal)],
                egress_allowlist=sorted(set([*ip_egress_rules, str(ip_literal)])),
            )

        # 4. Domain target: resolve DNS once and pin safe IPs to prevent DNS rebinding.
        resolved_ips: list[str] = []
        if resolve_dns and self.resolve_domains:
            try:
                addr_infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
                for info in addr_infos:
                    addr = str(info[4][0])
                    ip_obj = ipaddress.ip_address(addr)
                    err = self._check_ip_safety(ip_obj, rules)
                    if err:
                        return ScopeCheckResult(
                            allowed=False,
                            normalized_target=target,
                            matched_rule=matched,
                            reason=f"DNS rebinding guard blocked '{target}' -> {addr}: {err}",
                        )
                    if addr not in resolved_ips:
                        resolved_ips.append(addr)
            except socket.gaierror:
                if self.strict_dns:
                    return ScopeCheckResult(
                        allowed=False,
                        normalized_target=target,
                        matched_rule=matched,
                        reason=f"DNS resolution failed for '{target}' under strict DNS mode.",
                    )

        return ScopeCheckResult(
            allowed=True,
            normalized_target=target,
            matched_rule=matched,
            resolved_ips=resolved_ips,
            egress_allowlist=sorted(set([*ip_egress_rules, *resolved_ips])),
        )

    def is_literal_host_in_scope(self, engagement_id: str, host: str) -> bool:
        """Fast callback used by static validators to verify embedded URLs/IPs."""
        return self.evaluate_target(engagement_id, host, resolve_dns=False).allowed

    def _check_ip_safety(
        self, ip_obj: ipaddress._BaseAddress, explicit_rules: list[str]
    ) -> str | None:
        for blocked in UNCONDITIONALLY_BLOCKED_NETS:
            if ip_obj in blocked:
                return f"address {ip_obj} is in blocked cloud metadata range {blocked}"
        routed_ip = (
            ip_obj.ipv4_mapped
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped
            else ip_obj
        )
        if routed_ip.is_unspecified:
            return f"address {ip_obj} is unspecified (not an assessment destination)"
        if self.block_link_local and routed_ip.is_link_local:
            return f"address {ip_obj} is link-local (blocked against metadata/rebinding abuse)"
        if self.block_multicast and routed_ip.is_multicast:
            return f"address {ip_obj} is multicast (disallowed)"
        if self.block_loopback and routed_ip.is_loopback:
            if not (
                _is_explicitly_allowlisted_ip(ip_obj, explicit_rules)
                or _is_explicitly_allowlisted_ip(routed_ip, explicit_rules)
            ):
                return f"address {ip_obj} is loopback and not explicitly allowlisted"
        return None

    @staticmethod
    def _looks_like_ip_or_cidr(rule: str) -> bool:
        try:
            if "/" in rule:
                ipaddress.ip_network(rule, strict=False)
            else:
                ipaddress.ip_address(rule)
            return True
        except ValueError:
            return False
