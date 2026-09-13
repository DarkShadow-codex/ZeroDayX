"""Deterministic Scope Engine for ZeroDay v2.0.

Enforces fail-closed target boundaries across domains, subdomains, IP/CIDR ranges,
ports, protocols, URLs, and repository paths.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ScopeDecision:
    """Decision outcome from scope evaluation."""

    allowed: bool
    reason: str
    target: str
    matched_rule: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "target": self.target,
            "matched_rule": self.matched_rule,
        }


@dataclass
class ScopeConfig:
    """Configuration defining authorized testing boundaries."""

    allowed_domains: list[str] = field(default_factory=list)
    denied_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)  # single IPs or CIDRs
    denied_ips: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    denied_ports: list[int] = field(default_factory=list)
    allowed_protocols: list[str] = field(default_factory=lambda: ["http", "https"])
    denied_protocols: list[str] = field(default_factory=list)
    allowed_urls: list[str] = field(default_factory=list)
    denied_urls: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    denied_paths: list[str] = field(default_factory=list)
    max_requests_per_minute: int = 300


class ScopeEngine:
    """Deterministic, fail-closed security boundary for all network and tool actions."""

    def __init__(self, config: ScopeConfig | None = None) -> None:
        self.config = config or ScopeConfig()
        self._parsed_allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._parsed_denied_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._request_timestamps: list[float] = []
        self._compile_cidrs()

    def _compile_cidrs(self) -> None:
        self._parsed_allowed_cidrs = self._parse_networks(self.config.allowed_ips)
        self._parsed_denied_cidrs = self._parse_networks(self.config.denied_ips)

    @staticmethod
    def _parse_networks(
        ip_specs: list[str],
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for spec in ip_specs:
            spec = spec.strip()
            if not spec:
                continue
            try:
                networks.append(ipaddress.ip_network(spec, strict=False))
            except ValueError:
                logger.warning("Invalid IP or CIDR in scope config: %s", spec)
        return networks

    def check_rate_limit(self) -> ScopeDecision:
        """Verify that current request rate is within configured limits."""
        now = time.time()
        one_minute_ago = now - 60.0
        self._request_timestamps = [ts for ts in self._request_timestamps if ts > one_minute_ago]

        if len(self._request_timestamps) >= self.config.max_requests_per_minute:
            return ScopeDecision(
                allowed=False,
                reason=f"Rate limit exceeded: {len(self._request_timestamps)} requests in last 60s (max: {self.config.max_requests_per_minute})",
                target="rate_limit",
            )
        self._request_timestamps.append(now)
        return ScopeDecision(allowed=True, reason="Within rate limit", target="rate_limit")

    def is_in_scope(
        self,
        target: str,
        *,
        port: int | None = None,
        protocol: str | None = None,
    ) -> ScopeDecision:
        """Determine deterministically whether a target is permitted.

        Fail-closed: if the target is empty, malformed, or doesn't explicitly
        match allowed criteria, access is denied.
        """
        if not target or not isinstance(target, str):
            return ScopeDecision(
                allowed=False,
                reason="Fail closed: empty or invalid target string",
                target=str(target),
            )

        cleaned_target = target.strip()
        if not cleaned_target:
            return ScopeDecision(
                allowed=False,
                reason="Fail closed: blank target string",
                target=cleaned_target,
            )

        # 1. If target is a full URL, parse and evaluate protocol, port, host, and path
        if "://" in cleaned_target:
            return self._check_url(cleaned_target)

        # 2. Check if target has port appended (e.g. host:port)
        if ":" in cleaned_target and not cleaned_target.startswith("["):
            parts = cleaned_target.rsplit(":", 1)
            if parts[1].isdigit():
                cleaned_target = parts[0]
                if port is None:
                    port = int(parts[1])

        # 3. Check Port restrictions if port is specified
        if port is not None:
            port_decision = self._check_port(port, cleaned_target)
            if not port_decision.allowed:
                return port_decision

        # 4. Check Protocol restrictions if protocol is specified
        if protocol is not None:
            proto_decision = self._check_protocol(protocol, cleaned_target)
            if not proto_decision.allowed:
                return proto_decision

        # 5. Check if target is an IP address
        try:
            ip_obj = ipaddress.ip_address(cleaned_target)
            return self._check_ip(ip_obj, cleaned_target)
        except ValueError:
            pass  # Not a raw IP; proceed to domain / host check

        # 6. Check domain / hostname
        return self._check_domain(cleaned_target)

    def _check_port(self, port: int, target: str) -> ScopeDecision:
        if self.config.denied_ports and port in self.config.denied_ports:
            return ScopeDecision(
                allowed=False,
                reason=f"Port {port} is explicitly denied in scope",
                target=target,
                matched_rule=f"denied_port:{port}",
            )
        if self.config.allowed_ports and port not in self.config.allowed_ports:
            return ScopeDecision(
                allowed=False,
                reason=f"Port {port} is not in allowed ports list",
                target=target,
                matched_rule="allowed_ports_restriction",
            )
        return ScopeDecision(allowed=True, reason=f"Port {port} allowed", target=target)

    def _check_protocol(self, protocol: str, target: str) -> ScopeDecision:
        proto = protocol.lower().rstrip(":")
        if self.config.denied_protocols and proto in [
            p.lower() for p in self.config.denied_protocols
        ]:
            return ScopeDecision(
                allowed=False,
                reason=f"Protocol {proto} is explicitly denied in scope",
                target=target,
                matched_rule=f"denied_protocol:{proto}",
            )
        if self.config.allowed_protocols and proto not in [
            p.lower() for p in self.config.allowed_protocols
        ]:
            return ScopeDecision(
                allowed=False,
                reason=f"Protocol {proto} is not in allowed protocols list",
                target=target,
                matched_rule="allowed_protocols_restriction",
            )
        return ScopeDecision(allowed=True, reason=f"Protocol {proto} allowed", target=target)

    def _check_ip(
        self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, target: str
    ) -> ScopeDecision:
        for net in self._parsed_denied_cidrs:
            if ip_obj in net:
                return ScopeDecision(
                    allowed=False,
                    reason=f"IP {target} matches denied CIDR {net}",
                    target=target,
                    matched_rule=str(net),
                )

        # If allowed IPs configured, must match at least one
        if self._parsed_allowed_cidrs:
            for net in self._parsed_allowed_cidrs:
                if ip_obj in net:
                    return ScopeDecision(
                        allowed=True,
                        reason=f"IP {target} matches allowed CIDR {net}",
                        target=target,
                        matched_rule=str(net),
                    )
            return ScopeDecision(
                allowed=False,
                reason=f"IP {target} is not in any allowed CIDR range",
                target=target,
            )

        # If no allowed IPs are specified, check if domain scope is also empty
        if not self.config.allowed_domains and not self.config.allowed_urls:
            return ScopeDecision(
                allowed=False,
                reason="Fail closed: no allowed domains, URLs, or IPs configured in scope",
                target=target,
            )
        return ScopeDecision(
            allowed=False,
            reason=f"Raw IP {target} not authorized when only domain scope is defined",
            target=target,
        )

    def _check_domain(self, domain: str) -> ScopeDecision:
        norm_domain = domain.lower().strip(".")

        # Check denied domains first
        for denied in self.config.denied_domains:
            norm_denied = denied.lower().strip(".")
            if self._domain_matches(norm_domain, norm_denied):
                return ScopeDecision(
                    allowed=False,
                    reason=f"Domain {norm_domain} matches denied pattern {denied}",
                    target=domain,
                    matched_rule=denied,
                )

        # Must match allowed domain
        if not self.config.allowed_domains:
            # If no allowed domains defined, fail closed unless allowed_urls defined
            if not self.config.allowed_urls:
                return ScopeDecision(
                    allowed=False,
                    reason="Fail closed: no allowed domains configured in scope",
                    target=domain,
                )

        for allowed in self.config.allowed_domains:
            norm_allowed = allowed.lower().strip(".")
            if self._domain_matches(norm_domain, norm_allowed):
                return ScopeDecision(
                    allowed=True,
                    reason=f"Domain {norm_domain} matches allowed pattern {allowed}",
                    target=domain,
                    matched_rule=allowed,
                )

        return ScopeDecision(
            allowed=False,
            reason=f"Domain {norm_domain} is not in authorized domain scope",
            target=domain,
        )

    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        """Match domain against pattern, handling wildcards like *.example.com."""
        if pattern.startswith("*."):
            base_pattern = pattern[2:]
            # Matches sub.example.com or any depth, or the base domain itself
            if domain == base_pattern or domain.endswith("." + base_pattern):
                return True
        elif pattern.startswith("."):
            base_pattern = pattern[1:]
            if domain == base_pattern or domain.endswith("." + base_pattern):
                return True
        elif "*" in pattern:
            if fnmatch.fnmatch(domain, pattern):
                return True
        return domain == pattern

    def _check_url(self, raw_url: str) -> ScopeDecision:
        try:
            parsed = urlparse(raw_url)
        except Exception as e:
            return ScopeDecision(
                allowed=False,
                reason=f"Fail closed: malformed URL ({e})",
                target=raw_url,
            )

        if not parsed.scheme or not parsed.netloc:
            return ScopeDecision(
                allowed=False,
                reason="Fail closed: URL missing scheme or netloc",
                target=raw_url,
            )

        # Check protocol
        proto_decision = self._check_protocol(parsed.scheme, raw_url)
        if not proto_decision.allowed:
            return proto_decision

        # Extract hostname and port
        hostname = parsed.hostname or ""
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80

        port_decision = self._check_port(port, raw_url)
        if not port_decision.allowed:
            return port_decision

        # Check explicit denied URLs
        for denied_url in self.config.denied_urls:
            if raw_url.startswith(denied_url):
                return ScopeDecision(
                    allowed=False,
                    reason=f"URL matches denied URL prefix {denied_url}",
                    target=raw_url,
                    matched_rule=denied_url,
                )

        # Check explicit denied paths
        path = parsed.path or "/"
        for denied_path in self.config.denied_paths:
            if fnmatch.fnmatch(path, denied_path) or path.startswith(denied_path):
                return ScopeDecision(
                    allowed=False,
                    reason=f"Path {path} matches denied path {denied_path}",
                    target=raw_url,
                    matched_rule=denied_path,
                )

        # Check explicit allowed URLs
        if self.config.allowed_urls:
            for allowed_url in self.config.allowed_urls:
                if raw_url.startswith(allowed_url):
                    return ScopeDecision(
                        allowed=True,
                        reason=f"URL matches allowed URL prefix {allowed_url}",
                        target=raw_url,
                        matched_rule=allowed_url,
                    )

        # Check explicit allowed paths if specified
        if self.config.allowed_paths:
            path_allowed = False
            for allowed_path in self.config.allowed_paths:
                if fnmatch.fnmatch(path, allowed_path) or path.startswith(allowed_path):
                    path_allowed = True
                    break
            if not path_allowed:
                return ScopeDecision(
                    allowed=False,
                    reason=f"Path {path} not in allowed paths list",
                    target=raw_url,
                )

        # Check underlying host
        host_decision = self.is_in_scope(hostname, port=port)
        if not host_decision.allowed:
            return host_decision

        return ScopeDecision(
            allowed=True,
            reason="URL and host are within authorized scope",
            target=raw_url,
        )
