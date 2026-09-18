"""Authoritative Tool Registry & Execution Contract for ZeroDay v2.0.

Provides metadata-driven tool permission enforcement, contract validation, and audit recording.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


# Standard regexes for automatic redaction of sensitive data in arguments and outputs
SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)(?:api[_-]?key|access[_-]?token|secret|password|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?"
        ),
        r"[REDACTED_SECRET]",
    ),
    (
        re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.]{8,})"),
        r"Bearer [REDACTED_SECRET]",
    ),
    (
        re.compile(
            r"-----BEGIN\s+(?:RSA|OPENSSH|EC|PRIVATE)?\s*KEY-----[\s\S]+?-----END\s+(?:RSA|OPENSSH|EC|PRIVATE)?\s*KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "[REDACTED_JWT]",
    ),
)


def redact_sensitive(text: str) -> str:
    """Redact passwords, API keys, private keys, and JWT tokens."""
    if not text:
        return text
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


@dataclass(slots=True)
class ToolMetadata:
    """Metadata specification for a tool."""

    name: str
    category: str  # "recon", "web", "api", "source", "system", "reporting", etc.
    risk: str  # "low", "medium", "high"
    requires_network: bool = False
    supports_scope: bool = True
    allowed_agents: list[str] = field(default_factory=list)
    sandbox_only: bool = True
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolExecutionContract:
    """Audit record capturing the full contract of a tool invocation."""

    tool_id: str
    agent_id: str
    scan_id: str
    arguments_hash: str
    sanitized_arguments: dict[str, Any]
    start_time: float
    end_time: float
    exit_code: int
    stdout_hash: str
    stderr_hash: str
    scope_decision: dict[str, Any]
    policy_decision: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolRegistry:
    """Authoritative tool permission and metadata layer."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolMetadata] = {}
        self._contracts: list[ToolExecutionContract] = []
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        defaults = [
            ToolMetadata(
                name="shell",
                category="terminal",
                risk="medium",
                requires_network=True,
                supports_scope=True,
                allowed_agents=["recon", "web", "api", "source", "auth", "authorization"],
                sandbox_only=True,
                description="Execute bash command inside the disposable Kali sandbox",
            ),
            ToolMetadata(
                name="browser",
                category="browser",
                risk="low",
                requires_network=True,
                supports_scope=True,
                allowed_agents=["recon", "web", "auth", "validation"],
                sandbox_only=True,
                description="Sandboxed browser automation and page inspection",
            ),
            ToolMetadata(
                name="proxy",
                category="proxy",
                risk="low",
                requires_network=True,
                supports_scope=True,
                allowed_agents=["recon", "web", "api", "auth", "authorization", "validation"],
                sandbox_only=True,
                description="Intercept, inspect, and replay HTTP/S traffic via Caido",
            ),
            ToolMetadata(
                name="repeat_request",
                category="proxy",
                risk="medium",
                requires_network=True,
                supports_scope=True,
                allowed_agents=["web", "api", "auth", "authorization", "validation"],
                sandbox_only=True,
                description="Replay a modified HTTP request through proxy",
            ),
            ToolMetadata(
                name="create_vulnerability_report",
                category="reporting",
                risk="low",
                requires_network=False,
                supports_scope=False,
                allowed_agents=["web", "api", "source", "auth", "authorization", "validation"],
                sandbox_only=False,
                description="Record a validated vulnerability finding",
            ),
            ToolMetadata(
                name="apply_patch",
                category="remediation",
                risk="medium",
                requires_network=False,
                supports_scope=False,
                allowed_agents=["remediation"],
                sandbox_only=False,
                description="Apply a proposed source code patch",
            ),
            ToolMetadata(
                name="nmap",
                category="recon",
                risk="medium",
                requires_network=True,
                supports_scope=True,
                allowed_agents=["recon"],
                sandbox_only=True,
                description="Network discovery and port scanning",
            ),
            ToolMetadata(
                name="nuclei",
                category="scanners",
                risk="medium",
                requires_network=True,
                supports_scope=True,
                allowed_agents=["recon", "web"],
                sandbox_only=True,
                description="Vulnerability scanner using community templates",
            ),
            ToolMetadata(
                name="sqlmap",
                category="scanners",
                risk="high",
                requires_network=True,
                supports_scope=True,
                allowed_agents=["web", "api"],
                sandbox_only=True,
                description="Automatic SQL injection detection and validation",
            ),
        ]
        for t in defaults:
            self._tools[t.name] = t

    def register_tool(self, metadata: ToolMetadata) -> None:
        self._tools[metadata.name] = metadata

    def get_tool(self, name: str) -> ToolMetadata | None:
        return self._tools.get(name)

    def list_tools(self) -> list[ToolMetadata]:
        return list(self._tools.values())

    def record_execution(
        self,
        *,
        tool_id: str,
        agent_id: str,
        scan_id: str,
        raw_arguments: dict[str, Any] | str,
        start_time: float,
        end_time: float,
        exit_code: int,
        stdout: str,
        stderr: str,
        scope_decision: dict[str, Any] | None = None,
        policy_decision: dict[str, Any] | None = None,
    ) -> ToolExecutionContract:
        """Create and record an audit contract entry with hashed artifacts and redaction."""
        # Sanitize arguments
        if isinstance(raw_arguments, str):
            arg_str = raw_arguments
            sanitized_dict = {"raw_input": redact_sensitive(raw_arguments)}
        else:
            arg_str = json.dumps(raw_arguments, sort_keys=True)
            sanitized_dict = json.loads(redact_sensitive(arg_str))

        arg_hash = hashlib.sha256(arg_str.encode("utf-8", errors="ignore")).hexdigest()
        stdout_hash = hashlib.sha256(stdout.encode("utf-8", errors="ignore")).hexdigest()
        stderr_hash = hashlib.sha256(stderr.encode("utf-8", errors="ignore")).hexdigest()

        contract = ToolExecutionContract(
            tool_id=tool_id,
            agent_id=agent_id,
            scan_id=scan_id,
            arguments_hash=arg_hash,
            sanitized_arguments=sanitized_dict,
            start_time=start_time,
            end_time=end_time,
            exit_code=exit_code,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            scope_decision=scope_decision or {"allowed": True, "reason": "Not network-bound"},
            policy_decision=policy_decision or {"allowed": True, "reason": "Pre-approved"},
        )
        self._contracts.append(contract)
        return contract

    def get_contracts(self, scan_id: str | None = None) -> list[ToolExecutionContract]:
        if scan_id is None:
            return list(self._contracts)
        return [c for c in self._contracts if c.scan_id == scan_id]


# Global tool registry
GLOBAL_TOOL_REGISTRY = ToolRegistry()
