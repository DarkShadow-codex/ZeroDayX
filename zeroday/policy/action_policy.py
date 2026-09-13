"""Action Risk Classification & Policy Gate for ZeroDay v2.0.

Classifies all proposed agent actions into LOW, MEDIUM, or HIGH risk categories
and determines human approval requirements.
"""

from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


class ActionRiskLevel(enum.Enum):
    """Risk tier of a proposed security testing action."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(slots=True)
class ActionPolicyDecision:
    """Outcome of action risk and policy evaluation."""

    allowed: bool
    risk_level: ActionRiskLevel
    requires_approval: bool
    reason: str
    action_type: str
    target: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "risk_level": self.risk_level.value,
            "requires_approval": self.requires_approval,
            "reason": self.reason,
            "action_type": self.action_type,
            "target": self.target,
        }


# High-risk patterns in shell commands that always trigger HIGH risk or denial
DANGEROUS_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-(?:r|f|rf|fr)\s+/(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=.*of=/dev/", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", re.IGNORECASE),  # fork bomb
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\breboot\b", re.IGNORECASE),
    re.compile(r"\bkill\s+-9\s+1\b", re.IGNORECASE),
    re.compile(r">\s*/dev/sd[a-z]", re.IGNORECASE),
)

# HTTP methods and endpoints considered state-changing or high-impact
HIGH_RISK_HTTP_METHODS: frozenset[str] = frozenset({"DELETE", "PUT", "PATCH"})
HIGH_RISK_PATH_KEYWORDS: tuple[str, ...] = (
    "delete",
    "drop",
    "purge",
    "reset",
    "truncate",
    "destroy",
    "terminate",
    "admin/delete",
    "users/delete",
    "database",
    "transfer",
    "payout",
    "refund",
)


@dataclass
class ActionPolicyConfig:
    """Config for action policy engine."""

    auto_approve_medium: bool = True
    auto_approve_high: bool = False
    deny_dangerous_commands: bool = True
    custom_high_risk_keywords: list[str] = field(default_factory=list)


class ActionPolicyEngine:
    """Evaluates security testing actions against policy and risk rules."""

    def __init__(self, config: ActionPolicyConfig | None = None) -> None:
        self.config = config or ActionPolicyConfig()

    def evaluate_shell_command(
        self,
        command: str,
        *,
        agent_name: str = "agent",
    ) -> ActionPolicyDecision:
        """Evaluate the risk tier of an arbitrary shell command."""
        cmd_clean = command.strip()

        # Check for dangerous / destructive commands first
        if self.config.deny_dangerous_commands:
            for pattern in DANGEROUS_COMMAND_PATTERNS:
                if pattern.search(cmd_clean):
                    return ActionPolicyDecision(
                        allowed=False,
                        risk_level=ActionRiskLevel.HIGH,
                        requires_approval=False,
                        reason=f"Blocked dangerous destructive system command: pattern match {pattern.pattern}",
                        action_type="shell",
                        target=cmd_clean,
                    )

        # High-risk commands
        high_risk_cmds = ("dropdb", "rmdir", "del", "format", "iptables -F", "ufw disable")
        for high_cmd in high_risk_cmds:
            if high_cmd in cmd_clean.lower():
                return ActionPolicyDecision(
                    allowed=not self.config.auto_approve_high,
                    risk_level=ActionRiskLevel.HIGH,
                    requires_approval=not self.config.auto_approve_high,
                    reason=f"High-impact destructive command requires approval: {high_cmd}",
                    action_type="shell",
                    target=cmd_clean,
                )

        # Medium-risk commands (scanners, fuzzers, active network tools)
        medium_tools = (
            "sqlmap",
            "nmap",
            "nuclei",
            "ffuf",
            "wfuzz",
            "gobuster",
            "hydra",
            "commix",
            "nikto",
            "masscan",
        )
        for tool in medium_tools:
            if re.search(rf"\b{tool}\b", cmd_clean, re.IGNORECASE):
                return ActionPolicyDecision(
                    allowed=True,
                    risk_level=ActionRiskLevel.MEDIUM,
                    requires_approval=not self.config.auto_approve_medium,
                    reason=f"Active security tool invocation: {tool}",
                    action_type="shell",
                    target=cmd_clean,
                )

        # Low-risk (passive, read-only tools, inspection)
        return ActionPolicyDecision(
            allowed=True,
            risk_level=ActionRiskLevel.LOW,
            requires_approval=False,
            reason="Standard read-only or informational command",
            action_type="shell",
            target=cmd_clean,
        )

    def evaluate_http_request(
        self,
        method: str,
        url: str,
        *,
        body: str | None = None,
        agent_name: str = "agent",
    ) -> ActionPolicyDecision:
        """Evaluate HTTP request risk tier."""
        m = method.upper().strip()
        url_lower = url.lower()

        # Check for DELETE or destructive path keywords
        is_destructive_method = m in HIGH_RISK_HTTP_METHODS
        has_destructive_path = any(
            kw in url_lower
            for kw in HIGH_RISK_PATH_KEYWORDS + tuple(self.config.custom_high_risk_keywords)
        )

        if is_destructive_method or (m == "POST" and has_destructive_path):
            requires_approval = not self.config.auto_approve_high
            return ActionPolicyDecision(
                allowed=not requires_approval,
                risk_level=ActionRiskLevel.HIGH,
                requires_approval=requires_approval,
                reason=f"Potentially destructive HTTP request ({m} {url})",
                action_type="http_request",
                target=url,
            )

        if m in ("POST", "PUT"):
            return ActionPolicyDecision(
                allowed=True,
                risk_level=ActionRiskLevel.MEDIUM,
                requires_approval=not self.config.auto_approve_medium,
                reason=f"State-affecting HTTP {m} request",
                action_type="http_request",
                target=url,
            )

        return ActionPolicyDecision(
            allowed=True,
            risk_level=ActionRiskLevel.LOW,
            requires_approval=False,
            reason=f"Safe idempotent HTTP {m} request",
            action_type="http_request",
            target=url,
        )
