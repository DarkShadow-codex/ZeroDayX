"""Agent Capability & Permission Model for ZeroDay v2.0.

Enforces least-privilege security boundaries per agent role.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PermissionDecision:
    """Outcome of an agent permission check."""

    allowed: bool
    reason: str
    agent_name: str
    tool_name: str
    action_type: str = "tool_execution"

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "agent_name": self.agent_name,
            "tool_name": self.tool_name,
            "action_type": self.action_type,
        }


@dataclass
class AgentCapabilities:
    """Security capability profile declared by or assigned to an agent."""

    agent_name: str
    allowed_tools: list[str] = field(default_factory=list)
    network_outbound: bool = True
    filesystem_read: bool = True
    filesystem_write: bool = False
    destructive_actions: bool = False
    max_turns: int = 100


# Canonical role capabilities mapping for the 15 specialized agents
DEFAULT_AGENT_CAPABILITIES: dict[str, AgentCapabilities] = {
    "root": AgentCapabilities(
        agent_name="root",
        allowed_tools=[
            "create_agent",
            "stop_agent",
            "send_message_to_agent",
            "wait_for_agents",
            "view_agent_graph",
            "agent_finish",
            "finish_scan",
            "save_threat_model",
            "get_threat_model",
            "amend_threat_model",
            "list_coverage",
            "record_coverage",
            "update_coverage",
            "create_note",
            "get_note",
            "list_notes",
            "update_note",
            "delete_note",
            "create_todo",
            "list_todos",
            "update_todo",
            "mark_todo_done",
            "mark_todo_pending",
            "delete_todo",
            "web_search",
            "web_get_contents",
            "think",
            "respond_to_user",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=True,
        destructive_actions=False,
    ),
    "recon": AgentCapabilities(
        agent_name="recon",
        allowed_tools=[
            "shell",
            "browser",
            "web_search",
            "web_get_contents",
            "list_requests",
            "view_request",
            "list_sitemap",
            "view_sitemap_entry",
            "create_note",
            "get_note",
            "list_notes",
            "record_coverage",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "web": AgentCapabilities(
        agent_name="web",
        allowed_tools=[
            "shell",
            "browser",
            "proxy",
            "list_requests",
            "view_request",
            "repeat_request",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "get_note",
            "list_notes",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "api": AgentCapabilities(
        agent_name="api",
        allowed_tools=[
            "shell",
            "proxy",
            "list_requests",
            "view_request",
            "repeat_request",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "get_note",
            "list_notes",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "source": AgentCapabilities(
        agent_name="source",
        allowed_tools=[
            "shell",
            "create_vulnerability_report",
            "create_dependency_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "get_note",
            "list_notes",
            "think",
            "agent_finish",
        ],
        network_outbound=False,  # source agent runs offline against local tree
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "auth": AgentCapabilities(
        agent_name="auth",
        allowed_tools=[
            "shell",
            "browser",
            "proxy",
            "repeat_request",
            "view_request",
            "list_requests",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "authorization": AgentCapabilities(
        agent_name="authorization",
        allowed_tools=[
            "shell",
            "browser",
            "proxy",
            "repeat_request",
            "view_request",
            "list_requests",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "business_logic": AgentCapabilities(
        agent_name="business_logic",
        allowed_tools=[
            "shell",
            "browser",
            "proxy",
            "repeat_request",
            "view_request",
            "list_requests",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "cloud": AgentCapabilities(
        agent_name="cloud",
        allowed_tools=[
            "shell",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "container": AgentCapabilities(
        agent_name="container",
        allowed_tools=[
            "shell",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "k8s": AgentCapabilities(
        agent_name="k8s",
        allowed_tools=[
            "shell",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "secrets": AgentCapabilities(
        agent_name="secrets",
        allowed_tools=[
            "shell",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=False,  # secrets analysis is purely static/local
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "supply_chain": AgentCapabilities(
        agent_name="supply_chain",
        allowed_tools=[
            "shell",
            "create_dependency_report",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "record_coverage",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,  # CVE queries
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "validation": AgentCapabilities(
        agent_name="validation",
        allowed_tools=[
            "shell",
            "browser",
            "proxy",
            "repeat_request",
            "view_request",
            "list_requests",
            "create_vulnerability_report",
            "update_vulnerability_report",
            "get_report",
            "list_reports",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=True,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "detection": AgentCapabilities(
        agent_name="detection",
        allowed_tools=[
            "shell",
            "create_note",
            "get_note",
            "list_notes",
            "think",
            "agent_finish",
        ],
        network_outbound=False,
        filesystem_read=True,
        filesystem_write=False,
        destructive_actions=False,
    ),
    "remediation": AgentCapabilities(
        agent_name="remediation",
        allowed_tools=[
            "shell",
            "apply_patch",
            "get_report",
            "list_reports",
            "create_note",
            "think",
            "agent_finish",
        ],
        network_outbound=False,
        filesystem_read=True,
        filesystem_write=True,  # remediation proposes code changes
        destructive_actions=False,
    ),
}


class PermissionValidator:
    """Enforces least privilege per agent role."""

    def __init__(
        self,
        capabilities: dict[str, AgentCapabilities] | None = None,
    ) -> None:
        self.capabilities = (
            dict(capabilities) if capabilities is not None else dict(DEFAULT_AGENT_CAPABILITIES)
        )

    def register_agent_capabilities(self, capabilities: AgentCapabilities) -> None:
        self.capabilities[capabilities.agent_name] = capabilities

    def get_capabilities(self, agent_name: str) -> AgentCapabilities | None:
        return self.capabilities.get(agent_name)

    def check_tool_permission(self, agent_name: str, tool_name: str) -> PermissionDecision:
        """Validate whether an agent has permission to execute the specified tool."""
        cap = self.capabilities.get(agent_name)
        if cap is None:
            # Unknown agent: fail closed
            return PermissionDecision(
                allowed=False,
                reason=f"Fail closed: no registered capability profile for agent '{agent_name}'",
                agent_name=agent_name,
                tool_name=tool_name,
            )

        # Exact match or wildcard match in allowed_tools
        if "*" in cap.allowed_tools or tool_name in cap.allowed_tools:
            return PermissionDecision(
                allowed=True,
                reason=f"Agent '{agent_name}' is authorized to invoke '{tool_name}'",
                agent_name=agent_name,
                tool_name=tool_name,
            )

        return PermissionDecision(
            allowed=False,
            reason=f"Tool '{tool_name}' is not in allowed tools list for agent role '{agent_name}'",
            agent_name=agent_name,
            tool_name=tool_name,
        )

    def check_network_permission(self, agent_name: str) -> PermissionDecision:
        cap = self.capabilities.get(agent_name)
        if cap is None:
            return PermissionDecision(
                allowed=False,
                reason=f"Fail closed: no capability profile for agent '{agent_name}'",
                agent_name=agent_name,
                tool_name="network",
                action_type="network_egress",
            )
        if not cap.network_outbound:
            return PermissionDecision(
                allowed=False,
                reason=f"Outbound network access denied for agent role '{agent_name}'",
                agent_name=agent_name,
                tool_name="network",
                action_type="network_egress",
            )
        return PermissionDecision(
            allowed=True,
            reason="Network outbound permitted",
            agent_name=agent_name,
            tool_name="network",
            action_type="network_egress",
        )

    def check_filesystem_permission(
        self, agent_name: str, *, write: bool = False
    ) -> PermissionDecision:
        cap = self.capabilities.get(agent_name)
        if cap is None:
            return PermissionDecision(
                allowed=False,
                reason=f"Fail closed: no capability profile for agent '{agent_name}'",
                agent_name=agent_name,
                tool_name="filesystem",
                action_type="filesystem",
            )
        if write and not cap.filesystem_write:
            return PermissionDecision(
                allowed=False,
                reason=f"Filesystem write access denied for agent role '{agent_name}'",
                agent_name=agent_name,
                tool_name="filesystem",
                action_type="filesystem_write",
            )
        if not write and not cap.filesystem_read:
            return PermissionDecision(
                allowed=False,
                reason=f"Filesystem read access denied for agent role '{agent_name}'",
                agent_name=agent_name,
                tool_name="filesystem",
                action_type="filesystem_read",
            )
        return PermissionDecision(
            allowed=True,
            reason="Filesystem access permitted",
            agent_name=agent_name,
            tool_name="filesystem",
            action_type="filesystem_write" if write else "filesystem_read",
        )
