"""Specialized Agent Lifecycle & Graph Manager for ZeroDay v2.0."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from zeroday.policy.permissions import PermissionValidator


logger = logging.getLogger(__name__)


@dataclass
class ManagedAgent:
    agent_id: str
    agent_type: str  # root, recon, web, api, source, auth, etc.
    name: str
    parent_id: str | None = None
    status: str = "INITIALIZED"  # INITIALIZED, RUNNING, WAITING, COMPLETED, FAILED, TERMINATED
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentManager:
    """Oversees multi-agent red team lifecycle, capability binding, and monitoring."""

    def __init__(self, permission_validator: PermissionValidator | None = None) -> None:
        self.permission_validator = permission_validator or PermissionValidator()
        self._agents: dict[str, ManagedAgent] = {}

    def spawn_agent(
        self,
        agent_type: str,
        name: str | None = None,
        parent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ManagedAgent:
        agent_id = f"AGT-{agent_type.upper()}-{uuid.uuid4().hex[:6]}"
        agent_name = name or f"{agent_type.capitalize()}Agent"

        cap = self.permission_validator.get_capabilities(agent_type)
        allowed_tools = cap.allowed_tools if cap else []

        agent = ManagedAgent(
            agent_id=agent_id,
            agent_type=agent_type,
            name=agent_name,
            parent_id=parent_id,
            capabilities=allowed_tools,
            metadata=metadata or {},
        )
        self._agents[agent_id] = agent
        logger.info("Spawned %s (%s) under parent %s", agent_name, agent_id, parent_id)
        return agent

    def get_agent(self, agent_id: str) -> ManagedAgent | None:
        return self._agents.get(agent_id)

    def list_agents(self, agent_type: str | None = None) -> list[ManagedAgent]:
        if agent_type:
            return [a for a in self._agents.values() if a.agent_type == agent_type]
        return list(self._agents.values())

    def update_status(self, agent_id: str, status: str) -> None:
        if agent_id in self._agents:
            self._agents[agent_id].status = status
            logger.debug("Agent %s status updated to %s", agent_id, status)
