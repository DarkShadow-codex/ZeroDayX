"""Red-Team Task Distribution & Tracking for ZeroDay v2.0."""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class RedTeamTask:
    task_id: str
    scan_id: str
    assigned_agent_id: str
    target: str
    objective: str
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, BLOCKED, FAILED
    findings_count: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TaskManager:
    """Manages assignment and completion tracking for security testing operations."""

    def __init__(self) -> None:
        self.tasks: dict[str, RedTeamTask] = {}

    def create_task(
        self,
        *,
        scan_id: str,
        assigned_agent_id: str,
        target: str,
        objective: str,
        details: dict[str, Any] | None = None,
    ) -> RedTeamTask:
        task_id = f"TASK-{uuid.uuid4().hex[:8]}"
        task = RedTeamTask(
            task_id=task_id,
            scan_id=scan_id,
            assigned_agent_id=assigned_agent_id,
            target=target,
            objective=objective,
            details=details or {},
        )
        self.tasks[task_id] = task
        logger.info("Assigned task %s to agent %s: %s", task_id, assigned_agent_id, objective)
        return task

    def get_task(self, task_id: str) -> RedTeamTask | None:
        return self.tasks.get(task_id)

    def list_tasks(self, scan_id: str | None = None) -> list[RedTeamTask]:
        if scan_id:
            return [t for t in self.tasks.values() if t.scan_id == scan_id]
        return list(self.tasks.values())
