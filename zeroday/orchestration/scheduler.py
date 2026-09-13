"""DAG-Based Task Scheduler for ZeroDay v2.0."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class ScheduledTask:
    task_id: str
    name: str
    agent_type: str  # recon, web, api, source, etc.
    parameters: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)  # list of task_ids
    priority: int = 5  # 1 = highest, 10 = lowest
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED
    result: Any = None


class TaskScheduler:
    """Schedules and dispatches red-team tasks adhering to dependency constraints."""

    def __init__(self) -> None:
        self.tasks: dict[str, ScheduledTask] = {}

    def add_task(self, task: ScheduledTask) -> None:
        self.tasks[task.task_id] = task

    def get_ready_tasks(self) -> list[ScheduledTask]:
        """Return all pending tasks whose dependencies have successfully completed."""
        ready: list[ScheduledTask] = []
        for task in self.tasks.values():
            if task.status != "PENDING":
                continue
            deps_met = all(
                self.tasks.get(dep_id) and self.tasks[dep_id].status == "COMPLETED"
                for dep_id in task.depends_on
            )
            if deps_met:
                ready.append(task)

        # Sort by priority ascending (1 is higher priority than 5)
        ready.sort(key=lambda t: t.priority)
        return ready

    def mark_completed(self, task_id: str, result: Any = None) -> None:
        if task_id in self.tasks:
            self.tasks[task_id].status = "COMPLETED"
            self.tasks[task_id].result = result
            logger.info("Task %s completed", task_id)

    def mark_failed(self, task_id: str, error: str = "") -> None:
        if task_id in self.tasks:
            self.tasks[task_id].status = "FAILED"
            self.tasks[task_id].result = error
            logger.warning("Task %s failed: %s", task_id, error)

    def is_all_completed(self) -> bool:
        return all(t.status in ("COMPLETED", "FAILED") for t in self.tasks.values())
