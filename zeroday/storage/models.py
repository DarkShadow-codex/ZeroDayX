"""Persistent Storage Models for ZeroDay v2.0."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ScanRecord:
    scan_id: str
    project_id: str
    target: str
    status: str  # running, completed, failed, paused
    scan_mode: str  # passive, standard, deep, purple_team, regression
    safety_mode: str  # safe, controlled, authorized_active, high_impact
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditLogRecord:
    log_id: str
    project_id: str
    scan_id: str
    agent_id: str
    action: str
    target: str
    outcome: str  # ALLOWED, DENIED, APPROVED, BLOCKED
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
