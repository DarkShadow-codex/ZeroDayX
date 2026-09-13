"""Human Approval System for ZeroDay v2.0.

Provides deterministic approval gating for HIGH risk or destructive actions.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


class ApprovalStatus(enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"


@dataclass
class ApprovalRequest:
    """A formal request for human operator approval."""

    approval_id: str
    scan_id: str
    agent_id: str
    action: str
    risk: str  # "HIGH", "MEDIUM"
    target: str
    reason: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    timestamp: float = field(default_factory=time.time)
    resolved_at: float | None = None
    resolved_by: str | None = None
    denial_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "scan_id": self.scan_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "risk": self.risk,
            "target": self.target,
            "reason": self.reason,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "denial_reason": self.denial_reason,
        }


class ApprovalManager:
    """Manages pending and resolved human approvals."""

    def __init__(self, default_timeout_s: float = 300.0) -> None:
        self.default_timeout_s = default_timeout_s
        self._requests: dict[str, ApprovalRequest] = {}
        self._events: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    def create_request(
        self,
        *,
        scan_id: str,
        agent_id: str,
        action: str,
        risk: str,
        target: str,
        reason: str,
    ) -> ApprovalRequest:
        approval_id = f"APPR-{uuid.uuid4().hex[:8]}"
        req = ApprovalRequest(
            approval_id=approval_id,
            scan_id=scan_id,
            agent_id=agent_id,
            action=action,
            risk=risk,
            target=target,
            reason=reason,
        )
        self._requests[approval_id] = req
        self._events[approval_id] = asyncio.Event()
        logger.warning(
            "APPROVAL REQUIRED [%s]: Agent '%s' requests '%s' on '%s' (Risk: %s, Reason: %s)",
            approval_id,
            agent_id,
            action,
            target,
            risk,
            reason,
        )
        return req

    async def wait_for_decision(
        self,
        approval_id: str,
        timeout_s: float | None = None,
    ) -> ApprovalRequest:
        """Asynchronously wait for an operator decision on an approval request."""
        req = self._requests.get(approval_id)
        if not req:
            raise KeyError(f"Approval request {approval_id} not found")

        event = self._events.get(approval_id)
        if not event:
            return req

        timeout = timeout_s if timeout_s is not None else self.default_timeout_s
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            req.status = ApprovalStatus.TIMED_OUT
            req.resolved_at = time.time()
            req.resolved_by = "system_timeout"
            logger.warning("Approval request %s timed out after %ss", approval_id, timeout)

        return req

    def approve(self, approval_id: str, resolved_by: str = "operator") -> bool:
        req = self._requests.get(approval_id)
        if not req or req.status != ApprovalStatus.PENDING:
            return False
        req.status = ApprovalStatus.APPROVED
        req.resolved_at = time.time()
        req.resolved_by = resolved_by
        event = self._events.get(approval_id)
        if event:
            event.set()
        logger.info("Approval %s APPROVED by %s", approval_id, resolved_by)
        return True

    def deny(
        self,
        approval_id: str,
        resolved_by: str = "operator",
        denial_reason: str = "",
    ) -> bool:
        req = self._requests.get(approval_id)
        if not req or req.status != ApprovalStatus.PENDING:
            return False
        req.status = ApprovalStatus.DENIED
        req.resolved_at = time.time()
        req.resolved_by = resolved_by
        req.denial_reason = denial_reason or "Denied by operator"
        event = self._events.get(approval_id)
        if event:
            event.set()
        logger.info("Approval %s DENIED by %s (%s)", approval_id, resolved_by, denial_reason)
        return True

    def get_pending_requests(self) -> list[ApprovalRequest]:
        return [r for r in self._requests.values() if r.status == ApprovalStatus.PENDING]

    def get_request(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)
