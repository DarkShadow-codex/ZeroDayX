"""Kill Switch Engine for ZeroDay v2.0.

Provides immediate, emergency execution termination and post-mortem state preservation
upon detection of critical security or policy violations.
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)


class KillCondition(enum.Enum):
    SCOPE_VIOLATION = "scope_violation"
    TARGET_MISMATCH = "target_mismatch"
    DANGEROUS_COMMAND = "dangerous_command"
    EXCESSIVE_TRAFFIC = "excessive_traffic"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    REPEATED_AGENT_LOOPS = "repeated_agent_loops"
    UNAUTHORIZED_CREDENTIAL = "unauthorized_credential"
    SANDBOX_FAILURE = "sandbox_failure"
    POLICY_FAILURE = "policy_failure"
    OPERATOR_OVERRIDE = "operator_override"


@dataclass(slots=True)
class KillSwitchEvent:
    condition: KillCondition
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "condition": self.condition.value,
            "reason": self.reason,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class KillSwitch:
    """Central safety circuit breaker for the ZeroDay execution environment."""

    def __init__(self) -> None:
        self._triggered = False
        self._event: KillSwitchEvent | None = None
        self._callbacks: list[Callable[[KillSwitchEvent], None]] = []

    @property
    def is_triggered(self) -> bool:
        return self._triggered

    @property
    def event(self) -> KillSwitchEvent | None:
        return self._event

    def register_callback(self, callback: Callable[[KillSwitchEvent], None]) -> None:
        """Register a callback to run synchronously when the kill switch triggers."""
        self._callbacks.append(callback)

    def trigger(
        self,
        condition: KillCondition,
        reason: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> KillSwitchEvent:
        """Immediately trigger the kill switch, halting operations."""
        if self._triggered:
            logger.warning("Kill switch already active; ignoring secondary trigger: %s", reason)
            return self._event  # type: ignore[return-value]

        self._triggered = True
        self._event = KillSwitchEvent(
            condition=condition,
            reason=reason,
            details=details or {},
        )

        logger.critical(
            "🛑 KILL SWITCH TRIGGERED: [%s] %s (details: %s)",
            condition.value,
            reason,
            details,
        )

        # Run emergency callbacks (e.g. stop agents, pause sandbox, flush reports)
        for cb in self._callbacks:
            try:
                cb(self._event)
            except Exception:
                logger.exception("Error executing kill switch callback")

        return self._event

    def reset(self) -> None:
        """Reset the kill switch (typically for tests or authorized resumption)."""
        self._triggered = False
        self._event = None
        logger.info("Kill switch reset")


# Global singleton instance for easy cross-module check
GLOBAL_KILL_SWITCH = KillSwitch()
