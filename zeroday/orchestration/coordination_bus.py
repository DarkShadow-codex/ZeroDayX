"""Coordination Bus & Event Stream for ZeroDay v2.0."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Event:
    """An immutable event in the ZeroDay append-oriented event stream."""

    event_id: str
    scan_id: str
    event_type: str
    agent_id: str
    payload: dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


EventHandler = Callable[[Event], Coroutine[Any, Any, None] | None]


class CoordinationBus:
    """Pub/sub event bus supporting inter-agent messaging, telemetry, and audit logging."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._history: list[Event] = []
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._handlers[event_type].append(handler)

    async def publish(
        self,
        event_type: str,
        *,
        scan_id: str = "",
        agent_id: str = "system",
        payload: dict[str, Any] | None = None,
    ) -> Event:
        event = Event(
            event_id=f"EVT-{uuid.uuid4().hex[:12]}",
            scan_id=scan_id,
            event_type=event_type,
            agent_id=agent_id,
            payload=payload or {},
        )

        async with self._lock:
            self._history.append(event)

        # Dispatch to specific listeners and wildcard listeners
        listeners = list(self._handlers.get(event_type, [])) + list(self._handlers.get("*", []))
        for handler in listeners:
            try:
                res = handler(event)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as e:
                logger.exception("Error in event handler for %s: %s", event_type, e)

        return event

    def get_history(
        self,
        event_type: str | None = None,
        scan_id: str | None = None,
    ) -> list[Event]:
        events = list(self._history)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if scan_id:
            events = [e for e in events if e.scan_id == scan_id]
        return events
