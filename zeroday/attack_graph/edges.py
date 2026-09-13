"""Attack Graph Edge Models for ZeroDay v2.0."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class AttackEdgeType(enum.Enum):
    EXPOSES = "exposes"
    AFFECTS = "affects"
    USES = "uses"
    AUTHENTICATES = "authenticates"
    ESCALATES = "escalates"
    ACCESSES = "accesses"
    CONNECTS = "connects"


@dataclass
class AttackEdge:
    source_id: str
    target_id: str
    edge_type: AttackEdgeType
    weight: float = 1.0  # Exploit difficulty / cost
    confidence: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["edge_type"] = self.edge_type.value
        return d
