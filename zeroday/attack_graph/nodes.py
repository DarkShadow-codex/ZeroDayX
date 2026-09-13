"""Attack Graph Node Models for ZeroDay v2.0."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class AttackNodeType(enum.Enum):
    ASSET = "asset"
    USER = "user"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    PRIVILEGE = "privilege"
    SERVICE = "service"
    DATA = "data"
    TECHNIQUE = "technique"


@dataclass
class AttackNode:
    node_id: str
    node_type: AttackNodeType
    label: str
    is_entry_point: bool = False
    is_critical_asset: bool = False
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["node_type"] = self.node_type.value
        return d
