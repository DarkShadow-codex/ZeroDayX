"""Directed Attack Graph for ZeroDay v2.0."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from zeroday.attack_graph.edges import AttackEdge, AttackEdgeType
from zeroday.attack_graph.nodes import AttackNode, AttackNodeType


logger = logging.getLogger(__name__)


class AttackGraph:
    """Represents the multi-stage exploit graph for an assessment."""

    def __init__(self) -> None:
        self._nodes: dict[str, AttackNode] = {}
        self._edges: list[AttackEdge] = []
        self._outgoing: dict[str, list[AttackEdge]] = defaultdict(list)
        self._incoming: dict[str, list[AttackEdge]] = defaultdict(list)

    def add_node(
        self,
        node_id: str,
        node_type: AttackNodeType,
        label: str,
        *,
        is_entry_point: bool = False,
        is_critical_asset: bool = False,
        properties: dict[str, Any] | None = None,
    ) -> AttackNode:
        node = AttackNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            is_entry_point=is_entry_point,
            is_critical_asset=is_critical_asset,
            properties=properties or {},
        )
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: AttackEdgeType,
        *,
        weight: float = 1.0,
        confidence: float = 1.0,
        properties: dict[str, Any] | None = None,
    ) -> AttackEdge:
        edge = AttackEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            confidence=confidence,
            properties=properties or {},
        )
        self._edges.append(edge)
        self._outgoing[source_id].append(edge)
        self._incoming[target_id].append(edge)
        return edge

    def get_node(self, node_id: str) -> AttackNode | None:
        return self._nodes.get(node_id)

    def get_entry_points(self) -> list[AttackNode]:
        return [n for n in self._nodes.values() if n.is_entry_point]

    def get_critical_assets(self) -> list[AttackNode]:
        return [n for n in self._nodes.values() if n.is_critical_asset]

    def get_outgoing(self, node_id: str) -> list[AttackEdge]:
        return self._outgoing.get(node_id, [])

    def to_mermaid(self) -> str:
        """Render the attack graph as a Mermaid diagram."""
        lines = ["graph TD"]
        for node in self._nodes.values():
            shape_start, shape_end = ("(", ")") if node.is_entry_point else ("[", "]")
            if node.is_critical_asset:
                shape_start, shape_end = ("((", "))")
            clean_label = node.label.replace('"', "'")
            lines.append(f'    {node.node_id}{shape_start}"{clean_label}"{shape_end}')

        lines.extend(
            f"    {edge.source_id} -->|{edge.edge_type.value}| {edge.target_id}"
            for edge in self._edges
        )

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }
