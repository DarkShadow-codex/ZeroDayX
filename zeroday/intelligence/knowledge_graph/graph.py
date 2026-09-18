"""Security Knowledge Graph for ZeroDay v2.0."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class KnowledgeNode:
    node_id: str
    # Asset, Endpoint, Vulnerability, CWE, OWASP, ATT&CK, Finding, Control, etc.
    entity_type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class KnowledgeEdge:
    source_id: str
    target_id: str
    relation: str  # exposes, affected_by, maps_to, uses, affects, requires, generates
    properties: dict[str, Any] = field(default_factory=dict)


class SecurityKnowledgeGraph:
    """Unified graph correlating attack surface, vulnerabilities, frameworks, and defenses."""

    def __init__(self) -> None:
        self._nodes: dict[str, KnowledgeNode] = {}
        self._edges: list[KnowledgeEdge] = []
        self._outgoing: dict[str, list[KnowledgeEdge]] = defaultdict(list)
        self._incoming: dict[str, list[KnowledgeEdge]] = defaultdict(list)

    def add_node(
        self,
        node_id: str,
        entity_type: str,
        label: str,
        properties: dict[str, Any] | None = None,
    ) -> KnowledgeNode:
        node = KnowledgeNode(
            node_id=node_id,
            entity_type=entity_type,
            label=label,
            properties=properties or {},
        )
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        properties: dict[str, Any] | None = None,
    ) -> KnowledgeEdge:
        edge = KnowledgeEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            properties=properties or {},
        )
        self._edges.append(edge)
        self._outgoing[source_id].append(edge)
        self._incoming[target_id].append(edge)
        return edge

    def get_node(self, node_id: str) -> KnowledgeNode | None:
        return self._nodes.get(node_id)

    def get_outgoing(self, node_id: str) -> list[KnowledgeEdge]:
        return self._outgoing.get(node_id, [])

    def get_incoming(self, node_id: str) -> list[KnowledgeEdge]:
        return self._incoming.get(node_id, [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "nodes": [asdict(n) for n in self._nodes.values()],
            "edges": [asdict(e) for e in self._edges],
        }
