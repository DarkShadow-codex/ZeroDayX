"""Attack Path Analysis for ZeroDay v2.0."""

from __future__ import annotations

import heapq
import logging
from dataclasses import dataclass, field
from typing import Any

from zeroday.attack_graph.graph import AttackGraph
from zeroday.attack_graph.nodes import AttackNode


logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    path_id: str
    nodes: list[str]  # sequence of node_ids
    labels: list[str]
    total_cost: float
    confidence: float
    reaches_critical_asset: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "nodes": self.nodes,
            "labels": self.labels,
            "total_cost": round(self.total_cost, 2),
            "confidence": round(self.confidence, 2),
            "reaches_critical_asset": self.reaches_critical_asset,
        }


class AttackPathAnalyzer:
    """Discovers high-impact and shortest exploit paths from entry points to critical targets."""

    def __init__(self, graph: AttackGraph) -> None:
        self.graph = graph

    def find_all_paths(
        self,
        start_node_id: str,
        target_node_id: str,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """Depth-first path search with cycle prevention."""
        results: list[list[str]] = []

        def dfs(current: str, path: list[str]) -> None:
            if len(path) > max_depth:
                return
            if current == target_node_id:
                results.append(list(path))
                return

            for edge in self.graph.get_outgoing(current):
                neighbor = edge.target_id
                if neighbor not in path:
                    path.append(neighbor)
                    dfs(neighbor, path)
                    path.pop()

        dfs(start_node_id, [start_node_id])
        return results

    def find_paths_to_critical_assets(self) -> list[AttackPath]:
        """Find all viable paths leading from any entry point to any critical asset."""
        entry_points = self.graph.get_entry_points()
        critical_assets = self.graph.get_critical_assets()

        paths: list[AttackPath] = []
        path_idx = 1

        for ep in entry_points:
            for ca in critical_assets:
                raw_paths = self.find_all_paths(ep.node_id, ca.node_id)
                for rp in raw_paths:
                    labels = [
                        (self.graph.get_node(nid).label if self.graph.get_node(nid) else nid)
                        for nid in rp
                    ]
                    # Calculate cumulative confidence and cost
                    confidence = 1.0
                    cost = 0.0
                    for i in range(len(rp) - 1):
                        edges = [
                            e for e in self.graph.get_outgoing(rp[i]) if e.target_id == rp[i + 1]
                        ]
                        if edges:
                            confidence *= edges[0].confidence
                            cost += edges[0].weight

                    paths.append(
                        AttackPath(
                            path_id=f"AP-{path_idx:03d}",
                            nodes=rp,
                            labels=labels,
                            total_cost=cost,
                            confidence=confidence,
                            reaches_critical_asset=True,
                        )
                    )
                    path_idx += 1

        # Sort by shortest cost and highest confidence
        paths.sort(key=lambda p: (p.total_cost, -p.confidence))
        return paths

    def get_shortest_path(self, start_id: str, target_id: str) -> AttackPath | None:
        """Dijkstra's shortest path."""
        distances: dict[str, float] = {start_id: 0.0}
        previous: dict[str, str | None] = {start_id: None}
        pq: list[tuple[float, str]] = [(0.0, start_id)]

        while pq:
            current_dist, current_node = heapq.heappop(pq)
            if current_node == target_id:
                break
            if current_dist > distances.get(current_node, float("inf")):
                continue

            for edge in self.graph.get_outgoing(current_node):
                neighbor = edge.target_id
                distance = current_dist + edge.weight
                if distance < distances.get(neighbor, float("inf")):
                    distances[neighbor] = distance
                    previous[neighbor] = current_node
                    heapq.heappush(pq, (distance, neighbor))

        if target_id not in previous and start_id != target_id:
            return None

        # Reconstruct path
        path_nodes: list[str] = []
        curr: str | None = target_id
        while curr is not None:
            path_nodes.append(curr)
            curr = previous.get(curr)
        path_nodes.reverse()

        labels = [
            (self.graph.get_node(nid).label if self.graph.get_node(nid) else nid)
            for nid in path_nodes
        ]
        target_node = self.graph.get_node(target_id)
        is_crit = target_node.is_critical_asset if target_node else False

        return AttackPath(
            path_id="AP-SHORTEST",
            nodes=path_nodes,
            labels=labels,
            total_cost=distances.get(target_id, 0.0),
            confidence=0.95,
            reaches_critical_asset=is_crit,
        )
