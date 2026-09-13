"""Asset Graph for ZeroDay v2.0 Attack Surface Management."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from zeroday.intelligence.attack_surface.models import Asset, AssetType


logger = logging.getLogger(__name__)


class AssetGraph:
    """Manages hierarchical attack surface relationships and topology."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._children: dict[str, set[str]] = defaultdict(set)
        self._parents: dict[str, str | None] = {}

    def add_asset(self, asset: Asset) -> None:
        self._assets[asset.asset_id] = asset
        if asset.parent_id:
            self._children[asset.parent_id].add(asset.asset_id)
            self._parents[asset.asset_id] = asset.parent_id

    def get_asset(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def list_assets(self, asset_type: AssetType | None = None) -> list[Asset]:
        if asset_type is None:
            return list(self._assets.values())
        return [a for a in self._assets.values() if a.type == asset_type]

    def get_children(self, asset_id: str) -> list[Asset]:
        child_ids = self._children.get(asset_id, set())
        return [self._assets[cid] for cid in child_ids if cid in self._assets]

    def get_parent(self, asset_id: str) -> Asset | None:
        parent_id = self._parents.get(asset_id)
        if parent_id and parent_id in self._assets:
            return self._assets[parent_id]
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_assets": len(self._assets),
            "assets": [a.to_dict() for a in self._assets.values()],
            "hierarchy": {pid: list(cids) for pid, cids in self._children.items()},
        }
