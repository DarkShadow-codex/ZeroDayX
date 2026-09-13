"""Asset Criticality & Risk Weighting for ZeroDay v2.0."""

from __future__ import annotations

from zeroday.intelligence.attack_surface.models import AssetCriticality


CRITICALITY_MULTIPLIERS: dict[AssetCriticality, float] = {
    AssetCriticality.CRITICAL: 1.5,
    AssetCriticality.HIGH: 1.2,
    AssetCriticality.MEDIUM: 1.0,
    AssetCriticality.LOW: 0.7,
}


class AssetRiskScorer:
    """Calculates asset risk weighting based on role and environment."""

    @staticmethod
    def get_multiplier(criticality: AssetCriticality | str) -> float:
        if isinstance(criticality, str):
            try:
                criticality = AssetCriticality(criticality.lower())
            except ValueError:
                return 1.0
        return CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
