"""Network Exposure Scoring for ZeroDay v2.0."""

from __future__ import annotations

from zeroday.intelligence.attack_surface.models import ExposureLevel


EXPOSURE_MULTIPLIERS: dict[ExposureLevel, float] = {
    ExposureLevel.INTERNET_FACING: 1.5,
    ExposureLevel.DMZ: 1.2,
    ExposureLevel.INTERNAL: 0.9,
    ExposureLevel.AIR_GAPPED: 0.5,
}


class ExposureScorer:
    """Calculates network accessibility multipliers."""

    @staticmethod
    def get_multiplier(exposure: ExposureLevel | str) -> float:
        if isinstance(exposure, str):
            try:
                exposure = ExposureLevel(exposure.lower())
            except ValueError:
                return 1.0
        return EXPOSURE_MULTIPLIERS.get(exposure, 1.0)
