"""
Aggregates sub-scores from all analyzers and determines the final risk level.
"""

from typing import List, Tuple

from app.core.constants import RISK_THRESHOLDS, RiskLevel


class RiskScoreEngine:
    """
    Sums individual module scores, clamps the result to [0, 100],
    and maps it to a LOW / MEDIUM / HIGH risk label.
    """

    def compute(self, sub_scores: List[int]) -> Tuple[int, str]:
        """
        Args:
            sub_scores: Raw scores returned by each analyzer module.

        Returns:
            (final_score_0_to_100, risk_level_string)
        """
        final_score = min(sum(sub_scores), 100)
        risk_level = self._classify(final_score)
        return final_score, risk_level

    @staticmethod
    def _classify(score: int) -> str:
        for level, (low, high) in RISK_THRESHOLDS.items():
            if low <= score <= high:
                return level.value
        return RiskLevel.HIGH.value
