"""
Detects phishing keywords, urgency language, and social engineering phrases.
"""

from typing import List, Tuple

from app.core.constants import SCORE_WEIGHTS
from app.core.patterns import (
    PHISHING_KEYWORDS,
    SOCIAL_ENGINEERING_PHRASES,
    URGENCY_PHRASES,
)


class KeywordDetector:
    """
    Scans the full email body for known phishing vocabulary.

    Scoring is capped per category so a single indicator cannot
    dominate the total risk score on its own.
    """

    _MAX_KEYWORD_CONTRIBUTION = 30
    _MAX_URGENCY_CONTRIBUTION = 20
    _MAX_SE_CONTRIBUTION = 15

    def __init__(self) -> None:
        self._keywords = [kw.lower() for kw in PHISHING_KEYWORDS]
        self._urgency = [p.lower() for p in URGENCY_PHRASES]
        self._social_eng = [p.lower() for p in SOCIAL_ENGINEERING_PHRASES]

    def analyze(self, content: str) -> Tuple[int, List[str]]:
        """
        Scan email content for phishing indicators.

        Returns:
            (score_contribution, list_of_human_readable_detections)
        """
        body = content.lower()
        detections: list[str] = []
        score = 0

        matched_kw = [kw for kw in self._keywords if kw in body]
        matched_urg = [p for p in self._urgency if p in body]
        matched_se = [p for p in self._social_eng if p in body]

        if matched_kw:
            contribution = min(
                SCORE_WEIGHTS["keyword"] * len(matched_kw),
                self._MAX_KEYWORD_CONTRIBUTION,
            )
            score += contribution
            preview = ", ".join(f'"{k}"' for k in matched_kw[:5])
            detections.append(f"Phishing keywords detected: {preview}")

        if matched_urg:
            contribution = min(
                SCORE_WEIGHTS["urgency"] * len(matched_urg),
                self._MAX_URGENCY_CONTRIBUTION,
            )
            score += contribution
            preview = ", ".join(f'"{p}"' for p in matched_urg[:3])
            detections.append(f"Urgency / fear-tactic language detected: {preview}")

        if matched_se:
            contribution = min(
                SCORE_WEIGHTS["social_engineering"] * len(matched_se),
                self._MAX_SE_CONTRIBUTION,
            )
            score += contribution
            preview = ", ".join(f'"{p}"' for p in matched_se[:3])
            detections.append(f"Social engineering phrases detected: {preview}")

        return score, detections
