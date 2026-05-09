"""
Orchestrates all detection modules for a single email file.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from app.analyzer.attachment_scanner import AttachmentScanner
from app.analyzer.domain_checker import DomainChecker
from app.analyzer.keyword_detector import KeywordDetector
from app.analyzer.risk_score import RiskScoreEngine
from app.core.utils import format_timestamp, read_email_file, setup_logger

logger = setup_logger(__name__)


class EmailAnalyzer:
    """
    Coordinates KeywordDetector, DomainChecker, AttachmentScanner, and
    RiskScoreEngine to produce a structured phishing assessment for one email.
    """

    def __init__(self) -> None:
        self._keyword = KeywordDetector()
        self._domain = DomainChecker()
        self._attachment = AttachmentScanner()
        self._scorer = RiskScoreEngine()

    def analyze(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Analyze a single email file.

        Args:
            file_path: Absolute or relative path to a .txt email sample.

        Returns:
            Assessment dictionary, or None if the file cannot be read.
        """
        content = read_email_file(file_path)
        if content is None:
            logger.error("Could not read file: %s", file_path)
            return None

        logger.info("Analyzing email: %s", file_path.name)

        kw_score, kw_detections = self._keyword.analyze(content)
        dom_score, dom_detections = self._domain.analyze(content)
        att_score, att_detections = self._attachment.analyze(content)

        all_detections = kw_detections + dom_detections + att_detections
        final_score, risk_level = self._scorer.compute([kw_score, dom_score, att_score])

        return {
            "email_file": file_path.name,
            "analyzed_at": format_timestamp(),
            "risk_level": risk_level,
            "risk_score": final_score,
            "detections": all_detections,
            "score_breakdown": {
                "keyword_score": kw_score,
                "domain_score": dom_score,
                "attachment_score": att_score,
            },
        }
