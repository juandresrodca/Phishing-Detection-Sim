"""
Exports analysis results to JSON and CSV formats.
"""

import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from app.core.utils import ensure_output_dir, setup_logger

logger = setup_logger(__name__)


class ReportGenerator:
    """
    Serializes a list of email assessment dicts produced by EmailAnalyzer
    into JSON and/or CSV files in the configured output directory.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        ensure_output_dir(output_dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_json(
        self,
        results: List[Dict[str, Any]],
        filename: str = "analysis_report.json",
    ) -> Path:
        """Write all results to a pretty-printed JSON file."""
        path = self.output_dir / filename
        try:
            path.write_text(
                json.dumps(results, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("JSON report saved: %s", path)
            return path
        except OSError as exc:
            logger.error("Failed to write JSON report: %s", exc)
            raise

    def export_csv(
        self,
        results: List[Dict[str, Any]],
        filename: str = "analysis_report.csv",
    ) -> Path:
        """Write a summary CSV with one row per analyzed email."""
        path = self.output_dir / filename
        fieldnames = [
            "email_file",
            "analyzed_at",
            "risk_level",
            "risk_score",
            "keyword_score",
            "domain_score",
            "attachment_score",
            "detection_count",
            "detections_summary",
        ]
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    breakdown = r.get("score_breakdown", {})
                    writer.writerow({
                        "email_file": r.get("email_file", ""),
                        "analyzed_at": r.get("analyzed_at", ""),
                        "risk_level": r.get("risk_level", ""),
                        "risk_score": r.get("risk_score", 0),
                        "keyword_score": breakdown.get("keyword_score", 0),
                        "domain_score": breakdown.get("domain_score", 0),
                        "attachment_score": breakdown.get("attachment_score", 0),
                        "detection_count": len(r.get("detections", [])),
                        "detections_summary": " | ".join(r.get("detections", [])),
                    })
            logger.info("CSV report saved: %s", path)
            return path
        except OSError as exc:
            logger.error("Failed to write CSV report: %s", exc)
            raise
