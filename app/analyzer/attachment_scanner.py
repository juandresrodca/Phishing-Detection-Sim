"""
Detects dangerous file attachment indicators inside email text.
"""

import re
from pathlib import Path
from typing import List, Tuple

from app.core.constants import SCORE_WEIGHTS
from app.core.patterns import (
    DANGEROUS_EXTENSIONS,
    HIGH_RISK_EXTENSIONS,
    LOW_RISK_EXTENSIONS,
    MEDIUM_RISK_EXTENSIONS,
    PATTERNS,
    VERY_HIGH_RISK_EXTENSIONS,
)


class AttachmentScanner:
    """
    Locates attachment filename references in the email body and header
    area, then classifies each by risk tier.

    Also flags double-extension masquerading (e.g. "invoice.pdf.exe").
    """

    _MAX_SCORE = 50

    def analyze(self, content: str) -> Tuple[int, List[str]]:
        """
        Return (score_contribution, detections) after scanning *content*
        for attachment filename references.
        """
        detections: list[str] = []
        score = 0

        found_extensions = self._collect_extensions(content)

        for ext in found_extensions:
            ext_lower = ext.lower()
            if ext_lower in VERY_HIGH_RISK_EXTENSIONS:
                score += SCORE_WEIGHTS["attachment_very_high"]
                detections.append(
                    f"Executable/script attachment detected (extremely high risk): *{ext_lower}"
                )
            elif ext_lower in HIGH_RISK_EXTENSIONS:
                score += SCORE_WEIGHTS["attachment_high"]
                detections.append(
                    f"High-risk attachment type detected: *{ext_lower}"
                )
            elif ext_lower in MEDIUM_RISK_EXTENSIONS:
                score += SCORE_WEIGHTS["attachment_medium"]
                detections.append(
                    f"Medium-risk attachment detected (common malware carrier): *{ext_lower}"
                )
            elif ext_lower in LOW_RISK_EXTENSIONS:
                score += SCORE_WEIGHTS["attachment_low"]
                detections.append(
                    f"Suspicious attachment noted (possible HTML phishing page): *{ext_lower}"
                )

        # Double-extension masquerading check
        for match in PATTERNS["double_extension"].findall(content):
            score += 25
            detections.append(
                f"Double-extension masquerading detected (hides true file type): {match}"
            )

        return min(score, self._MAX_SCORE), detections

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_extensions(self, content: str) -> set[str]:
        """Return the set of dangerous extensions referenced in the content."""
        extensions: set[str] = set()

        # Filenames found anywhere in the body
        for match in PATTERNS["attachment_filename"].finditer(content):
            ext = Path(match.group(0)).suffix.lower()
            if ext in {e.lower() for e in DANGEROUS_EXTENSIONS}:
                extensions.add(ext)

        # Explicit attachment / filename headers
        header_pattern = re.compile(
            r"(?:attachment|attached|filename)[:\s=]+([^\s,;\r\n\"']+)",
            re.IGNORECASE,
        )
        for match in header_pattern.finditer(content):
            ext = Path(match.group(1)).suffix.lower()
            if ext in {e.lower() for e in DANGEROUS_EXTENSIONS}:
                extensions.add(ext)

        return extensions
