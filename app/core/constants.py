"""
Application-wide constants: risk levels, thresholds, score weights, and terminal colors.
"""

from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_DIR = BASE_DIR / "output"
LOG_FILE = BASE_DIR / "phishing_detector.log"

# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# Inclusive [min, max] score ranges for each risk level
RISK_THRESHOLDS: dict[str, tuple[int, int]] = {
    RiskLevel.LOW: (0, 30),
    RiskLevel.MEDIUM: (31, 65),
    RiskLevel.HIGH: (66, 100),
}

# ---------------------------------------------------------------------------
# Scoring weights (points added per detection hit, before capping)
# ---------------------------------------------------------------------------

SCORE_WEIGHTS: dict[str, int] = {
    "keyword": 12,
    "urgency": 10,
    "social_engineering": 8,
    "domain": 22,
    "sender_spoof": 25,
    "url_suspicious": 15,
    "attachment_very_high": 30,
    "attachment_high": 20,
    "attachment_medium": 12,
    "attachment_low": 5,
}

# ---------------------------------------------------------------------------
# ANSI terminal colors
# ---------------------------------------------------------------------------


class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
