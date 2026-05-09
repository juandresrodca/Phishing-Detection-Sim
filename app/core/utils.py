"""
Shared utility functions: logging setup, file I/O, terminal formatting.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.core.constants import Colors, LOG_FORMAT, LOG_FILE


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def setup_logger(name: str, verbose: bool = False) -> logging.Logger:
    """Return a module-level logger that writes INFO+ to a file and WARN+ to stderr."""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # already configured — avoid duplicate handlers

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    formatter = logging.Formatter(LOG_FORMAT)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    try:
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        pass  # non-writable environment — skip file logging

    return logger


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def read_email_file(file_path: Path) -> Optional[str]:
    """Read raw email text from a file; returns None on failure."""
    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _print_error(f"File not found: {file_path}")
    except UnicodeDecodeError:
        try:
            return file_path.read_text(encoding="latin-1")
        except Exception as exc:
            _print_error(f"Cannot decode {file_path}: {exc}")
    except OSError as exc:
        _print_error(f"Cannot read {file_path}: {exc}")
    return None


def ensure_output_dir(output_dir: Path) -> None:
    """Create the output directory tree if it does not exist."""
    output_dir.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------


def colorize_risk(risk_level: str) -> str:
    """Wrap a risk level string in the appropriate ANSI color."""
    palette = {
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.GREEN,
    }
    color = palette.get(risk_level, Colors.WHITE)
    return f"{color}{Colors.BOLD}{risk_level}{Colors.RESET}"


def print_banner() -> None:
    """Print the application banner to stdout."""
    print(
        f"\n{Colors.CYAN}{Colors.BOLD}"
        "+--------------------------------------------------------------+\n"
        "|        PHISHING DETECTION SIMULATOR  v1.0.0                 |\n"
        "|        SOC Analyst Email Triage Tool                        |\n"
        "+--------------------------------------------------------------+"
        f"{Colors.RESET}\n"
    )


def print_separator(char: str = "-", width: int = 64) -> None:
    """Print a horizontal rule."""
    print(f"{Colors.DIM}{char * width}{Colors.RESET}")


def format_timestamp() -> str:
    """Return current UTC time as a formatted string."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def truncate(text: str, max_len: int = 70) -> str:
    """Truncate a string for display, appending '...' when shortened."""
    return text[:max_len] + "..." if len(text) > max_len else text


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _print_error(message: str) -> None:
    print(f"{Colors.RED}[ERROR]{Colors.RESET} {message}", file=sys.stderr)
