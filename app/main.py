"""
Entry point for the Phishing Detection Simulator.

Usage:
    python -m app.main                          Scan all samples
    python -m app.main -f samples/email.txt     Scan one file
    python -m app.main --no-csv                 Skip CSV export
    python -m app.main --output-dir ./reports   Custom output directory
    python -m app.main --verbose                Enable debug logging
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from app.analyzer.email_analyzer import EmailAnalyzer
from app.core.constants import Colors, OUTPUT_DIR, SAMPLES_DIR
from app.core.utils import (
    colorize_risk,
    print_banner,
    print_separator,
    setup_logger,
    truncate,
)
from app.reports.report_generator import ReportGenerator

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Phishing Detection Simulator — SOC Email Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m app.main\n"
            "  python -m app.main -f samples/phishing_email_1.txt\n"
            "  python -m app.main --no-csv --output-dir ./reports\n"
            "  python -m app.main --verbose\n"
        ),
    )
    parser.add_argument(
        "--file", "-f",
        metavar="PATH",
        type=Path,
        default=None,
        help="Analyze a single email file (default: all .txt files in --samples-dir).",
    )
    parser.add_argument(
        "--samples-dir",
        metavar="DIR",
        type=Path,
        default=SAMPLES_DIR,
        help=f"Directory containing sample emails (default: {SAMPLES_DIR}).",
    )
    parser.add_argument(
        "--output-dir", "-o",
        metavar="DIR",
        type=Path,
        default=OUTPUT_DIR,
        help=f"Directory to write reports (default: {OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Suppress JSON report export.",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Suppress CSV report export.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------


def _collect_files(args: argparse.Namespace) -> List[Path]:
    if args.file:
        if not args.file.exists():
            print(
                f"{Colors.RED}[ERROR]{Colors.RESET} File not found: {args.file}",
                file=sys.stderr,
            )
            sys.exit(1)
        return [args.file]

    samples_dir: Path = args.samples_dir
    if not samples_dir.exists():
        print(
            f"{Colors.RED}[ERROR]{Colors.RESET} Samples directory not found: {samples_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    files = sorted(samples_dir.glob("*.txt"))
    if not files:
        print(
            f"{Colors.YELLOW}[WARN]{Colors.RESET} No .txt files found in {samples_dir}",
            file=sys.stderr,
        )
        sys.exit(0)

    return files


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------


def _print_result_card(result: dict) -> None:
    risk_level: str = result["risk_level"]
    score: int = result["risk_score"]
    detections: list = result["detections"]
    breakdown: dict = result.get("score_breakdown", {})

    print_separator()
    print(f"  {Colors.BOLD}File:{Colors.RESET}        {result['email_file']}")
    print(f"  {Colors.BOLD}Analyzed:{Colors.RESET}    {result['analyzed_at']}")
    print(f"  {Colors.BOLD}Risk Level:{Colors.RESET}  {colorize_risk(risk_level)}")
    print(f"  {Colors.BOLD}Risk Score:{Colors.RESET}  {score}/100")
    print(
        f"  {Colors.DIM}Breakdown -> "
        f"Keywords: {breakdown.get('keyword_score', 0)}  "
        f"Domains: {breakdown.get('domain_score', 0)}  "
        f"Attachments: {breakdown.get('attachment_score', 0)}"
        f"{Colors.RESET}"
    )

    if detections:
        print(f"\n  {Colors.BOLD}Indicators Detected:{Colors.RESET}")
        for det in detections:
            print(f"    {Colors.YELLOW}>>{Colors.RESET} {truncate(det, 80)}")
    else:
        print(f"\n  {Colors.GREEN}[OK] No phishing indicators detected.{Colors.RESET}")

    print()


def _print_summary(
    results: list,
    json_path: Optional[Path],
    csv_path: Optional[Path],
) -> None:
    print_separator("=", 64)
    print(f"{Colors.BOLD}{Colors.CYAN}  ANALYSIS SUMMARY{Colors.RESET}")
    print_separator("=", 64)

    high = sum(1 for r in results if r["risk_level"] == "HIGH")
    medium = sum(1 for r in results if r["risk_level"] == "MEDIUM")
    low = sum(1 for r in results if r["risk_level"] == "LOW")

    print(f"  Emails analyzed : {Colors.BOLD}{len(results)}{Colors.RESET}")
    print(f"  {colorize_risk('HIGH')}             : {high}")
    print(f"  {colorize_risk('MEDIUM')}           : {medium}")
    print(f"  {colorize_risk('LOW')}              : {low}")

    if json_path:
        print(f"\n  {Colors.CYAN}JSON report :{Colors.RESET} {json_path}")
    if csv_path:
        print(f"  {Colors.CYAN}CSV  report :{Colors.RESET} {csv_path}")

    print_separator("=", 64)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    args = _build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print_banner()

    email_files = _collect_files(args)
    analyzer = EmailAnalyzer()
    reporter = ReportGenerator(output_dir=args.output_dir)

    print(
        f"  {Colors.BOLD}Scanning {len(email_files)} email(s) …{Colors.RESET}\n"
    )

    results = []
    for path in email_files:
        result = analyzer.analyze(path)
        if result:
            results.append(result)
            _print_result_card(result)

    if not results:
        print(f"{Colors.RED}No results to report.{Colors.RESET}")
        sys.exit(1)

    json_path: Optional[Path] = None
    csv_path: Optional[Path] = None

    if not args.no_json:
        json_path = reporter.export_json(results)

    if not args.no_csv:
        csv_path = reporter.export_csv(results)

    _print_summary(results, json_path, csv_path)


if __name__ == "__main__":
    main()
