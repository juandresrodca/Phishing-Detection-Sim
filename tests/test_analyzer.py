"""
Unit tests for the phishing detection simulator.

Run with:
    python -m pytest tests/ -v
"""

import unittest
from pathlib import Path

from app.analyzer.attachment_scanner import AttachmentScanner
from app.analyzer.domain_checker import DomainChecker
from app.analyzer.email_analyzer import EmailAnalyzer
from app.analyzer.keyword_detector import KeywordDetector
from app.analyzer.risk_score import RiskScoreEngine


# ---------------------------------------------------------------------------
# KeywordDetector
# ---------------------------------------------------------------------------


class TestKeywordDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = KeywordDetector()

    def test_detects_phishing_keywords(self) -> None:
        content = "Please verify your account immediately. Click here to reset your password."
        score, detections = self.detector.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("keyword" in d.lower() for d in detections))

    def test_detects_urgency_language(self) -> None:
        content = "Your account will be closed within 24 hours. Final notice."
        score, detections = self.detector.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("urgency" in d.lower() or "fear" in d.lower() for d in detections))

    def test_detects_social_engineering(self) -> None:
        content = "For security purposes, do not share this email. To protect your account, act now."
        score, detections = self.detector.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("social engineering" in d.lower() for d in detections))

    def test_clean_email_has_low_score(self) -> None:
        content = "Hi team, the sprint review is scheduled for Friday at 2 PM. See you there."
        score, detections = self.detector.analyze(content)
        self.assertEqual(score, 0)
        self.assertEqual(detections, [])

    def test_score_does_not_exceed_cap(self) -> None:
        # Repeat many keywords — score must still respect per-category caps
        repeated = " ".join(["urgent click here verify your account"] * 20)
        score, _ = self.detector.analyze(repeated)
        self.assertLessEqual(score, 65)  # keyword + urgency + SE caps combined


# ---------------------------------------------------------------------------
# DomainChecker
# ---------------------------------------------------------------------------


class TestDomainChecker(unittest.TestCase):
    def setUp(self) -> None:
        self.checker = DomainChecker()

    def test_detects_suspicious_tld(self) -> None:
        content = "From: support@secure-login.ru\nClick: http://secure-login.ru/verify"
        score, detections = self.checker.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("tld" in d.lower() or ".ru" in d for d in detections))

    def test_detects_ip_url(self) -> None:
        content = "Verify here: http://192.168.0.1/login"
        score, detections = self.checker.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("ip" in d.lower() for d in detections))

    def test_detects_url_shortener(self) -> None:
        content = "Click this link: https://bit.ly/abc123"
        score, detections = self.checker.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("shortener" in d.lower() for d in detections))

    def test_detects_sender_spoofing(self) -> None:
        content = "From: PayPal Security <security@random-domain.com>"
        score, detections = self.checker.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("spoof" in d.lower() for d in detections))

    def test_detects_free_provider_impersonation(self) -> None:
        content = "From: Microsoft Support <microsoft-help@gmail.com>"
        score, detections = self.checker.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("free" in d.lower() or "provider" in d.lower() for d in detections))

    def test_clean_url_scores_zero(self) -> None:
        content = "From: no-reply@medium.com\nRead more: https://medium.com/article"
        score, _ = self.checker.analyze(content)
        self.assertEqual(score, 0)

    def test_detects_typosquatting(self) -> None:
        content = "Visit http://paypa1.com/secure/login to verify."
        score, detections = self.checker.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("typosquat" in d.lower() or "misspell" in d.lower() for d in detections))


# ---------------------------------------------------------------------------
# AttachmentScanner
# ---------------------------------------------------------------------------


class TestAttachmentScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = AttachmentScanner()

    def test_detects_exe_attachment(self) -> None:
        content = "Please open the attached file: setup.exe"
        score, detections = self.scanner.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any(".exe" in d for d in detections))

    def test_detects_zip_attachment(self) -> None:
        content = "See the documents enclosed: report_q4.zip"
        score, detections = self.scanner.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any(".zip" in d for d in detections))

    def test_detects_macro_document(self) -> None:
        content = "Please review: quarterly_update.docm"
        score, detections = self.scanner.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any(".docm" in d for d in detections))

    def test_detects_double_extension(self) -> None:
        content = "Filename: invoice.pdf.exe"
        score, detections = self.scanner.analyze(content)
        self.assertGreater(score, 0)
        self.assertTrue(any("double" in d.lower() for d in detections))

    def test_clean_attachment_scores_zero(self) -> None:
        content = "Attached is the meeting agenda: agenda.txt"
        score, detections = self.scanner.analyze(content)
        self.assertEqual(score, 0)
        self.assertEqual(detections, [])

    def test_score_does_not_exceed_cap(self) -> None:
        content = "Files: a.exe b.scr c.bat d.cmd e.msi f.vbs g.ps1 h.jar i.zip j.docm"
        score, _ = self.scanner.analyze(content)
        self.assertLessEqual(score, 50)


# ---------------------------------------------------------------------------
# RiskScoreEngine
# ---------------------------------------------------------------------------


class TestRiskScoreEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskScoreEngine()

    def test_low_risk_classification(self) -> None:
        score, level = self.engine.compute([5, 5, 5])
        self.assertEqual(level, "LOW")
        self.assertEqual(score, 15)

    def test_medium_risk_classification(self) -> None:
        score, level = self.engine.compute([15, 20, 15])
        self.assertEqual(level, "MEDIUM")
        self.assertEqual(score, 50)

    def test_high_risk_classification(self) -> None:
        score, level = self.engine.compute([30, 30, 30])
        self.assertEqual(level, "HIGH")
        self.assertGreaterEqual(score, 66)

    def test_score_capped_at_100(self) -> None:
        score, _ = self.engine.compute([999, 999, 999])
        self.assertEqual(score, 100)

    def test_zero_score_is_low(self) -> None:
        score, level = self.engine.compute([0, 0, 0])
        self.assertEqual(score, 0)
        self.assertEqual(level, "LOW")


# ---------------------------------------------------------------------------
# EmailAnalyzer (integration)
# ---------------------------------------------------------------------------


class TestEmailAnalyzerIntegration(unittest.TestCase):
    """
    Integration tests that read real sample files from the samples/ directory.
    These tests verify the full analysis pipeline end-to-end.
    """

    SAMPLES = Path(__file__).resolve().parent.parent / "samples"

    def setUp(self) -> None:
        self.analyzer = EmailAnalyzer()

    def _analyze(self, filename: str) -> dict:
        result = self.analyzer.analyze(self.SAMPLES / filename)
        self.assertIsNotNone(result, f"Analyzer returned None for {filename}")
        return result

    def test_phishing_email_1_is_high_risk(self) -> None:
        result = self._analyze("phishing_email_1.txt")
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertGreater(result["risk_score"], 65)
        self.assertGreater(len(result["detections"]), 0)

    def test_phishing_email_2_is_high_or_medium_risk(self) -> None:
        result = self._analyze("phishing_email_2.txt")
        self.assertIn(result["risk_level"], ("HIGH", "MEDIUM"))
        self.assertGreater(result["risk_score"], 30)

    def test_phishing_email_3_is_not_low_risk(self) -> None:
        result = self._analyze("phishing_email_3.txt")
        self.assertNotEqual(result["risk_level"], "LOW")

    def test_legitimate_email_is_low_risk(self) -> None:
        result = self._analyze("legitimate_email_1.txt")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertLessEqual(result["risk_score"], 30)

    def test_result_has_required_keys(self) -> None:
        result = self._analyze("phishing_email_1.txt")
        required_keys = {
            "email_file", "analyzed_at", "risk_level",
            "risk_score", "detections", "score_breakdown",
        }
        self.assertTrue(required_keys.issubset(result.keys()))

    def test_missing_file_returns_none(self) -> None:
        result = self.analyzer.analyze(Path("nonexistent_email.txt"))
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
