"""
Analyzes URLs and sender fields for suspicious domain indicators.
"""

from typing import List, Tuple
from urllib.parse import urlparse

from app.core.constants import SCORE_WEIGHTS
from app.core.patterns import (
    BRAND_MISSPELLINGS,
    FREE_EMAIL_PROVIDERS,
    PATTERNS,
    SPOOFED_BRANDS,
    SUSPICIOUS_TLDS,
)


class DomainChecker:
    """
    Evaluates every URL and the From: header for:
      - Suspicious TLDs (.ru, .tk, …)
      - Brand names used as subdomains on unrelated domains
      - Typosquatted brand names
      - IP-address URLs
      - URL shorteners
      - Sender display-name / domain mismatch
      - Corporate brand impersonation via free e-mail providers
    """

    _MAX_SCORE = 60

    def analyze(self, content: str) -> Tuple[int, List[str]]:
        """
        Return (score_contribution, detections) after inspecting all URLs
        and the From: header found in *content*.
        """
        detections: list[str] = []
        score = 0

        # --- IP-address URLs --------------------------------------------------
        ip_urls = PATTERNS["ip_url"].findall(content)
        if ip_urls:
            score += 20
            detections.append(
                f"IP-address URL detected (evades domain reputation checks): {ip_urls[0]}"
            )

        # --- URL shorteners ---------------------------------------------------
        if PATTERNS["shortened_url"].search(content):
            score += 15
            detections.append(
                "URL shortener detected (hides true destination from the recipient)"
            )

        # --- Per-URL inspection -----------------------------------------------
        seen_domains: set[str] = set()
        for url in PATTERNS["url"].findall(content):
            domain = self._extract_domain(url)
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            if hit := self._check_tld(domain):
                score += SCORE_WEIGHTS["domain"]
                detections.append(f"Suspicious top-level domain detected: {hit}")

            if hit := self._check_brand_subdomain(domain):
                score += SCORE_WEIGHTS["sender_spoof"]
                detections.append(f"Brand used as subdomain on unrelated host: {hit}")

            if hit := self._check_misspelling(domain):
                score += SCORE_WEIGHTS["domain"]
                detections.append(f"Typosquatted brand name in domain: {hit}")

            if domain.count(".") >= 3:
                score += 8
                detections.append(
                    f"Excessive subdomain depth (evasion technique): {domain}"
                )

        # --- Sender analysis --------------------------------------------------
        sender_raw = self._extract_sender(content)
        if sender_raw:
            s, d = self._analyze_sender(sender_raw)
            score += s
            detections.extend(d)

        return min(score, self._MAX_SCORE), list(dict.fromkeys(detections))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower().split(":")[0]  # strip port
        except Exception:
            return ""

    @staticmethod
    def _extract_sender(content: str) -> str:
        match = PATTERNS["from_header"].search(content)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _check_tld(domain: str) -> str:
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return f"{domain}  (TLD: {tld})"
        return ""

    @staticmethod
    def _check_brand_subdomain(domain: str) -> str:
        """Flag '<brand>.attacker.com' patterns."""
        parts = domain.split(".")
        if len(parts) < 3:
            return ""
        subdomain = ".".join(parts[:-2])
        for brand in SPOOFED_BRANDS:
            if brand in subdomain:
                apex = ".".join(parts[-2:])
                return f'"{brand}" in subdomain of {apex}'
        return ""

    @staticmethod
    def _check_misspelling(domain: str) -> str:
        for misspelling in BRAND_MISSPELLINGS:
            if misspelling in domain:
                return f'"{misspelling}" found in {domain}'
        return ""

    @staticmethod
    def _analyze_sender(sender: str) -> Tuple[int, List[str]]:
        score = 0
        detections: list[str] = []
        sender_lower = sender.lower()

        match = PATTERNS["email_address"].search(sender)
        if not match:
            return score, detections

        email_addr = match.group(0).lower()
        email_domain = email_addr.split("@", 1)[-1]

        for brand in SPOOFED_BRANDS:
            if brand not in sender_lower:
                continue

            # Brand name in display text but email domain is different
            if brand not in email_domain:
                score += SCORE_WEIGHTS["sender_spoof"]
                detections.append(
                    f'Sender spoofing: "{brand}" in display name but actual domain is "{email_domain}"'
                )
                break

        for brand in SPOOFED_BRANDS:
            if brand in sender_lower:
                for provider in FREE_EMAIL_PROVIDERS:
                    if email_domain == provider:
                        score += 20
                        detections.append(
                            f"Corporate brand impersonated via free e-mail provider: {email_addr}"
                        )
                        break

        return score, detections
