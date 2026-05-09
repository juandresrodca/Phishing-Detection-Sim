"""
Keyword lists, brand lists, and compiled regex patterns used across analyzers.
"""

import re

# ---------------------------------------------------------------------------
# Phishing vocabulary
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS: list[str] = [
    "urgent", "immediately", "act now", "limited time",
    "verify your account", "confirm your account",
    "password expired", "password reset", "reset your password",
    "click here", "click below", "click the link",
    "security alert", "security warning", "account suspended",
    "unusual activity", "suspicious activity",
    "verify your identity", "confirm your identity",
    "your account has been", "your account will be",
    "bank account", "credit card", "social security",
    "update your information", "update your details",
    "congratulations", "you have won", "winner selected",
    "free gift", "prize", "reward", "gift card",
    "invoice attached", "document attached",
    "action required", "immediate action",
    "dear customer", "dear user", "dear client",
    "verify now", "confirm now",
    "login", "log in", "sign in",
]

URGENCY_PHRASES: list[str] = [
    "within 24 hours", "within 48 hours", "in the next 24 hours",
    "account will be closed", "account will be suspended",
    "account will be terminated", "immediately or",
    "or your account", "failure to respond",
    "your account expires", "last warning",
    "final notice", "respond immediately",
    "time sensitive", "expires today",
]

SOCIAL_ENGINEERING_PHRASES: list[str] = [
    "do not share this", "keep this confidential",
    "this is not spam", "this is a legitimate",
    "we will never ask", "for security purposes",
    "to protect your account", "to keep your account safe",
    "from our security team", "from our fraud department",
    "your information is safe", "we take your privacy",
]

# ---------------------------------------------------------------------------
# Domain / URL threat intelligence
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: list[str] = [
    ".ru", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".download",
    ".review", ".country", ".kim", ".science",
    ".work", ".party", ".gdn", ".racing",
    ".faith", ".loan", ".win", ".bid",
]

# Brands most commonly impersonated in phishing campaigns
SPOOFED_BRANDS: list[str] = [
    "paypal", "amazon", "microsoft", "apple", "google",
    "facebook", "netflix", "instagram", "twitter",
    "wellsfargo", "bankofamerica", "chase", "citibank",
    "hsbc", "barclays", "dhl", "fedex", "ups",
    "irs", "linkedin", "dropbox", "docusign", "zoom",
    "office365", "outlook",
]

# Typosquatting / homoglyph misspellings of popular brands
BRAND_MISSPELLINGS: set[str] = {
    "paypa1", "paypai", "paypa!", "paypall",
    "micros0ft", "micosoft", "microsfot", "microsofft",
    "arnazon", "amazzon", "amaz0n", "arnaz0n",
    "app1e", "appie", "aple",
    "g00gle", "gogle", "g0ogle",
    "netf1ix", "netfix", "netlfix",
    "faceb00k", "facebok",
}

FREE_EMAIL_PROVIDERS: list[str] = [
    "gmail.com", "yahoo.com", "hotmail.com",
    "outlook.com", "protonmail.com", "aol.com",
]

# ---------------------------------------------------------------------------
# Attachment risk classification
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS: list[str] = [
    # Executable / script (.com excluded — collides with domain names in plain-text email)
    ".exe", ".scr", ".bat", ".cmd", ".msi",
    ".vbs", ".js", ".jar", ".ps1", ".psm1", ".psd1",
    # Archive (often used to bypass AV scanning)
    ".zip", ".rar", ".7z", ".tar", ".gz",
    # Macro-enabled Office documents
    ".docm", ".xlsm", ".pptm",
    # Disk images
    ".iso", ".img", ".dmg",
    # HTML phishing pages
    ".html", ".htm",
]

VERY_HIGH_RISK_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
})
HIGH_RISK_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".jar", ".iso", ".img", ".dmg",
})
MEDIUM_RISK_EXTENSIONS: frozenset[str] = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz", ".docm", ".xlsm", ".pptm",
})
LOW_RISK_EXTENSIONS: frozenset[str] = frozenset({
    ".html", ".htm",
})

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

PATTERNS: dict[str, re.Pattern] = {
    "url": re.compile(
        r"https?://[^\s<>\"{}|\\^`\[\]]+",
        re.IGNORECASE,
    ),
    "email_address": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    ),
    "ip_url": re.compile(
        r"https?://\d{1,3}(?:\.\d{1,3}){3}",
    ),
    "shortened_url": re.compile(
        r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|"
        r"is\.gd|buff\.ly|adf\.ly|tiny\.cc|shorte\.st)/\S+",
        re.IGNORECASE,
    ),
    "from_header": re.compile(
        r"^From:\s*(.+)$",
        re.MULTILINE | re.IGNORECASE,
    ),
    "subject_header": re.compile(
        r"^Subject:\s*(.+)$",
        re.MULTILINE | re.IGNORECASE,
    ),
    "double_extension": re.compile(
        r"\b\w[\w\- ]+\.\w{2,4}\.\w{2,4}\b",
        re.IGNORECASE,
    ),
}

# Build attachment filename pattern from the extension list at import time
_ext_group = "|".join(re.escape(e) for e in DANGEROUS_EXTENSIONS)
PATTERNS["attachment_filename"] = re.compile(
    rf"\b[\w\-. ]+(?:{_ext_group})\b",
    re.IGNORECASE,
)
