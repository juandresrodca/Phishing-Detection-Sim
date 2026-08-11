# Phishing Detection Simulator

> A lightweight SOC email triage tool that analyzes suspicious email samples and generates structured phishing risk assessment reports — built to demonstrate real-world security engineering skills.

![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Security](https://img.shields.io/badge/Domain-Cybersecurity%20%7C%20SOC-red)

---

## Overview

The **Phishing Detection Simulator** is a command-line tool designed to simulate how a junior SOC analyst triages potentially malicious emails. It reads raw email text files, runs them through a modular detection engine, assigns a risk score (LOW / MEDIUM / HIGH), and exports structured JSON and CSV reports — just like real SIEM/SOAR tooling.

This project is built with clean architecture principles, making it easy to extend with new detection modules, integrate into CI pipelines, or connect to live email sources via an API adapter.

---

## Features

| Feature | Description |
|---|---|
| Keyword Analysis | Detects phishing vocabulary, urgency language, and social engineering tactics |
| Domain & URL Inspection | Flags suspicious TLDs, URL shorteners, IP-address links, and brand spoofing |
| Attachment Scanning | Classifies dangerous attachment types across four risk tiers |
| Sender Spoofing Detection | Catches display-name / domain mismatches and corporate impersonation via free email |
| Modular Scoring Engine | Weighted, capped scoring per category — aggregated into a final 0–100 score |
| Colored Terminal Output | ANSI-colored risk levels and detection cards for fast human review |
| JSON Export | Structured machine-readable report for downstream SIEM ingestion |
| CSV Export | Spreadsheet-friendly summary for reporting and management reviews |
| CLI Arguments | Flexible invocation — scan one file, a whole directory, or customize output paths |
| Logging | Rotating file log (`phishing_detector.log`) alongside stderr warnings |
| Unit Test Suite | 20+ tests covering every module with both unit and integration coverage |

---

## Project Structure

```
phishing-detection-simulator/
│
├── app/
│   ├── analyzer/
│   │   ├── email_analyzer.py      # Orchestrates all detection modules
│   │   ├── keyword_detector.py    # Phishing keywords & social engineering phrases
│   │   ├── domain_checker.py      # URL & sender domain analysis
│   │   ├── attachment_scanner.py  # Dangerous attachment classification
│   │   └── risk_score.py          # Scoring engine & risk classification
│   │
│   ├── core/
│   │   ├── constants.py           # Risk levels, weights, color codes, paths
│   │   ├── patterns.py            # Keyword lists, regex patterns, extension sets
│   │   └── utils.py               # Logger, file I/O, terminal helpers
│   │
│   ├── reports/
│   │   └── report_generator.py    # JSON & CSV export
│   │
│   └── main.py                    # CLI entry point
│
├── samples/
│   ├── phishing_email_1.txt       # PayPal credential harvest (HIGH)
│   ├── phishing_email_2.txt       # Microsoft 365 password reset (HIGH)
│   ├── phishing_email_3.txt       # Fake HR rewards with macro attachment (HIGH)
│   └── legitimate_email_1.txt     # Newsletter from medium.com (LOW)
│
├── output/                        # Generated reports land here
├── tests/
│   └── test_analyzer.py           # 20+ unit & integration tests
│
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Detection Logic

### 1 — Keyword Analysis (`keyword_detector.py`).
Scans the full email body against three lists:
- **Phishing keywords** — `"verify your account"`, `"click here"`, `"password expired"`, …
- **Urgency phrases** — `"within 24 hours"`, `"account will be closed"`, `"final notice"`, …
- **Social engineering** — `"for security purposes"`, `"do not share this"`, …

### 2 — Domain & URL Analysis (`domain_checker.py`).
For every URL and the `From:` header:
- Suspicious TLDs (`.ru`, `.tk`, `.xyz`, `.click`, …)
- Brand names used as subdomains of unrelated domains (`paypal.attacker.com`)
- Typosquatted brand names (`paypa1`, `micros0ft`, `amaz0n`, …)
- IP-address URLs that bypass domain reputation lookups
- URL shorteners hiding the true destination
- Sender display-name / email domain mismatch
- Corporate brand impersonated via a free email provider (Gmail, Outlook, …).

### 3 — Attachment Analysis (`attachment_scanner.py`)
Matches filenames in both body and headers, classified in four tiers:

| Risk Tier | Extensions |
|---|---|
| Very High | `.exe` `.scr` `.bat` `.cmd` `.msi` `.vbs` `.ps1` |
| High | `.js` `.jar` `.iso` `.img` `.dmg` |
| Medium | `.zip` `.rar` `.7z` `.docm` `.xlsm` `.pptm` |
| Low | `.html` `.htm` |

Also detects **double-extension masquerading** (`invoice.pdf.exe`).

### 4 — Risk Score (`risk_score.py`)
Sub-scores from each module are summed, clamped to `[0, 100]`, then classified:

| Score Range | Risk Level |
|---|---|
| 0 – 30 | LOW |
| 31 – 65 | MEDIUM |
| 66 – 100 | HIGH |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/phishing-detection-simulator.git
cd phishing-detection-simulator

# 2. Create a virtual environment (recommended)
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Analyze all sample emails (default)
```bash
python -m app.main
```

### Analyze a single email file
```bash
python -m app.main --file samples/phishing_email_1.txt
```

### Custom output directory
```bash
python -m app.main --output-dir ./reports
```

### Skip CSV export
```bash
python -m app.main --no-csv
```

### Enable verbose/debug logging
```bash
python -m app.main --verbose
```

### Full option reference
```
python -m app.main --help

options:
  -h, --help            show this help message and exit
  --file PATH, -f PATH  Analyze a single email file
  --samples-dir DIR     Directory containing sample emails (default: samples/)
  --output-dir DIR, -o DIR
                        Directory to write reports (default: output/)
  --no-json             Suppress JSON report export
  --no-csv              Suppress CSV report export
  --verbose, -v         Enable DEBUG-level logging
```

---

## Example Terminal Output

```
╔══════════════════════════════════════════════════════════════╗
║        PHISHING DETECTION SIMULATOR  v1.0.0                 ║
║        SOC Analyst Email Triage Tool                        ║
╚══════════════════════════════════════════════════════════════╝

  Scanning 4 email(s) …

────────────────────────────────────────────────────────────────
  File:        phishing_email_1.txt
  Analyzed:    2025-01-15T14:32:01Z
  Risk Level:  HIGH
  Risk Score:  95/100
  Breakdown  →  Keywords: 30  Domains: 50  Attachments: 30

  Indicators Detected:
    ▸ Phishing keywords detected: "verify your account", "click here", "urgent"
    ▸ Urgency / fear-tactic language detected: "within 24 hours"
    ▸ Social engineering phrases detected: "do not share this", "for security purposes"
    ▸ Suspicious top-level domain detected: paypa1-support.ru  (TLD: .ru)
    ▸ Typosquatted brand name in domain: "paypa1" found in paypa1-support.ru
    ▸ Sender spoofing: "paypal" in display name but actual domain is "paypa1-support.ru"
    ▸ Executable / script attachment detected — extremely high risk: *.exe

════════════════════════════════════════════════════════════════
  ANALYSIS SUMMARY
════════════════════════════════════════════════════════════════
  Emails analyzed : 4
  HIGH             : 3
  MEDIUM           : 0
  LOW              : 1

  JSON report : output/analysis_report.json
  CSV  report : output/analysis_report.csv
════════════════════════════════════════════════════════════════
```

---

## Example JSON Report

```json
[
  {
    "email_file": "phishing_email_1.txt",
    "analyzed_at": "2025-01-15T14:32:01Z",
    "risk_level": "HIGH",
    "risk_score": 95,
    "detections": [
      "Phishing keywords detected: \"verify your account\", \"click here\", \"urgent\"",
      "Urgency / fear-tactic language detected: \"within 24 hours\"",
      "Suspicious top-level domain detected: paypa1-support.ru  (TLD: .ru)",
      "Typosquatted brand name in domain: \"paypa1\" found in paypa1-support.ru",
      "Sender spoofing: \"paypal\" in display name but actual domain is \"paypa1-support.ru\"",
      "Executable / script attachment detected — extremely high risk: *.exe"
    ],
    "score_breakdown": {
      "keyword_score": 30,
      "domain_score": 50,
      "attachment_score": 30
    }
  },
  {
    "email_file": "legitimate_email_1.txt",
    "analyzed_at": "2025-01-15T14:32:01Z",
    "risk_level": "LOW",
    "risk_score": 0,
    "detections": [],
    "score_breakdown": {
      "keyword_score": 0,
      "domain_score": 0,
      "attachment_score": 0
    }
  }
]
```

---

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ -v --cov=app --cov-report=term-missing
```

Expected output:
```
tests/test_analyzer.py::TestKeywordDetector::test_clean_email_has_low_score PASSED
tests/test_analyzer.py::TestKeywordDetector::test_detects_phishing_keywords PASSED
tests/test_analyzer.py::TestKeywordDetector::test_detects_urgency_language PASSED
tests/test_analyzer.py::TestDomainChecker::test_detects_ip_url PASSED
tests/test_analyzer.py::TestDomainChecker::test_detects_sender_spoofing PASSED
tests/test_analyzer.py::TestDomainChecker::test_detects_url_shortener PASSED
... (20+ tests)
```

---

## Screenshots

> _Add terminal screenshots here after running the tool._

| Terminal output | JSON report | CSV report |
|---|---|---|
| _(screenshot)_ | _(screenshot)_ | _(screenshot)_ |

---

## Skills Demonstrated

| Category | Skills |
|---|---|
| **Security Engineering** | Phishing indicator analysis, IOC detection, threat triage simulation, domain reputation heuristics |
| **Python Engineering** | OOP with clean interfaces, type hints, modular architecture, PEP 8 compliance |
| **SOC Tooling** | Risk scoring engines, structured reporting (JSON/CSV), SIEM-ready output format |
| **Software Design** | Single-responsibility modules, dependency injection, layered architecture |
| **Testing** | Unit tests, integration tests, edge-case coverage with `pytest` |
| **CLI UX** | `argparse` CLI, ANSI-colored output, human-readable terminal cards |
| **DevOps Basics** | `.gitignore`, virtual env, `requirements.txt`, MIT license, Git-ready structure |

---

## Future Improvements

- [ ] **MIME parser** — parse real `.eml` files including multipart MIME with base64-encoded payloads
- [ ] **VirusTotal API** — live URL and attachment hash reputation lookups
- [ ] **ML scoring layer** — replace heuristic weights with a trained NLP classifier
- [ ] **Elasticsearch output** — push reports directly to an ELK stack index
- [ ] **Web dashboard** — Flask/FastAPI frontend for non-technical analysts
- [ ] **YARA rule integration** — scan attachment content with YARA signatures
- [ ] **Header forgery detection** — deep SPF / DKIM / DMARC header analysis
- [ ] **Batch API mode** — REST endpoint to submit emails programmatically

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Author

**Juan Rodriguez** — Cybersecurity & Python Engineer  
_Built as a portfolio project to demonstrate SOC tooling and Python clean architecture._
