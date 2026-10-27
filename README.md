# CyberSafe Edu

**An explainable phishing-awareness and message-analysis tool**

CyberSafe Edu is a student cybersecurity awareness project. It helps users learn about common phishing indicators by inspecting URL text and analysing pasted message text with transparent, rule-based heuristics. It also includes short learning material, a five-question awareness quiz, safety recommendations, and JSON export of analysis results.

## Features

- **URL Inspector:** checks URL text for configurable clues such as non-HTTPS schemes, IP-address hosts, URL shorteners, long hostnames, and suspicious-looking URL patterns.
- **Message Analyzer:** scans message text for urgency, credential requests, unusual payment terms, links, and other configured phrases.
- **Explainable results:** displays the indicators that triggered the score and practical next steps.
- **Awareness learning section:** explains common phishing tactics.
- **Five-question quiz:** gives immediate feedback and a score.
- **JSON export:** download a result for review or documentation.
- **Local-only analysis:** the app does not visit URLs or call external reputation services.

## Technologies

- Python 3.10 or newer recommended
- Streamlit
- Python standard library: `re`, `json`, `datetime`, and `urllib.parse`

## Dataset

**No external dataset is used or required.** The prototype uses a small set of manually defined warning phrases and URL-text heuristics within `app.py`. These are educational rules, not a statistically validated detection model.

## Setup and run

1. Install Python 3.10+.
2. Download or clone this repository.
3. Open a terminal in the project directory.
4. Create and activate a virtual environment (recommended).

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Streamlit will print a local address (usually `http://localhost:8501`) to open in your browser.

## How to use

1. Open **URL Inspector** and paste URL text. The app analyses the text only; it does not open the link.
2. Open **Message Analyzer** and paste a suspicious message. Use fictional or sanitised examples.
3. Review the indicators and recommended next steps.
4. Download the JSON result if needed.
5. Explore **Learn** and complete the **Awareness Quiz**.

## Project structure

```text
CyberSafe-Edu/
├── app.py
├── requirements.txt
├── README.md
├── AryanDas_CyberSafeEdu_ProjectReport.docx
└── AryanDas_CyberSafeEdu.ipynb
```

## Important limitations and responsible use

- This is an educational prototype, not an enterprise phishing detector.
- A high signal means several configured rules matched; it is not a probability or a confirmed malicious verdict.
- False positives and false negatives are possible.
- The app does not use a trained machine-learning model, external dataset, URL crawling, or live threat-intelligence lookup.
- Do not enter real credentials, OTPs, confidential communications, or sensitive personal information.
- Verify suspicious requests through an independent, trusted channel and report incidents to the appropriate institution or service provider.

## Author

**Project author:** Aryan Das  
**Project:** CyberSafe Edu — Explainable Phishing-Awareness and Message-Analysis Tool  
**Programme:** IBM SkillsBuild Cyber Security Bootcamp 2026, conducted by BharatCares

Before submitting, check that your full name, institution, and other form details are accurate. If your certificate name should use a different spelling or full legal name, update the author field in this README and the report.

## Licence

Created for educational and academic submission. Add a licence if you intend to publish and reuse the project publicly.
