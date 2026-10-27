"""
CyberSafe Edu — Explainable Phishing-Awareness and Message-Analysis Tool
Educational prototype. It does not visit URLs or query external reputation services.
"""
import json
import re
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(page_title="CyberSafe Edu", page_icon="🛡️", layout="wide")

SUSPICIOUS_TERMS = {
    "urgent": "Creates pressure to act quickly",
    "immediately": "Creates pressure to act quickly",
    "verify your account": "Requests account verification",
    "password": "Mentions a password or credential",
    "bank": "Mentions banking or financial access",
    "account suspended": "Threatens account suspension",
    "click here": "Uses a generic click instruction",
    "limited time": "Uses scarcity or urgency",
    "gift card": "Requests or mentions a common scam payment method",
    "otp": "Mentions a one-time password",
    "one time password": "Mentions a one-time password",
    "wire transfer": "Requests an unusual payment method",
    "crypto": "Mentions cryptocurrency as a payment/investment hook",
    "prize": "Promises a prize or reward",
    "winner": "Claims the recipient has won something",
    "confirm your identity": "Requests identity confirmation",
    "download the attachment": "Encourages opening/downloading an attachment",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".work", ".support", ".country", ".gq", ".tk"}

def inspect_url(raw_url):
    """Inspect URL text only. Never opens or fetches the URL."""
    value = raw_url.strip()
    if not value:
        return {"input": "", "risk": "Unknown", "score": 0, "indicators": ["Enter a URL to inspect."], "recommendations": ["Do not share credentials or payment details with an unverified site."]}
    candidate = value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) else "https://" + value
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().strip(".")
        if not host or "." not in host:
            raise ValueError("No valid hostname")
    except Exception:
        return {"input": value, "risk": "Unknown", "score": 0, "indicators": ["The input could not be parsed as a typical web URL."], "recommendations": ["Check the spelling and inspect suspicious links without opening them."]}

    indicators = []
    score = 0
    if parsed.scheme.lower() != "https":
        indicators.append("The URL does not use HTTPS.")
        score += 1
    if "@" in parsed.netloc:
        indicators.append("The URL contains '@' in its network location, which can obscure the intended destination.")
        score += 2
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        indicators.append("The hostname is an IP address rather than a conventional domain.")
        score += 2
    if host.startswith("xn--") or ".xn--" in host:
        indicators.append("The hostname uses an internationalized/punycode label; verify it carefully.")
        score += 1
    if host.count("-") >= 3:
        indicators.append("The hostname contains several hyphens.")
        score += 1
    if len(host) > 35:
        indicators.append("The hostname is unusually long.")
        score += 1
    if host in URL_SHORTENERS:
        indicators.append("This is a URL-shortening domain, so the final destination is not visible here.")
        score += 2
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        indicators.append("The domain uses a TLD that can be abused; the TLD alone does not prove fraud.")
        score += 1
    brand_words = ("paypal", "microsoft", "google", "apple", "amazon", "bank")
    if any(word in host for word in brand_words) and not any(host == word + ".com" or host.endswith("." + word + ".com") for word in brand_words):
        indicators.append("A familiar brand-related word appears in the hostname; check the registrable domain carefully.")
        score += 1
    if len(parsed.path) > 70:
        indicators.append("The URL path is unusually long.")
        score += 1
    if not indicators:
        indicators.append("No configured URL-text warning rules were triggered. This does not establish that the URL is safe.")
    risk = "High" if score >= 4 else "Moderate" if score >= 2 else "Lower signal"
    recs = [
        "Do not enter passwords, one-time codes, or payment details from an unexpected link.",
        "Open the official app or type the known official domain yourself instead of following the message link.",
        "Confirm unusual requests using a separate, trusted contact method.",
    ]
    if score >= 2:
        recs.insert(0, "Treat this link cautiously and verify its destination through an independent channel.")
    return {"input": value, "hostname": host, "risk": risk, "score": score, "indicators": indicators, "recommendations": recs}

def analyze_message(message):
    """Rule-based text scan; findings are clues, not a verdict."""
    text = message.strip()
    if not text:
        return {"risk": "Unknown", "score": 0, "indicators": ["Paste a message to analyze."], "recommendations": ["Never share passwords or one-time codes in response to an unexpected message."]}
    lower = text.lower()
    indicators, score = [], 0
    for term, explanation in SUSPICIOUS_TERMS.items():
        if term in lower:
            indicators.append(f'Found phrase "{term}": {explanation}.')
            score += 1 if term not in {"otp", "password", "bank", "gift card", "wire transfer"} else 2
    if re.search(r"https?://|www\.", lower):
        indicators.append("The message contains a web link.")
        score += 1
    if re.search(r"\b(today|within \d+ hours?|now|immediately|asap)\b", lower):
        indicators.append("The message uses time pressure.")
        score += 1
    if re.search(r"\b\d{4,8}\b", text):
        indicators.append("The message contains a 4–8 digit number; verify whether it is a code or reference number.")
        score += 1
    if len(text) > 0 and text.count("!") >= 3:
        indicators.append("The message uses repeated exclamation marks.")
        score += 1
    if not indicators:
        indicators.append("No configured warning rules were triggered. This does not prove the message is legitimate.")
    risk = "High" if score >= 5 else "Moderate" if score >= 2 else "Lower signal"
    recs = [
        "Check the sender address and the exact domain, not just the display name or logo.",
        "Do not open unexpected attachments or share passwords, OTPs, recovery codes, or payment details.",
        "Contact the organization through its official website/app or a known phone number.",
        "Report suspected phishing using your institution or email provider's reporting process.",
    ]
    return {"risk": risk, "score": score, "indicators": indicators, "recommendations": recs}

def result_panel(result, title):
    st.subheader(title)
    c1, c2 = st.columns([1, 3])
    c1.metric("Rule-based signal", result.get("risk", "Unknown"))
    c2.metric("Indicator score (not a probability)", result.get("score", 0))
    st.caption("This is a transparent educational heuristic, not a malware scanner, reputation check, or guarantee.")
    st.markdown("**Indicators found**")
    for item in result.get("indicators", []):
        st.write("• " + item)
    st.markdown("**Recommended next steps**")
    for item in result.get("recommendations", []):
        st.write("• " + item)
    payload = {"tool": "CyberSafe Edu", "generated_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z", "result": result}
    st.download_button("Download analysis as JSON", json.dumps(payload, indent=2), file_name="cybersafe-analysis.json", mime="application/json")

st.title("🛡️ CyberSafe Edu")
st.caption("Understand suspicious messages and URL clues — without visiting links.")
st.info("Educational prototype: analyses text locally using simple rules. It does not contact websites, use an external dataset, or determine whether a URL is truly malicious.")

tab_url, tab_message, tab_learn, tab_quiz, tab_about = st.tabs(
    ["URL Inspector", "Message Analyzer", "Learn", "Awareness Quiz", "About & Limits"]
)

with tab_url:
    st.markdown("### Inspect a URL before you open it")
    url_input = st.text_input("Paste URL text", placeholder="https://example.com/login")
    if st.button("Inspect URL", type="primary", key="inspect_url"):
        result_panel(inspect_url(url_input), "URL inspection result")

with tab_message:
    st.markdown("### Check a suspicious email, SMS, or direct message")
    message_input = st.text_area("Paste message text", height=180, placeholder="Example: Your account is suspended. Verify your account immediately...")
    if st.button("Analyze message", type="primary", key="analyze_message"):
        result_panel(analyze_message(message_input), "Message analysis result")

with tab_learn:
    st.markdown("### Common phishing warning signs")
    lessons = [
        ("Urgency or threats", "Messages pressure you to act immediately, claim your account will be closed, or threaten penalties."),
        ("Unexpected links", "A visible brand name or padlock is not proof. Check the real domain and avoid shortened links in unexpected messages."),
        ("Credential or OTP requests", "Legitimate support staff should not ask you to reveal your password or one-time code."),
        ("Unusual payment methods", "Gift cards, cryptocurrency, or urgent wire transfers can be warning signs."),
        ("Unexpected attachments", "Verify the sender independently before opening attachments or enabling macros."),
        ("Independent verification", "Use the official app, a saved bookmark, or a known phone number rather than the contact details in the suspicious message."),
    ]
    for heading, body in lessons:
        with st.expander(heading):
            st.write(body)
    st.markdown("**Remember:** a warning sign is not proof of a scam, and a message with no warning signs may still be malicious.")

with tab_quiz:
    st.markdown("### Quick awareness quiz")
    questions = [
        ("An unexpected text asks for your OTP to prevent account closure. What should you do?", ["Reply with the OTP", "Do not share it; verify using the official app/site", "Forward it to a friend"], 1,
         "Never disclose OTPs. Contact the service through a trusted channel."),
        ("A link says `bank.example-login.com`. What matters most?", ["The word 'bank' anywhere in the URL", "The exact domain you would be visiting", "The page logo"], 1,
         "Look at the actual domain; brand words and logos can be copied."),
        ("A message has no spelling mistakes. Does that prove it is safe?", ["Yes", "No"], 1,
         "Professional wording does not establish legitimacy."),
        ("A colleague unexpectedly requests gift cards urgently. What is best?", ["Buy them quickly", "Verify through a separate known contact method", "Send the card codes"], 1,
         "Urgent payment requests should be independently verified."),
        ("What does this tool's 'High' signal mean?", ["A confirmed malware verdict", "Several configured warning rules matched", "The URL has been checked online"], 1,
         "The score is a transparent heuristic, not a probability or online reputation result."),
    ]
    with st.form("quiz_form"):
        answers = []
        for i, (question, options, correct, explanation) in enumerate(questions):
            answers.append(st.radio(f"{i+1}. {question}", options, key=f"q{i}", index=None))
        submitted = st.form_submit_button("Check answers")
    if submitted:
        score = 0
        for i, (question, options, correct, explanation) in enumerate(questions):
            selected = answers[i]
            if selected == options[correct]:
                score += 1
                st.success(f"Question {i+1}: Correct. {explanation}")
            else:
                st.warning(f"Question {i+1}: Review this. {explanation}")
        st.metric("Your score", f"{score}/{len(questions)}")

with tab_about:
    st.markdown("### Project overview")
    st.write("CyberSafe Edu is an explainable phishing-awareness learning tool that applies local, rule-based checks to URL text and message content.")
    st.markdown("### Scope and limitations")
    st.write("- No URLs are opened, fetched, or crawled.")
    st.write("- No external reputation API, trained machine-learning model, or external dataset is used.")
    st.write("- Rules can produce false positives and false negatives; scores are not probabilities.")
    st.write("- Do not paste real passwords, personal data, confidential messages, or live access tokens into this educational prototype.")
    st.write("- For real incidents, follow your institution's security reporting process and use trusted security tools.")
    st.markdown("### Technologies")
    st.write("Python, Streamlit, regular expressions, urllib.parse, JSON, and Python standard library.")
    st.markdown("### Dataset")
    st.write("No external dataset is required. The app uses a small, explicitly defined set of rule keywords and URL heuristics.")

st.divider()
st.caption("CyberSafe Edu • Student cybersecurity awareness project • Use as an educational aid, not as a security guarantee.")
