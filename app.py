import re
import socket
from urllib.parse import urlparse

import streamlit as st
import tldextract
import dns.resolver


SCAM_PATTERNS = [
    (r"\burgent\b|\bimmediately\b|\bact now\b|\blimited time\b", 2, "Urgency pressure"),
    (r"\bbitcoin\b|\bcrypto\b|\busdt\b|\bwallet\b", 3, "Crypto payment"),
    (r"\bfee\b|\bverification\b|\bunlock\b|\brelease funds\b", 2, "Pay-to-release / verification"),
    (r"\bthreat\b|\barrest\b|\bsuspend(ed)?\b|\baccount closed\b", 3, "Threat / coercion"),
    (r"\bguarantee(d)?\b|\bno risk\b|\b100%\b", 2, "Too-good-to-be-true promise"),
    (r"\bclick here\b|\blink\b|\breset password\b", 1, "Click-bait / credential lure"),
]


def normalize_input(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "https://" + u
    return u


def extract_domain(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    host = host.split("@")[-1].split(":")[0].strip().lower()
    ext = tldextract.extract(host)
    reg_domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    return {"input_url": url, "host": host, "registered_domain": reg_domain, "subdomain": ext.subdomain}


def dns_ip_lookup(host: str) -> dict:
    out = {"a_records": [], "ip_guess": None, "dns_error": None}
    try:
        answers = dns.resolver.resolve(host, "A")
        out["a_records"] = [str(a) for a in answers]
        out["ip_guess"] = out["a_records"][0] if out["a_records"] else None
    except Exception as e:
        out["dns_error"] = str(e)

    if not out["ip_guess"]:
        try:
            out["ip_guess"] = socket.gethostbyname(host)
        except Exception:
            pass
    return out


def message_scan(text: str) -> dict:
    text = (text or "").strip()
    hits = []
    score = 0
    for pattern, weight, label in SCAM_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append({"label": label, "weight": weight})
            score += weight
    return {"pattern_hits": hits, "pattern_score": score}


def risk_label(score: int) -> str:
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MED"
    return "LOW"


def explain_risk(msg_out: dict) -> list[str]:
    explanations = []
    for hit in msg_out.get("pattern_hits", []):
        explanations.append(f"- {hit['label']}")
    return explanations



st.set_page_config(page_title="OSINT Scam-Check Prototype", layout="wide")
st.title("OSINT Scam-Check Prototype (Step 4: DNS + Message Scanner)")

url_in = st.text_input(
    "URL or Domain",
    placeholder="example.com or https://example.com/login",
    key="url_input_step4",
)
msg_in = st.text_area(
    "Message text (optional)",
    height=130,
    placeholder="Paste SMS/email text here...",
    key="msg_input_step4",
)

if st.button("Run Scam-Check (DNS + Message)"):
    if not url_in.strip():
        st.error("Please enter a URL or domain.")
    else:
        url = normalize_input(url_in)
        domain = extract_domain(url)
        dns_out = dns_ip_lookup(domain["host"])
        msg_out = message_scan(msg_in)

        # Very simple combined score (only message patterns for now)
        score = msg_out["pattern_score"]
        label = risk_label(score)

        st.subheader("Risk (prototype)")

        if label == "HIGH":
            st.error(f"🔴 HIGH RISK — Score: {score}")
        elif label == "MED":
            st.warning(f"🟡 MEDIUM RISK — Score: {score}")
        else:
            st.success(f"🟢 LOW RISK — Score: {score}")


        st.subheader("Why this looks risky")

        explanations = explain_risk(msg_out)

        if explanations:
            for e in explanations:
                st.write(e)
        else:
            st.write("No obvious scam patterns detected.")

        st.subheader("Recommended action")

        if label == "HIGH":
            st.write("❌ Do NOT send money or credentials. Contact the company through its official website.")
        elif label == "MED":
            st.write("⚠️ Be cautious. Verify the request using a trusted source before taking action.")
        else:
            st.write("✅ No immediate red flags detected, but remain cautious.")


        st.subheader("Domain Parsing")
        st.json(domain)

        st.subheader("DNS / IP Lookup")
        st.json(dns_out)

        st.subheader("Message Pattern Scan")
        st.json(msg_out)
