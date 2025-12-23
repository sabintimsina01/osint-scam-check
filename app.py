# app.py
import re
import socket
from urllib.parse import urlparse

import streamlit as st
import tldextract
import dns.resolver


# =========================================================
# 0) URL auto-detection helper (extract first URL)
# =========================================================
URL_RE = re.compile(r"(https?://\S+|www\.\S+|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\S*)")

def extract_first_url(text: str):
    if not text:
        return None
    m = URL_RE.search(text)
    if not m:
        return None
    url = m.group(0).strip("()[]{}<>.,!\"'")
    if url.startswith("www."):
        url = "https://" + url
    if "://" not in url and "." in url:
        url = "https://" + url
    return url


# =========================================================
# 1) Scam pattern library (tuned)
# =========================================================
SCAM_PATTERNS = [
    (r"\burgent\b|\bimmediately\b|\bact now\b|\blimited time\b|\bfinal notice\b", 2, "Urgency pressure"),
    (r"\bbitcoin\b|\bcrypto\b|\busdt\b|\bwallet\b|\bcoinbase\b", 3, "Crypto payment mention"),
    (r"\bfee\b|\bverification\b|\bunlock\b|\brelease funds\b|\bprocessing fee\b", 2, "Pay-to-release / verification fee"),
    (r"\bthreat\b|\barrest\b|\bsuspend(ed)?\b|\baccount closed\b|\blegal action\b|\bpermanently\b", 3, "Threat / coercion language"),
    (r"\bguarantee(d)?\b|\bno risk\b|\b100%\b|\binstant approval\b", 2, "Too-good-to-be-true promise"),

    # FIX 1: stronger credential-lure detection (weight increased)
    (r"\bconfirm your account\b|\bverify your account\b|\blogin\b|\breset password\b", 3, "Credential harvesting attempt"),

    # FIX 2: brand impersonation (high-impact)
    (r"\bpaypal\b|\bamazon\b|\bapple\b|\bnetflix\b|\bgoogle\b|\bmicrosoft\b|\bbank\b", 3, "Brand impersonation"),
]


# =========================================================
# 2) Helpers
# =========================================================
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
    return {
        "input_url": url,
        "host": host,
        "registered_domain": reg_domain,
        "subdomain": ext.subdomain,
    }


def dns_ip_lookup(host: str) -> dict:
    out = {"a_records": [], "ip_guess": None, "dns_error": None}
    try:
        answers = dns.resolver.resolve(host, "A")
        out["a_records"] = [str(a) for a in answers]
        out["ip_guess"] = out["a_records"][0] if out["a_records"] else None
    except Exception as e:
        out["dns_error"] = str(e)

    # fallback
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


def extract_urls(text: str) -> list[str]:
    """
    Pull URLs from message text.
    Accepts http(s)://... and bare domains like example.com/path
    """
    text = text or ""
    urls = set()

    # 1) Full URLs
    for m in re.findall(r"https?://[^\s)>\]]+", text, flags=re.IGNORECASE):
        urls.add(m.rstrip(".,!?:;\"'"))

    # 2) Bare domains (simple)
    for m in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s)>\]]*)?\b", text, flags=re.IGNORECASE):
        if "@" in m:
            continue
        urls.add(m.rstrip(".,!?:;\"'"))

    return sorted(urls)


def explain_risk(msg_out: dict) -> list[str]:
    return [hit["label"] for hit in msg_out.get("pattern_hits", [])]


# FIX 3: suspicious-domain scoring
def domain_risk(domain: dict) -> int:
    host = (domain or {}).get("host", "") or ""
    risky_terms = ["secure", "verify", "login", "support", "center", "account", "alert", "billing", "refund", "update"]
    return sum(1 for t in risky_terms if t in host)


# =========================================================
# 3) UI (Clean single page)
# =========================================================
st.set_page_config(page_title="Scam Check", layout="wide")

st.title("🔍 Scam Check")
st.caption("Paste a suspicious message or link. This tool flags common scam patterns and suggests next steps.")

col1, col2 = st.columns([1, 1])
with col1:
    url_in = st.text_input(
        "URL or Domain (optional)",
        placeholder="example.com or https://example.com/login",
        key="url_input_main",
    )
with col2:
    st.write("")
    st.write("Tip: Paste a message with a link — we’ll auto-detect it.")

msg_in = st.text_area(
    "Message text (recommended)",
    height=160,
    placeholder="Paste SMS/email text here...",
    key="msg_input_main",
)

# Auto-fill URL if found in message and user left URL blank
auto_url = extract_first_url(msg_in)
if auto_url and not url_in:
    st.info(f"🔎 Detected URL from message: {auto_url}")
    url_in = auto_url

run = st.button("✅ Check for Scam Risk", use_container_width=True)

if run:
    detected_urls = extract_urls(msg_in)
    chosen_url = (url_in or "").strip()

    if not chosen_url and detected_urls:
        chosen_url = detected_urls[0]  # simple: pick the first

    # Message scan (base score)
    msg_out = message_scan(msg_in)
    score = msg_out["pattern_score"]

    # Domain + DNS (optional) + add domain risk points
    domain = None
    dns_out = None
    if chosen_url:
        url_norm = normalize_input(chosen_url)
        domain = extract_domain(url_norm)
        dns_out = dns_ip_lookup(domain["host"])

        # add suspicious-domain points
        score += domain_risk(domain)

    # final label AFTER all scoring
    label = risk_label(score)

    # Big risk banner
    st.divider()
    if label == "HIGH":
        st.error(f"🔴 HIGH SCAM RISK — Score: {score}")
    elif label == "MED":
        st.warning(f"🟡 MEDIUM SCAM RISK — Score: {score}")
    else:
        st.success(f"🟢 LOW SCAM RISK — Score: {score}")

    # Show detected URLs (visible feature)
    if detected_urls:
        st.info(
            "🔗 Detected link(s) in message: "
            + ", ".join(detected_urls[:3])
            + (" ..." if len(detected_urls) > 3 else "")
        )

    # Why risky
    st.subheader("Why this looks risky")
    reasons = explain_risk(msg_out)

    # Also surface domain-risk reasons in human terms
    if domain:
        extra = domain_risk(domain)
        if extra > 0:
            reasons.append("Suspicious domain wording (e.g., 'verify', 'login', 'secure', 'refund')")

    if reasons:
        for r in reasons:
            st.write(f"⚠️ {r}")
    else:
        st.write("✅ No common scam patterns detected in the message text.")

    # Clear action box
    st.subheader("What you should do now")
    if label == "HIGH":
        st.error(
            "🚫 **Do NOT click links, do NOT reply, and do NOT send money/crypto.**\n\n"
            "- Contact the company using the official website or phone number you find independently.\n"
            "- If this involves a bank or payment account, log in by typing the official site yourself (not the link).\n"
            "- If you’re unsure, ask a trusted person before acting."
        )
    elif label == "MED":
        st.warning(
            "⚠️ **Be cautious and verify before acting.**\n\n"
            "- Verify the request using a trusted source.\n"
            "- Do not rush. Scammers rely on urgency.\n"
            "- Avoid sharing passwords, codes, or personal information."
        )
    else:
        st.success(
            "✅ **No strong scam indicators detected.**\n\n"
            "- Still be careful if money, passwords, or codes are requested.\n"
            "- If anything feels off, verify independently."
        )

    # Technical details (optional)
    with st.expander("Technical details (for testing)"):
        if domain:
            st.write("**Domain parsing**")
            st.json(domain)
        else:
            st.write("No URL/domain provided or detected.")

        if dns_out:
            st.write("**DNS / IP lookup**")
            st.json(dns_out)

        st.write("**Message scan output**")
        st.json(msg_out)

    st.caption("⚠️ This tool provides risk signals, not guarantees. Always verify independently.")
