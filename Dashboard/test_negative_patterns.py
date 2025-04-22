import re

# ────────────────────────────────────────────
# Re‑define or import your pre‑compiled patterns
# ────────────────────────────────────────────
CVE_RE     = re.compile(r'\bCVE-\d{4}-\d{4,5}\b')
URL_RE = re.compile(
    r'\bhttps?://[A-Za-z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+', 
    flags=re.IGNORECASE
)
EMAIL_RE   = re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b')
HASH_RE    = re.compile(r'\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b')
IP_PORT_RE = re.compile(
    r'\b'                                   
    r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}'  # three octets 0–255
    r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)'           # last octet
    r':'
    r'(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])'  
    r'\b'
)

# ────────────────────────────────────────────
# Negative test samples (should produce zero matches)
# ────────────────────────────────────────────
negatives = {
    "CVE": [
        "CVE-20A1-1234", "XCVE-2021-1234", "CVE-20211234", "2021.1234"
    ],
    "URL": [
        "not_a_url.com/", "http//broken.com", "just.text"
    ],
    "Email": [
        "user@@example.com", "@example.com", "user@example"
    ],
    "Hash": [
        "abc123", "g1234567890abcdef", "1234567890abcdef"
    ],
    "IP_PORT": [
        "256.1.1.1:80", "192.168.1.1:", ":8080"
    ]
}

pattern_map = {
    "CVE": CVE_RE,
    "URL": URL_RE,
    "Email": EMAIL_RE,
    "Hash": HASH_RE,
    "IP_PORT": IP_PORT_RE
}

# ────────────────────────────────────────────
# Run the negative tests
# ────────────────────────────────────────────
if __name__ == "__main__":
    for name, samples in negatives.items():
        pat = pattern_map[name]
        print(f"\n--- Negative tests for {name} ---")
        for s in samples:
            match = pat.search(s)
            if match:
                print(f"❌  Unexpected match: {name} pattern matched '{match.group(0)}' in {repr(s)}")
            else:
                print(f"✅  No match (ok): {repr(s)}")
