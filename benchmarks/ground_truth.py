"""Known vulnerability categories per benchmark target, used by
benchmarks/scorer.py to compute the project's evaluation metrics against a
real engagement's saved findings. Category names are the strings matched
(heuristically, case-insensitively, by substring) against each Finding's
vuln_type/tags - this is intentionally a coarse proxy, not exact
ground-truth labeling.

Each category is also mapped to an OWASP Top 10 (2021) class via
CATEGORY_TO_OWASP so the scorer can compute the PDF's "Detection Rate"
metric (target: 8/10 OWASP categories covered).
"""

# DVWA's own documented vulnerability modules (vulnerables/web-dvwa image,
# already used as the `dvwa` service in docker-compose.yml).
GROUND_TRUTH: dict[str, list[str]] = {
    "dvwa": [
        "Brute Force",
        "Command Injection",
        "CSRF",
        "File Inclusion",
        "File Upload",
        "Insecure CAPTCHA",
        "SQL Injection",
        "SQL Injection (Blind)",
        "Weak Session IDs",
        "XSS (Reflected)",
        "XSS (Stored)",
        "XSS (DOM)",
    ],
    # OWASP Juice Shop's published challenge categories. Not yet wired into
    # docker-compose.yml - see benchmarks/README.md to add it.
    "juice-shop": [
        "Injection",
        "Broken Authentication",
        "Sensitive Data Exposure",
        "Broken Access Control",
        "Security Misconfiguration",
        "XSS",
        "Insecure Deserialization",
        "Vulnerable Components",
        "XXE",
        "Improper Input Validation",
    ],
}

# OWASP Top 10 (2021) classes, in order. Detection Rate is reported against
# this list of 10 (PDF target: identify 8/10).
OWASP_TOP_10: list[str] = [
    "A01 Broken Access Control",
    "A02 Cryptographic Failures",
    "A03 Injection",
    "A04 Insecure Design",
    "A05 Security Misconfiguration",
    "A06 Vulnerable and Outdated Components",
    "A07 Identification and Authentication Failures",
    "A08 Software and Data Integrity Failures",
    "A09 Security Logging and Monitoring Failures",
    "A10 Server-Side Request Forgery",
]

# Maps every category named above to its OWASP Top 10 (2021) class. Used to
# compute Detection Rate = number of distinct OWASP classes detected.
CATEGORY_TO_OWASP: dict[str, str] = {
    # DVWA
    "Brute Force": "A07 Identification and Authentication Failures",
    "Command Injection": "A03 Injection",
    "CSRF": "A01 Broken Access Control",
    "File Inclusion": "A03 Injection",
    "File Upload": "A08 Software and Data Integrity Failures",
    "Insecure CAPTCHA": "A07 Identification and Authentication Failures",
    "SQL Injection": "A03 Injection",
    "SQL Injection (Blind)": "A03 Injection",
    "Weak Session IDs": "A07 Identification and Authentication Failures",
    "XSS (Reflected)": "A03 Injection",
    "XSS (Stored)": "A03 Injection",
    "XSS (DOM)": "A03 Injection",
    # Juice Shop
    "Injection": "A03 Injection",
    "Broken Authentication": "A07 Identification and Authentication Failures",
    "Sensitive Data Exposure": "A02 Cryptographic Failures",
    "Broken Access Control": "A01 Broken Access Control",
    "Security Misconfiguration": "A05 Security Misconfiguration",
    "XSS": "A03 Injection",
    "Insecure Deserialization": "A08 Software and Data Integrity Failures",
    "Vulnerable Components": "A06 Vulnerable and Outdated Components",
    "XXE": "A05 Security Misconfiguration",
    "Improper Input Validation": "A03 Injection",
}
