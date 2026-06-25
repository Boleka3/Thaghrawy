"""Known vulnerability categories per benchmark target, used by
benchmarks/scorer.py to compute ESR/AST/FP-rate against a real engagement's
saved findings. Category names are the strings matched (heuristically,
case-insensitively, by substring) against each Finding's vuln_type/tags -
this is intentionally a coarse proxy, not exact ground-truth labeling.
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
