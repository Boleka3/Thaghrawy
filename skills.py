"""Methodology guidance injected into the system prompt (see
prompt_builder.py). Each Skill maps a phase of a pentest engagement to
concrete tool names and OWASP/PTES-style guidance, so the agent's
free-form tool-calling loop still has a methodology to follow instead of
guessing which of the ~30 registered tools to reach for next.

This does not gate or order tool calls - core/agent.py's ReAct loop stays
fully dynamic. It's reference material in the prompt, not a state machine.
"""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Skill:
    name: str
    prompt: str
    tools: List[str] = field(default_factory=list)


SKILLS = {
    "recon": Skill(
        name="Reconnaissance",
        prompt=(
            "Map the attack surface before touching anything else: live hosts, open "
            "ports/services, subdomains, DNS records, and the web/tech stack in use. "
            "Passive techniques (whois, subfinder, assetfinder) before active ones "
            "(nmap, masscan) when scope/stealth matters."
        ),
        tools=[
            "amass_scan", "subfinder_scan", "assetfinder_scan", "dnsx_scan", "whois_lookup",
            "httpx_scan", "naabu_scan", "nmap_scan", "masscan_scan", "web_tech_detect",
            "wafw00f_scan", "katana_crawl",
        ],
    ),
    "content_discovery": Skill(
        name="Content & Parameter Discovery",
        prompt=(
            "Find what isn't linked: hidden directories/files (gobuster, ffuf), JS-referenced "
            "endpoints (katana), and undocumented GET/POST/JSON parameters (arjun) - the "
            "extra parameter is often the injection point the obvious form doesn't show."
        ),
        tools=["gobuster_scan", "ffuf_fuzz", "katana_crawl", "arjun_scan"],
    ),
    "vuln_scan": Skill(
        name="Vulnerability Scanning",
        prompt=(
            "Run breadth-first vulnerability scanners against discovered hosts/services "
            "before attempting manual exploitation: nuclei for known CVE/misconfig templates, "
            "nikto for web server issues, testssl for TLS weaknesses, wpscan if the stack is "
            "WordPress, headers_audit for missing HTTP security headers. "
            "Cross-reference identified software versions with searchsploit. "
            "For a broad OWASP Top-10 web sweep in one pass (XSS, SQLi, command exec, file "
            "handling, SSRF, CRLF), run wapiti against the app root before drilling in."
        ),
        tools=[
            "nuclei_scan", "nikto_scan", "testssl_scan", "wpscan_scan",
            "wapiti_scan", "searchsploit_lookup", "headers_audit",
        ],
    ),
    "exploit": Skill(
        name="Exploitation",
        prompt=(
            "Only attempt exploitation against in-scope targets with a specific suspected "
            "vulnerability backed by recon/scan evidence - never exploit speculatively. "
            "For OWASP A03 Injection: sqlmap for SQL injection points and dalfox for "
            "reflected/stored/DOM XSS on parameters that reflect input (wapiti's broad sweep "
            "in the vuln-scan phase also flags command injection and file-handling issues). "
            "For OWASP A05/A08: xxe_test on XML endpoints, headers_audit to confirm missing "
            "security headers on high-value endpoints. "
            "For OWASP A07: jwt_analyze to inspect JWT tokens for weak algorithms or missing "
            "claims before attempting signature bypass. "
            "For OWASP A01: csrf_check on form-heavy apps, and http_request with alternate "
            "HTTP methods or identifiers for IDOR testing. "
            "hydra for credential brute-forcing where lockout policy allows it, searchsploit to "
            "check for a public PoC for an identified version before reinventing one by hand."
        ),
        tools=[
            "sqlmap_scan", "dalfox_scan", "hydra_bruteforce",
            "searchsploit_lookup", "shell",
            "xxe_test", "jwt_analyze", "csrf_check", "headers_audit",
        ],
    ),
    "network_ad": Skill(
        name="Network & Active Directory",
        prompt=(
            "When the engagement scope extends past a single web app into an internal "
            "network/domain segment: port-sweep with nmap/masscan, then enumerate SMB "
            "shares, users, and password policy with enum4linux before considering any "
            "credential attacks."
        ),
        tools=["nmap_scan", "masscan_scan", "enum4linux_scan"],
    ),
    "delivery": Skill(
        name="Delivery",
        prompt=(
            "Test how attacker-controlled input reaches the target system. "
            "Use upload_test to probe file upload endpoints for dangerous file type acceptance "
            "(.php, .jsp, .aspx, double-extension bypasses). "
            "Use ssrf_test to check whether server-side URL parameters can be redirected to "
            "internal services (http/file/gopher/dict protocols)."
        ),
        tools=["upload_test", "ssrf_test", "ffuf_fuzz", "arjun_scan"],
    ),
    "post_exploit": Skill(
        name="Post-Exploitation (Installation / C2 / Actions on Objectives)",
        prompt=(
            "After obtaining a foothold: enumerate privilege escalation paths with "
            "linux_privesc_check (SUID/SGID binaries, sudo misconfigurations, cron jobs, "
            "writable paths, file capabilities). "
            "Search all gathered recon output in the workspace for leaked credentials, "
            "API keys, tokens, and password hashes with credential_search. "
            "SSRF vulnerabilities can serve as a C2 channel to reach internal services — "
            "pivot with ssrf_test after confirming a foothold."
        ),
        tools=["linux_privesc_check", "credential_search", "ssrf_test", "shell"],
    ),
    "access_control": Skill(
        name="Access Control Testing (OWASP A01)",
        prompt=(
            "Test for broken access control before and after authentication. "
            "Use csrf_check to detect missing anti-CSRF tokens on form endpoints. "
            "For IDOR (Insecure Direct Object Reference): iterate sequential/guessable "
            "identifiers (user IDs, order numbers, document IDs) via http_request with "
            "alternating owner context — look for data belonging to other users. "
            "Check HTTP method override headers (X-HTTP-Method-Override, X-Method-Override) "
            "for REST-endpoint privilege escalation. "
            "Test vertical privilege escalation by replaying admin-level requests on "
            "a low-privilege session."
        ),
        tools=["csrf_check", "http_request", "ffuf_fuzz", "katana_crawl"],
    ),
    "security_misconfig": Skill(
        name="Security Misconfiguration (OWASP A05)",
        prompt=(
            "Audit HTTP security headers first with headers_audit — missing HSTS/CSP/XFO/COOP "
            "are the most common scoring hits in bug bounties and pentest reports. "
            "Check for directory listing enabled on known paths, debug/admin endpoints "
            "exposed without auth, default credentials on common services, verb/OPTIONS "
            "tampering on endpoints that should be strict (PUT/DELETE on read-only routes). "
            "For XML endpoints, test XXE with xxe_test (file read, SSRF, SVG vectors). "
            "Check for stack trace / verbose error messages on 4xx/5xx responses."
        ),
        tools=[
            "headers_audit", "xxe_test", "ffuf_fuzz", "gobuster_scan",
            "nuclei_scan", "http_request",
        ],
    ),
    "ctf_web": Skill(
        name="CTF Web Exploitation",
        prompt=(
            "Web exploitation for CTF challenges: map the app surface first, capture "
            "normal request/response pairs before fuzzing, enumerate hidden functionality "
            "from JS bundles/response headers/routes/alternate methods. Classify bug family: "
            "injection (SQLi via sqlmap, XSS via dalfox), SSTI (Jinja2/Twig/Vue/Smarty), "
            "SSRF (Host header/DNS rebinding/curl redirect), XXE via xxe_test (basic/OOB/DOCX "
            "upload), JWT/JWE manipulation via jwt_analyze (weak secrets/header injection/key "
            "confusion), auth bypass via csrf_check (IDOR/OAuth/OIDC/SAML/CORS), headers_audit "
            "for misconfig scoring, file upload RCE (polyglot/double-ext/truncation), "
            "prototype pollution, deserialization (Java/Python/PHP), command injection, "
            "request smuggling, and race conditions. Build the smallest proof first (leak, "
            "bypass, primitive), chain for full exploit. Common flag locations: /flag.txt, "
            "environment vars, database flag tables, hidden DOM nodes, HTTP response headers."
        ),
        tools=[
            "sqlmap_scan", "dalfox_scan", "ffuf_fuzz", "arjun_scan",
            "ssrf_test", "upload_test", "xxe_test", "jwt_analyze",
            "csrf_check", "headers_audit", "searchsploit_lookup",
            "wapiti_scan", "nuclei_scan", "katana_crawl",
            "gobuster_scan", "web_tech_detect", "wafw00f_scan",
            "credential_search", "save_finding", "save_technique",
        ],
    ),
    "report": Skill(
        name="Reporting",
        prompt=(
            "Persist every confirmed vulnerability via save_finding as soon as it's "
            "confirmed - don't batch them up to remember later. While the finding is "
            "fresh in context, also judge its cvss_score, dread_score (1-10, your own "
            "DREAD-style estimate of Damage/Reproducibility/Exploitability/Affected "
            "users/Discoverability), affected_component, business_impact (plain-language: "
            "what exploitation costs the business), and remediation - these populate the "
            "executive report, and you have the most context for them right after "
            "confirming the finding. When the "
            "engagement wraps up, call generate_report with just the engagement_id - "
            "it builds both a technical report (full evidence/reproduction steps, for "
            "developers) and an executive report (business impact/risk, for "
            "management) directly from the saved findings, so there's no need to "
            "hand-write report content."
        ),
        tools=["save_finding", "save_technique", "generate_report"],
    ),
}


def methodology_reference(skill_filter: Optional[list[str]] = None) -> str:
    """Render skills as a compact reference block for the system prompt.

    When `skill_filter` is provided (a list of skill dict keys like
    ``["ctf_web", "recon"]``), only those skills are included — useful for
    engagement-type-specific routing (e.g. CTF web challenges vs. network
    pentests). When None or empty, ALL skills are shown.
    """
    lines = ["METHODOLOGY REFERENCE (guidance, not a required order):"]
    keys = set(skill_filter) if skill_filter else None
    if keys is not None and not keys:
        keys = None  # empty list is the same as "all"
    for key, skill in SKILLS.items():
        if keys is not None and key not in keys:
            continue
        lines.append(f"- {skill.name}: {skill.prompt} [tools: {', '.join(skill.tools)}]")
    return "\n".join(lines) if lines[1:] else "No relevant skills configured for this engagement type."
