"""Methodology guidance injected into the system prompt (see
prompt_builder.py). Each Skill maps a phase of a pentest engagement to
concrete tool names and OWASP/PTES-style guidance, so the agent's
free-form tool-calling loop still has a methodology to follow instead of
guessing which of the ~30 registered tools to reach for next.

This does not gate or order tool calls - core/agent.py's ReAct loop stays
fully dynamic. It's reference material in the prompt, not a state machine.
"""
from dataclasses import dataclass, field
from typing import List


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
            "WordPress. Cross-reference identified software versions with searchsploit."
        ),
        tools=["nuclei_scan", "nikto_scan", "testssl_scan", "wpscan_scan", "searchsploit_lookup"],
    ),
    "exploit": Skill(
        name="Exploitation",
        prompt=(
            "Only attempt exploitation against in-scope targets with a specific suspected "
            "vulnerability backed by recon/scan evidence - never exploit speculatively. "
            "sqlmap for confirmed/suspected SQL injection points, hydra for credential "
            "brute-forcing where lockout policy allows it, searchsploit to check for a public "
            "PoC for an identified version before reinventing one by hand."
        ),
        tools=["sqlmap_scan", "hydra_bruteforce", "searchsploit_lookup", "shell"],
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


def methodology_reference() -> str:
    """Render all skills as a compact reference block for the system prompt."""
    lines = ["METHODOLOGY REFERENCE (guidance, not a required order):"]
    for skill in SKILLS.values():
        lines.append(f"- {skill.name}: {skill.prompt} [tools: {', '.join(skill.tools)}]")
    return "\n".join(lines)
