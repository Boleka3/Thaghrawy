from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class Skill:
    name: str
    prompt: str
    tools: List[str]
    examples: List[Dict[str, Any]]
    output_format: str


_OUTPUT_FORMAT = '{"thought": "reasoning", "tool_call": "tool_name", "params": {...}}'

SKILLS = {
    "recon": Skill(
        name="Reconnaissance",
        prompt="Identify open ports, services, subdomains, and web technologies on the target.",
        tools=["amass_scan", "subfinder_scan", "httpx_scan", "katana_crawl", "web_tech_detect", "gobuster_scan"],
        examples=[
            {
                "input": "Scan the target example.com",
                "output": (
                    '{"thought": "I will start by enumerating subdomains.", '
                    '"tool_call": "subfinder_scan", "params": {"domain": "example.com"}}'
                ),
            }
        ],
        output_format=_OUTPUT_FORMAT,
    ),
    "vuln_scan": Skill(
        name="Vulnerability Scanning",
        prompt="Scan the identified services for known vulnerabilities.",
        tools=["nuclei_scan", "ffuf_fuzz"],
        examples=[
            {
                "input": "Check the web server for vulnerabilities.",
                "output": (
                    '{"thought": "I will use nuclei to check for known vulnerability templates.", '
                    '"tool_call": "nuclei_scan", "params": {"target": "http://localhost:80"}}'
                ),
            }
        ],
        output_format=_OUTPUT_FORMAT,
    ),
    "exploit": Skill(
        name="Exploitation",
        prompt="Attempt to exploit identified vulnerabilities to gain access or extract data.",
        tools=["sqlmap_scan", "hydra_bruteforce", "nikto_scan"],
        examples=[
            {
                "input": "Try to exploit potential SQL injection on login.php",
                "output": (
                    '{"thought": "I will use sqlmap to test for SQL injection.", '
                    '"tool_call": "sqlmap_scan", "params": {"url": "http://localhost/login.php"}}'
                ),
            }
        ],
        output_format=_OUTPUT_FORMAT,
    ),
    "report": Skill(
        name="Reporting",
        prompt=(
            "Consolidate all findings into a structured penetration testing report. "
            'CRITICAL: Escape all double quotes (\\") and newlines (\\\\n) inside the '
            "content_markdown JSON string. Do not use raw newlines."
        ),
        tools=["generate_report", "save_finding"],
        examples=[
            {
                "input": "Generate the final report based on our findings.",
                "output": (
                    '{"thought": "I will consolidate the data and generate the report.", '
                    '"tool_call": "generate_report", "params": {"content_markdown": "# Pentest Report..."}}'
                ),
            }
        ],
        output_format=_OUTPUT_FORMAT,
    ),
}
