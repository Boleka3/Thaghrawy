import json

import pytest

from core.finding_drafts import (
    finding_from_tool_result,
    flag_findings_from_output,
    normalize_vuln_type,
)


# ── vuln_type normalization ──


@pytest.mark.parametrize("hint,expected", [
    ("blind SQL injection in id param", "SQL Injection"),
    ("Cross Site Scripting (reflected)", "XSS"),
    ("dom xss", "XSS"),
    ("OS command execution", "Command Injection"),
    ("CVE-2021-1234 outdated jquery", "Vulnerable Components"),
    ("TLS 1.0 weak cipher", "Sensitive Data Exposure"),
    ("path traversal / LFI", "File Inclusion"),
    ("missing security header", "Security Misconfiguration"),
    ("something totally unclassified", "Security Misconfiguration"),
    # word-boundary guard: 'rce' must not match inside 'resource'
    ("cross-origin-resource-policy header", "Security Misconfiguration"),
    ("os command injection via ping", "Command Injection"),
])
def test_normalize_vuln_type(hint, expected):
    assert normalize_vuln_type(hint) == expected


# ── nuclei extractor ──


def test_nuclei_result_becomes_findings():
    result = {
        "status": "success",
        "findings": [
            {"template": "missing-csp-header", "protocol": "http", "severity": "low", "matched": "http://t/"},
            {"template": "CVE-2021-9999", "protocol": "http", "severity": "high", "matched": "http://t/x"},
        ],
    }
    findings = finding_from_tool_result("nuclei_scan", result, "eng-1", "http://t")
    assert len(findings) == 2
    csp, cve = findings
    assert csp.vuln_type == "Security Misconfiguration"
    assert csp.severity == "low"
    assert cve.vuln_type == "Vulnerable Components"
    assert cve.severity == "high"
    assert all(f.engagement_id == "eng-1" for f in findings)
    assert all("auto-ingested" in f.tags for f in findings)


def test_nuclei_unknown_severity_defaults_to_info():
    result = {"findings": [{"template": "x", "severity": "unknown", "matched": "http://t/"}]}
    findings = finding_from_tool_result("nuclei_scan", result, "eng-1", "http://t")
    assert findings[0].severity == "info"


# ── nikto precision guard (avoids the JAMon-style FP) ──


def test_nikto_ingests_only_high_precision_lines():
    result = {"findings": [
        "The X-Content-Type-Options header is not set.",
        "/JAMonAdmin.jsp: JAMon Admin interface found (possible XSS).",
    ]}
    findings = finding_from_tool_result("nikto_scan", result, "eng-1", "http://t")
    assert len(findings) == 1
    assert "X-Content-Type-Options" in findings[0].title
    assert findings[0].vuln_type == "Security Misconfiguration"


# ── sqlmap / dalfox verdicts ──


def test_sqlmap_injectable_becomes_one_finding():
    result = {"injectable": True, "parameters": ["id"], "dbms": "MySQL"}
    findings = finding_from_tool_result("sqlmap_scan", result, "eng-1", "http://t")
    assert len(findings) == 1
    assert findings[0].vuln_type == "SQL Injection"
    assert findings[0].severity == "high"


def test_sqlmap_not_injectable_yields_nothing():
    assert finding_from_tool_result("sqlmap_scan", {"injectable": False}, "eng-1", "t") == []


def test_dalfox_xss_found_becomes_finding():
    result = {"xss_found": True, "poc_count": 2, "reflected_params": ["q"]}
    findings = finding_from_tool_result("dalfox_scan", result, "eng-1", "http://t")
    assert len(findings) == 1 and findings[0].vuln_type == "XSS"


# ── robustness ──


def test_error_result_yields_nothing():
    assert finding_from_tool_result("nuclei_scan", {"status": "error"}, "e", "t") == []


def test_unknown_tool_yields_nothing():
    assert finding_from_tool_result("httpx_scan", {"hosts": ["a"]}, "e", "t") == []


def test_non_json_string_result_yields_nothing():
    assert finding_from_tool_result("nuclei_scan", "some string", "e", "t") == []


def test_json_string_result_is_parsed():
    # MCP tool wrappers return json.dumps(...), i.e. a STRING, not a dict.
    raw = json.dumps({"findings": [{"template": "missing-csp", "severity": "low", "matched": "http://t/"}]})
    findings = finding_from_tool_result("nuclei_scan", raw, "eng-1", "http://t")
    assert len(findings) == 1
    assert findings[0].vuln_type == "Security Misconfiguration"


# ── flag/secret detection ──


def test_flag_findings_from_output_picoctf():
    result = "The flag is picoCTF{Pat!3nt_15_Th3_K3y_dcffa92e}"
    findings = flag_findings_from_output("shell", result, "eng-1", "http://t")
    assert len(findings) == 1
    assert findings[0].vuln_type == "Sensitive Data Exposure"
    assert "flag" in findings[0].tags
    assert "picoCTF{Pat!3nt_15_Th3_K3y_dcffa92e}" in findings[0].description


def test_flag_findings_from_output_ctf_format():
    result = "CTF{some_flag_value}"
    findings = flag_findings_from_output("shell", result, "eng-1", "http://t")
    assert len(findings) == 1


def test_flag_findings_from_output_flag_format():
    result = "flag{th1s_1s_4_fl4g}"
    findings = flag_findings_from_output("shell", result, "eng-1", "http://t")
    assert len(findings) == 1


def test_flag_findings_from_output_clean_yields_nothing():
    result = "No secrets here, just normal output."
    findings = flag_findings_from_output("shell", result, "eng-1", "http://t")
    assert findings == []


def test_flag_findings_from_output_dedup():
    result = "picoCTF{dup} and picoCTF{dup} again"
    findings = flag_findings_from_output("shell", result, "eng-1", "http://t")
    assert len(findings) == 1


def test_flag_findings_from_output_multiple_unique():
    result = "First: picoCTF{flag1} and then CTF{flag2}"
    findings = flag_findings_from_output("shell", result, "eng-1", "http://t")
    assert len(findings) == 2


def test_flag_findings_from_output_dict_result():
    result = {"stdout": "picoCTF{embedded_in_dict}", "exit_code": 0}
    findings = flag_findings_from_output("shell", result, "eng-1", "http://t")
    assert len(findings) == 1


def test_flag_findings_from_output_technique_used_tool_name():
    result = "picoCTF{from_dalfox}"
    findings = flag_findings_from_output("dalfox_scan", result, "eng-1", "http://t")
    assert findings[0].technique_used == "dalfox_scan"


def test_finding_from_tool_result_shell_with_flag():
    """Shell results with flags now get findings via flag_findings_from_output."""
    result = {"stdout": "picoCTF{shell_captured_flag}", "exit_code": 0, "status": "success"}
    findings = finding_from_tool_result("shell", result, "eng-1", "http://t")
    assert len(findings) == 1
    assert findings[0].vuln_type == "Sensitive Data Exposure"
    assert "flag" in findings[0].tags
    assert findings[0].technique_used == "shell"
