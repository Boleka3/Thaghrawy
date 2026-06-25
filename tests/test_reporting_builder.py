from memory.schemas import Engagement, Finding
from reporting.builder import build_executive_report, build_technical_report


def _engagement() -> Engagement:
    return Engagement(
        id="eng-1",
        name="Acme Web App",
        target="https://acme.example.com",
        scope="acme.example.com",
        start_date="2026-06-01",
        tech_stack=["nginx", "django"],
    )


def _findings() -> list[Finding]:
    return [
        Finding(
            id="f-1",
            title="SQL Injection in login",
            severity="critical",
            vuln_type="SQL Injection",
            description="The login form is vulnerable to boolean-based SQLi.",
            reproduction_steps="POST /login with username=' OR 1=1--",
            technique_used="sqlmap",
            target="https://acme.example.com/login",
            engagement_id="eng-1",
            date="2026-06-02",
            cvss_score=9.8,
            affected_component="auth-service",
            business_impact="Full customer database could be exfiltrated.",
            remediation="Use parameterized queries.",
        ),
        Finding(
            id="f-2",
            title="Missing security headers",
            severity="low",
            vuln_type="Misconfiguration",
            description="CSP and X-Frame-Options headers are absent.",
            reproduction_steps="curl -I https://acme.example.com",
            technique_used="nikto",
            target="https://acme.example.com",
            engagement_id="eng-1",
            date="2026-06-02",
        ),
    ]


def test_technical_report_includes_reproduction_steps():
    report = build_technical_report(_engagement(), _findings())
    assert "POST /login with username=' OR 1=1--" in report
    assert "SQL Injection in login" in report
    assert "Missing security headers" in report


def test_executive_report_omits_reproduction_steps_but_keeps_impact():
    report = build_executive_report(_engagement(), _findings())
    assert "POST /login with username=' OR 1=1--" not in report
    assert "Full customer database could be exfiltrated." in report
    assert "SQL Injection in login" in report
    assert "Missing security headers" in report


def test_both_reports_list_same_finding_titles():
    findings = _findings()
    technical = build_technical_report(_engagement(), findings)
    executive = build_executive_report(_engagement(), findings)
    for finding in findings:
        assert finding.title in technical
        assert finding.title in executive


def test_empty_findings_does_not_crash():
    assert "No findings" in build_technical_report(_engagement(), [])
    assert "No findings" in build_executive_report(_engagement(), [])


def test_executive_report_sorts_by_dread_within_same_severity():
    findings = [
        Finding(
            id="f-low-dread", title="Low DREAD high finding", severity="high", vuln_type="X",
            description="d", reproduction_steps="r", technique_used="t", target="x",
            engagement_id="eng-1", date="2026-06-02", dread_score=3,
        ),
        Finding(
            id="f-high-dread", title="High DREAD high finding", severity="high", vuln_type="X",
            description="d", reproduction_steps="r", technique_used="t", target="x",
            engagement_id="eng-1", date="2026-06-02", dread_score=9,
        ),
    ]
    report = build_executive_report(_engagement(), findings)
    assert report.index("High DREAD high finding") < report.index("Low DREAD high finding")
    assert "DREAD risk score**: 9" in report


def test_executive_report_handles_missing_dread_score():
    findings = _findings()  # neither fixture finding sets dread_score
    report = build_executive_report(_engagement(), findings)
    assert "DREAD risk score" not in report
