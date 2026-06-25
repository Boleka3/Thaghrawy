from mcp_servers.tools.nuclei import _parse_nuclei, nuclei_scan

_SAMPLE_STDOUT = (
    "[CVE-2021-1234] [http] [critical] https://example.com/admin\n"
    "[exposed-panel] [http] [info] https://example.com/login\n"
    "not a finding line\n"
)


def test_nuclei_scan_requires_target():
    assert nuclei_scan(target="")["status"] == "error"


def test_nuclei_scan_builds_minimal_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nuclei_scan(target="https://example.com")
    assert fake_subprocess.last_call == ["nuclei", "-u", "https://example.com", "-nc", "-silent"]


def test_nuclei_scan_with_templates_severity_and_tags(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nuclei_scan(target="https://example.com", templates="cves/", severity="critical,high", tags="rce")
    cmd = fake_subprocess.last_call
    assert cmd[cmd.index("-t") + 1] == "cves/"
    assert cmd[cmd.index("-severity") + 1] == "critical,high"
    assert cmd[cmd.index("-tags") + 1] == "rce"


def test_parse_nuclei_extracts_findings_and_severity_breakdown():
    parsed = _parse_nuclei(_SAMPLE_STDOUT)
    assert parsed["total_findings"] == 2
    assert parsed["severity_breakdown"] == {"critical": 1, "info": 1}
    assert parsed["findings"][0] == {
        "template": "CVE-2021-1234",
        "protocol": "http",
        "severity": "critical",
        "matched": "https://example.com/admin",
    }


def test_parse_nuclei_handles_no_findings():
    parsed = _parse_nuclei("")
    assert parsed["total_findings"] == 0
    assert parsed["severity_breakdown"] == {}
