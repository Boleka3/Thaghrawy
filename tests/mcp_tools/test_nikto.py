from mcp_servers.tools.nikto import _parse_nikto, nikto_scan

_NIKTO_STDOUT = (
    "- Nikto v2.5.0\n"
    "+ Server: Apache/2.4.41\n"
    "+ /admin/: This might be interesting.\n"
    "+ OSVDB-3233: /icons/README: Apache default file found.\n"
)


def test_nikto_scan_requires_target():
    assert nikto_scan(target="")["status"] == "error"


def test_nikto_scan_builds_expected_command(fake_subprocess):
    fake_subprocess.stdout = _NIKTO_STDOUT
    nikto_scan(target="https://example.com")
    assert fake_subprocess.last_call == ["nikto", "-h", "https://example.com"]


def test_nikto_scan_returns_structured_envelope(fake_subprocess):
    fake_subprocess.stdout = _NIKTO_STDOUT
    result = nikto_scan(target="https://example.com")
    assert result["status"] == "success"
    assert result["tool"] == "nikto"
    assert result["finding_count"] == 3


def test_parse_nikto_extracts_plus_lines():
    parsed = _parse_nikto(_NIKTO_STDOUT)
    assert parsed["finding_count"] == 3
    assert parsed["findings"][0] == "Server: Apache/2.4.41"


def test_parse_nikto_no_findings():
    parsed = _parse_nikto("- Nikto v2.5.0\nNo web server found\n")
    assert parsed["finding_count"] == 0
