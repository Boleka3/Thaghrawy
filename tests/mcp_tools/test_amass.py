from mcp_servers.tools.amass import _parse_amass, amass_scan

_SAMPLE_STDOUT = (
    '{"name": "www.example.com"}\n'
    '{"name": "api.example.com"}\n'
    '{"name": "www.example.com"}\n'
    "not json\n"
)


def test_amass_scan_requires_domain():
    assert amass_scan(domain="")["status"] == "error"


def test_amass_scan_rejects_invalid_mode():
    result = amass_scan(domain="example.com", mode="aggressive")
    assert result["status"] == "error"
    assert "mode" in result["error"]


def test_amass_scan_passive_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    amass_scan(domain="example.com", mode="passive")
    assert fake_subprocess.last_call == [
        "amass", "enum", "-d", "example.com", "-json", "/dev/stdout", "-passive",
    ]


def test_amass_scan_active_adds_active_flag(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    amass_scan(domain="example.com", mode="active")
    assert "-active" in fake_subprocess.last_call


def test_amass_scan_brute_adds_brute_flag(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    amass_scan(domain="example.com", brute=True)
    assert "-brute" in fake_subprocess.last_call


def test_parse_amass_dedupes_and_sorts_subdomains():
    parsed = _parse_amass(_SAMPLE_STDOUT)
    assert parsed["subdomain_count"] == 2
    assert parsed["subdomains"] == ["api.example.com", "www.example.com"]


def test_parse_amass_handles_no_subdomains():
    parsed = _parse_amass("")
    assert parsed["subdomain_count"] == 0
    assert parsed["subdomains"] == []
