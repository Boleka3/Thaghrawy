from mcp_servers.tools.wafw00f import _parse_wafw00f, wafw00f_scan


def test_wafw00f_scan_requires_target():
    assert wafw00f_scan(target="")["status"] == "error"


def test_wafw00f_scan_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = "The site https://example.com is behind Cloudflare (Cloudflare Inc.)\n"
    wafw00f_scan(target="https://example.com")
    assert fake_subprocess.last_call == ["wafw00f", "https://example.com"]


def test_parse_wafw00f_detects_waf():
    parsed = _parse_wafw00f("The site https://example.com is behind Cloudflare (Cloudflare Inc.)")
    assert parsed["waf_detected"] is True
    assert parsed["waf_name"] == "Cloudflare"
    assert parsed["summary"] == "Cloudflare"


def test_parse_wafw00f_no_waf_detected():
    parsed = _parse_wafw00f("No WAF detected by the generic detection")
    assert parsed["waf_detected"] is False
    assert parsed["waf_name"] is None
    assert parsed["summary"] == "No WAF detected"


def test_parse_wafw00f_inconclusive_when_neither_pattern_matches():
    parsed = _parse_wafw00f("some unrelated output")
    assert parsed["summary"] == "Inconclusive"
