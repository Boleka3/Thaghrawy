from mcp_servers.tools.dalfox import _parse_dalfox, dalfox_scan

_POC_STDOUT = (
    "[POC][V][GET] http://host/?q=<script>alert(1)</script>\n"
    "[POC][V][GET] http://host/?name=\"><svg onload=alert(1)>\n"
    "[PARAM] q\n"
)


def test_dalfox_scan_requires_url():
    assert dalfox_scan(url="")["status"] == "error"


def test_dalfox_scan_builds_expected_command(fake_subprocess):
    fake_subprocess.stdout = _POC_STDOUT
    dalfox_scan(url="http://host/?q=test")
    assert fake_subprocess.last_call == [
        "dalfox", "url", "http://host/?q=test", "--no-color", "--silence", "--skip-bav",
    ]


def test_dalfox_scan_passes_method_and_cookie(fake_subprocess):
    fake_subprocess.stdout = ""
    dalfox_scan(url="http://host/?q=1", method="POST", cookie="PHPSESSID=abc; security=low")
    cmd = fake_subprocess.last_call
    assert cmd[cmd.index("-X") + 1] == "POST"
    assert cmd[cmd.index("-C") + 1] == "PHPSESSID=abc; security=low"


def test_dalfox_scan_get_omits_method_flag(fake_subprocess):
    fake_subprocess.stdout = ""
    dalfox_scan(url="http://host/?q=1", method="GET")
    assert "-X" not in fake_subprocess.last_call


def test_dalfox_scan_returns_structured_envelope(fake_subprocess):
    fake_subprocess.stdout = _POC_STDOUT
    result = dalfox_scan(url="http://host/?q=1")
    assert result["status"] == "success"
    assert result["tool"] == "dalfox"
    assert result["xss_found"] is True
    assert result["poc_count"] == 2


def test_parse_dalfox_no_xss():
    parsed = _parse_dalfox("[*] Scan completed. No issues found.\n")
    assert parsed["xss_found"] is False
    assert parsed["poc_count"] == 0
