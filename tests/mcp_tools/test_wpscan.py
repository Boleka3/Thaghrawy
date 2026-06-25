import json

from mcp_servers.tools.wpscan import _parse_wpscan, wpscan_scan

_SAMPLE_STDOUT = json.dumps({
    "version": {"number": "6.1.1", "vulnerabilities": []},
    "plugins": {
        "akismet": {"vulnerabilities": []},
        "vulnerable-plugin": {"vulnerabilities": [{"title": "Some XSS"}]},
    },
})


def test_wpscan_scan_requires_target():
    assert wpscan_scan(target="")["status"] == "error"


def test_wpscan_scan_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    wpscan_scan(target="https://example.com", enumerate="vp,vt,u")
    cmd = fake_subprocess.last_call
    assert cmd[:3] == ["wpscan", "--url", "https://example.com"]
    assert cmd[cmd.index("--enumerate") + 1] == "vp,vt,u"
    assert "--format" in cmd and cmd[cmd.index("--format") + 1] == "json"


def test_parse_wpscan_extracts_version_and_vulnerable_plugins():
    parsed = _parse_wpscan(_SAMPLE_STDOUT)
    assert parsed["wordpress_version"] == "6.1.1"
    assert parsed["total_plugins_found"] == 2
    assert "vulnerable-plugin" in parsed["vulnerable_plugins"]
    assert "akismet" not in parsed["vulnerable_plugins"]


def test_parse_wpscan_handles_invalid_json():
    parsed = _parse_wpscan("not json")
    assert "Could not parse JSON output" in parsed["summary"]
