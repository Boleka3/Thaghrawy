import json

from mcp_servers.tools.wapiti import _parse_wapiti_report, wapiti_scan


def test_wapiti_scan_requires_url():
    assert wapiti_scan(url="")["status"] == "error"


def test_wapiti_scan_builds_expected_command(fake_subprocess):
    fake_subprocess.stdout = ""
    wapiti_scan(url="http://host/", modules="xss,sql", scope="folder")
    cmd = fake_subprocess.last_call
    assert cmd[:3] == ["wapiti", "-u", "http://host/"]
    assert cmd[cmd.index("-m") + 1] == "xss,sql"
    assert cmd[cmd.index("--scope") + 1] == "folder"
    assert "-f" in cmd and cmd[cmd.index("-f") + 1] == "json"
    assert "--flush-session" in cmd


def test_parse_wapiti_report_counts_by_category(tmp_path):
    report = {
        "vulnerabilities": {
            "Cross Site Scripting": [{"path": "/a"}, {"path": "/b"}],
            "SQL Injection": [{"path": "/c"}],
            "Blind SQL Injection": [],  # empty categories are dropped
        }
    }
    path = tmp_path / "wapiti.json"
    path.write_text(json.dumps(report))
    parsed = _parse_wapiti_report(str(path))
    assert parsed["vulnerability_count"] == 3
    assert parsed["by_category"] == {"Cross Site Scripting": 2, "SQL Injection": 1}
    assert parsed["categories"] == ["Cross Site Scripting", "SQL Injection"]


def test_parse_wapiti_report_no_vulnerabilities(tmp_path):
    path = tmp_path / "wapiti.json"
    path.write_text(json.dumps({"vulnerabilities": {}}))
    parsed = _parse_wapiti_report(str(path))
    assert parsed["vulnerability_count"] == 0
    assert parsed["categories"] == []
