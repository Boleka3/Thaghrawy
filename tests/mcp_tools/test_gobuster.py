import pytest

from mcp_servers.tools.gobuster import _parse_gobuster, gobuster_scan

_DIR_STDOUT = "/admin                (Status: 301) [Size: 234]\n/login                (Status: 200) [Size: 1024]\n"


@pytest.fixture
def wordlist(tmp_path):
    path = tmp_path / "wordlist.txt"
    path.write_text("admin\nlogin\n")
    return str(path)


def test_gobuster_scan_rejects_invalid_mode(wordlist):
    result = gobuster_scan(mode="bogus", target="example.com", wordlist=wordlist)
    assert result["status"] == "error"


def test_gobuster_scan_requires_target(wordlist):
    assert gobuster_scan(mode="dir", target="", wordlist=wordlist)["status"] == "error"


def test_gobuster_scan_missing_wordlist_returns_error():
    result = gobuster_scan(mode="dir", target="example.com", wordlist="/no/such/file.txt")
    assert result["status"] == "error"
    assert "Wordlist not found" in result["error"]


def test_gobuster_scan_dir_mode_uses_dash_u_and_status_codes(fake_subprocess, wordlist):
    fake_subprocess.stdout = _DIR_STDOUT
    gobuster_scan(mode="dir", target="https://example.com", wordlist=wordlist, status_codes="200,301")
    cmd = fake_subprocess.last_call
    assert cmd[:2] == ["gobuster", "dir"]
    assert "-u" in cmd and cmd[cmd.index("-u") + 1] == "https://example.com"
    assert "-s" in cmd and cmd[cmd.index("-s") + 1] == "200,301"


def test_gobuster_scan_dir_mode_with_extensions(fake_subprocess, wordlist):
    fake_subprocess.stdout = _DIR_STDOUT
    gobuster_scan(mode="dir", target="https://example.com", wordlist=wordlist, extensions="php,html")
    cmd = fake_subprocess.last_call
    assert "-x" in cmd and cmd[cmd.index("-x") + 1] == "php,html"


def test_gobuster_scan_dns_mode_uses_dash_d(fake_subprocess, wordlist):
    fake_subprocess.stdout = "Found: api.example.com\n"
    gobuster_scan(mode="dns", target="example.com", wordlist=wordlist)
    cmd = fake_subprocess.last_call
    assert cmd[:2] == ["gobuster", "dns"]
    assert "-d" in cmd and cmd[cmd.index("-d") + 1] == "example.com"
    assert "-s" not in cmd


def test_gobuster_scan_vhost_mode_uses_dash_u(fake_subprocess, wordlist):
    fake_subprocess.stdout = ""
    gobuster_scan(mode="vhost", target="https://example.com", wordlist=wordlist)
    cmd = fake_subprocess.last_call
    assert "-u" in cmd


def test_parse_gobuster_dir_extracts_paths_and_interesting():
    parser = _parse_gobuster("dir")
    parsed = parser(_DIR_STDOUT)
    assert parsed["total_found"] == 2
    assert len(parsed["interesting_findings"]) == 2
    assert parsed["interesting_findings"][0] == {"path": "/admin", "status": 301, "size": 234}


def test_parse_gobuster_non_dir_mode_returns_raw_results():
    parser = _parse_gobuster("dns")
    parsed = parser("Found: api.example.com\nFound: cdn.example.com\n")
    assert parsed["total_found"] == 2
    assert parsed["results"][0] == {"result": "Found: api.example.com"}
