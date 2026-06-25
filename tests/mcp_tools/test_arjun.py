from mcp_servers.tools.arjun import _parse_arjun, arjun_scan


def test_arjun_scan_requires_url():
    assert arjun_scan(url="")["status"] == "error"


def test_arjun_scan_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = "Parameters found: id, debug"
    arjun_scan(url="https://example.com/api", method="get", threads=5)
    assert fake_subprocess.last_call == [
        "arjun", "-u", "https://example.com/api", "-m", "GET", "-t", "5",
    ]


def test_arjun_scan_uppercases_method(fake_subprocess):
    fake_subprocess.stdout = ""
    arjun_scan(url="https://example.com", method="post")
    cmd = fake_subprocess.last_call
    assert cmd[cmd.index("-m") + 1] == "POST"


def test_parse_arjun_extracts_parameter_list():
    parsed = _parse_arjun("Parameters found: id, debug, token")
    assert parsed["parameters"] == ["id", "debug", "token"]
    assert "3" in parsed["summary"]


def test_parse_arjun_no_parameters_found():
    parsed = _parse_arjun("Scanning complete. No vulnerable parameters found.")
    assert parsed["parameters"] == []
    assert parsed["summary"] == "No parameters found"
