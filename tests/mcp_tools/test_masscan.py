from mcp_servers.tools.masscan import _parse_masscan, masscan_scan

_SAMPLE_STDOUT = """\
Host: 10.0.0.1 ()    Ports: 22/open/tcp//ssh//
Host: 10.0.0.1 ()    Ports: 80/open/tcp//http//
Host: 10.0.0.1 ()    Ports: 53/open/udp//domain//
"""


def test_masscan_scan_requires_target():
    assert masscan_scan(target="")["status"] == "error"


def test_masscan_scan_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    masscan_scan(target="10.0.0.0/24", ports="1-1000", rate=500)
    cmd = fake_subprocess.last_call
    assert cmd[:2] == ["masscan", "10.0.0.0/24"]
    assert cmd[cmd.index("-p") + 1] == "1-1000"
    assert cmd[cmd.index("--rate") + 1] == "500"
    assert "-oG" in cmd


def test_parse_masscan_extracts_open_ports():
    parsed = _parse_masscan(_SAMPLE_STDOUT)
    assert len(parsed["open_ports"]) == 3
    assert {"port": 22, "protocol": "tcp"} in parsed["open_ports"]
    assert {"port": 53, "protocol": "udp"} in parsed["open_ports"]


def test_parse_masscan_handles_no_matches():
    parsed = _parse_masscan("no ports here")
    assert parsed["open_ports"] == []
