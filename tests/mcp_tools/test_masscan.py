from mcp_servers.tools import masscan as masscan_mod
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


def test_masscan_scan_top_ports_aliases_ports(fake_subprocess):
    # masscan has no top-ports preset; a top_ports value (naabu-style call)
    # is folded into -p instead of raising TypeError.
    fake_subprocess.stdout = _SAMPLE_STDOUT
    masscan_scan(target="10.0.0.1", top_ports="80,443")
    cmd = fake_subprocess.last_call
    assert cmd[cmd.index("-p") + 1] == "80,443"


def test_masscan_scan_resolves_hostname_to_ip(fake_subprocess, monkeypatch):
    # masscan rejects hostnames ("unknown command-line parameter"); the wrapper
    # resolves a bare host to an IP first. CIDRs/IPs pass through untouched.
    fake_subprocess.stdout = _SAMPLE_STDOUT
    monkeypatch.setattr(masscan_mod.socket, "gethostbyname", lambda h: "45.33.32.156")
    masscan_scan(target="http://scanme.nmap.org", ports="80")
    assert fake_subprocess.last_call[1] == "45.33.32.156"


def test_masscan_scan_preserves_cidr(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    masscan_scan(target="10.0.0.0/24", ports="80")
    assert fake_subprocess.last_call[1] == "10.0.0.0/24"


def test_parse_masscan_extracts_open_ports():
    parsed = _parse_masscan(_SAMPLE_STDOUT)
    assert len(parsed["open_ports"]) == 3
    assert {"port": 22, "protocol": "tcp"} in parsed["open_ports"]
    assert {"port": 53, "protocol": "udp"} in parsed["open_ports"]


def test_parse_masscan_handles_no_matches():
    parsed = _parse_masscan("no ports here")
    assert parsed["open_ports"] == []
