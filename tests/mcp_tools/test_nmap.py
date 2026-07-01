from mcp_servers.tools.nmap import _parse_nmap, nmap_scan

_SAMPLE_STDOUT = """\
Starting Nmap 7.94
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
443/tcp  closed https
Running: Linux 5.X
"""


def test_nmap_scan_requires_target():
    assert nmap_scan(target="")["status"] == "error"


def test_nmap_scan_default_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="example.com")
    assert fake_subprocess.last_call == ["nmap", "-Pn", "-sV", "example.com"]


def test_nmap_scan_quick_adds_fast_flag(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="example.com", scan_type="quick")
    assert "-F" in fake_subprocess.last_call


def test_nmap_scan_full_adds_all_ports_flag(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="example.com", scan_type="full")
    assert "-p-" in fake_subprocess.last_call


def test_nmap_scan_udp_adds_su_flag(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="example.com", scan_type="udp")
    assert "-sU" in fake_subprocess.last_call


def test_nmap_scan_with_explicit_ports(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="example.com", ports="22,80,443")
    cmd = fake_subprocess.last_call
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80,443"


def test_nmap_scan_without_service_detection_omits_sv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="example.com", service_detection=False)
    assert "-sV" not in fake_subprocess.last_call


def test_nmap_scan_sanitizes_target(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="example.com; rm -rf /")
    assert fake_subprocess.last_call[-1] == "example.com rm -rf /"


def test_nmap_scan_strips_url_scheme_and_path(fake_subprocess):
    # nmap fails with "Unable to split netmask" on a URL and reports 0 ports;
    # the wrapper normalizes http://host/path down to the bare host.
    fake_subprocess.stdout = _SAMPLE_STDOUT
    nmap_scan(target="http://nisc.coop/some/path")
    assert fake_subprocess.last_call[-1] == "nisc.coop"


def test_parse_nmap_extracts_open_ports_and_os_guess():
    parsed = _parse_nmap(_SAMPLE_STDOUT)
    assert parsed["total_ports_reported"] == 3
    assert len(parsed["open_ports"]) == 2
    assert parsed["open_ports"][0] == {
        "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.2p1",
    }
    assert parsed["os_guess"] == "Linux 5.X"


def test_parse_nmap_no_os_match_returns_none():
    parsed = _parse_nmap("22/tcp open ssh OpenSSH")
    assert parsed["os_guess"] is None
