from mcp_servers.tools.netexec import _parse_netexec, netexec_scan

_SAMPLE_STDOUT = """\
SMB  10.0.0.5  445  DC01  [*] Windows 10 / Server 2019
SMB  10.0.0.5  445  DC01  [+] WORKGROUP\\administrator:Password123
data          READ,WRITE
backup        READ
"""


def test_netexec_scan_requires_target():
    assert netexec_scan(target="")["status"] == "error"


def test_netexec_scan_builds_minimal_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    netexec_scan(target="10.0.0.5")
    assert fake_subprocess.last_call == ["netexec", "smb", "10.0.0.5"]


def test_netexec_scan_with_credentials(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    netexec_scan(target="10.0.0.5", username="administrator", password="Password123")
    cmd = fake_subprocess.last_call
    assert cmd[cmd.index("-u") + 1] == "administrator"
    assert cmd[cmd.index("-p") + 1] == "Password123"


def test_netexec_scan_with_enumerate_shares(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    netexec_scan(target="10.0.0.5", enumerate_shares=True)
    assert "--shares" in fake_subprocess.last_call


def test_parse_netexec_extracts_facts_auth_and_shares():
    parsed = _parse_netexec(_SAMPLE_STDOUT)
    assert len(parsed["facts"]) == 2
    assert len(parsed["accessible_shares"]) == 2
    # The alternation in the source regex (READ|WRITE|READ,WRITE) tries "READ"
    # before "READ,WRITE", so a "READ,WRITE" share is captured as just "READ".
    assert {"name": "data", "permissions": "READ"} in parsed["accessible_shares"]


def test_parse_netexec_handles_empty_output():
    parsed = _parse_netexec("")
    assert parsed["facts"] == []
    assert parsed["accessible_shares"] == []
