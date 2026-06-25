from mcp_servers.tools.enum4linux import _parse_enum4linux, enum4linux_scan

_SAMPLE_STDOUT = """\
[+] Got domain/workgroup name: WORKGROUP
[+] Server allows session using username '', password ''
print$        Disk      Printer Drivers
IPC$          IPC       IPC Service
"""


def test_enum4linux_scan_requires_target():
    assert enum4linux_scan(target="")["status"] == "error"


def test_enum4linux_scan_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    enum4linux_scan(target="10.0.0.5")
    assert fake_subprocess.last_call == ["enum4linux", "-a", "10.0.0.5"]


def test_parse_enum4linux_extracts_facts_and_shares():
    parsed = _parse_enum4linux(_SAMPLE_STDOUT)
    assert len(parsed["facts"]) == 2
    assert "Got domain/workgroup name: WORKGROUP" in parsed["facts"][0]
    assert {"name": "IPC$", "type": "IPC"} in parsed["shares"]


def test_parse_enum4linux_handles_empty_output():
    parsed = _parse_enum4linux("")
    assert parsed["facts"] == []
    assert parsed["shares"] == []
