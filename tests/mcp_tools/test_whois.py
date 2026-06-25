from mcp_servers.tools.whois import _parse_whois, whois_lookup

_SAMPLE_STDOUT = """\
Registrar: Example Registrar, Inc.
Creation Date: 2010-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
Domain Status: clientTransferProhibited
"""


def test_whois_lookup_requires_domain():
    assert whois_lookup(domain="")["status"] == "error"


def test_whois_lookup_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    whois_lookup(domain="example.com")
    assert fake_subprocess.last_call == ["whois", "example.com"]


def test_parse_whois_extracts_fields():
    parsed = _parse_whois(_SAMPLE_STDOUT)
    fields = parsed["fields"]
    assert fields["registrar"] == "Example Registrar, Inc."
    assert fields["creation_date"] == "2010-01-01T00:00:00Z"
    assert fields["name_servers"] == ["ns1.example.com", "ns2.example.com"]
    assert fields["status"] == "clientTransferProhibited"


def test_parse_whois_handles_no_matches():
    parsed = _parse_whois("no useful fields here")
    assert parsed["fields"] == {}
