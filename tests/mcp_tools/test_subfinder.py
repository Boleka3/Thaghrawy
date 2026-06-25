import os

from mcp_servers.tools.subfinder import _parse_subfinder, subfinder_scan

_SAMPLE_STDOUT = "[INF] enumerating\nwww.example.com\napi.example.com\n"


def test_subfinder_scan_requires_domain():
    assert subfinder_scan(domain="")["status"] == "error"


def test_subfinder_scan_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    subfinder_scan(domain="example.com")
    assert fake_subprocess.last_call == ["subfinder", "-d", "example.com", "-silent", "-nc"]


def test_subfinder_scan_saves_subdomain_list_file_on_success(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    result = subfinder_scan(domain="example.com")
    assert result["status"] == "success"
    assert "subdomain_list_file" in result
    assert os.path.isfile(result["subdomain_list_file"])
    content = open(result["subdomain_list_file"]).read()
    assert "www.example.com" in content


def test_subfinder_scan_no_list_file_when_no_subdomains_found(fake_subprocess):
    fake_subprocess.stdout = "[INF] enumerating\n"
    result = subfinder_scan(domain="example.com")
    assert "subdomain_list_file" not in result


def test_parse_subfinder_filters_log_lines():
    parsed = _parse_subfinder(_SAMPLE_STDOUT)
    assert parsed["subdomain_count"] == 2
    assert parsed["subdomains"] == ["www.example.com", "api.example.com"]
