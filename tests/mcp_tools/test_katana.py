from mcp_servers.tools.katana import _parse_katana, katana_crawl

_SAMPLE_STDOUT = (
    "https://example.com/app.js\n"
    "https://example.com/api/users\n"
    "https://example.com/login\n"
    "https://example.com/about\n"
)


def test_katana_crawl_requires_target():
    assert katana_crawl(target="")["status"] == "error"


def test_katana_crawl_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    katana_crawl(target="https://example.com", depth=2, js_crawl=False)
    cmd = fake_subprocess.last_call
    assert cmd[:3] == ["katana", "-u", "https://example.com"]
    assert cmd[cmd.index("-d") + 1] == "2"
    assert "-jc" not in cmd


def test_katana_crawl_js_crawl_adds_flag(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    katana_crawl(target="https://example.com")
    assert "-jc" in fake_subprocess.last_call


def test_parse_katana_categorizes_urls():
    parsed = _parse_katana(_SAMPLE_STDOUT)
    assert parsed["total_urls"] == 4
    assert parsed["categories"]["javascript_files"] == ["https://example.com/app.js"]
    assert parsed["categories"]["api_endpoints"] == ["https://example.com/api/users"]
    assert parsed["categories"]["forms"] == ["https://example.com/login"]
    assert parsed["categories"]["other"] == ["https://example.com/about"]


def test_parse_katana_handles_empty_output():
    parsed = _parse_katana("")
    assert parsed["total_urls"] == 0
