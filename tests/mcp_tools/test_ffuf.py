import pytest

from mcp_servers.tools.ffuf import _parse_ffuf, ffuf_fuzz

_SAMPLE_STDOUT = (
    '{"url": "https://example.com/admin", "status": 200, "length": 100, '
    '"words": 10, "lines": 5, "redirectlocation": ""}\n'
    "not json\n"
)


@pytest.fixture
def wordlist(tmp_path):
    path = tmp_path / "wordlist.txt"
    path.write_text("admin\nlogin\n")
    return str(path)


def test_ffuf_fuzz_requires_url():
    assert ffuf_fuzz(url="")["status"] == "error"


def test_ffuf_fuzz_missing_wordlist_returns_error():
    result = ffuf_fuzz(url="https://example.com/FUZZ", wordlist="/no/such/wordlist.txt")
    assert result["status"] == "error"
    assert "Wordlist not found" in result["error"]


def test_ffuf_fuzz_appends_fuzz_keyword_when_missing(fake_subprocess, wordlist):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    ffuf_fuzz(url="https://example.com/api", wordlist=wordlist)
    cmd = fake_subprocess.last_call
    assert cmd[cmd.index("-u") + 1] == "https://example.com/api/FUZZ"


def test_ffuf_fuzz_leaves_url_with_explicit_fuzz_unchanged(fake_subprocess, wordlist):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    ffuf_fuzz(url="https://example.com/FUZZ.php", wordlist=wordlist)
    cmd = fake_subprocess.last_call
    assert cmd[cmd.index("-u") + 1] == "https://example.com/FUZZ.php"


def test_ffuf_fuzz_includes_headers(fake_subprocess, wordlist):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    ffuf_fuzz(url="https://example.com/FUZZ", wordlist=wordlist, headers=["Authorization: Bearer x"])
    cmd = fake_subprocess.last_call
    assert "Authorization: Bearer x" in cmd


def test_ffuf_fuzz_includes_filter_codes_and_size(fake_subprocess, wordlist):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    ffuf_fuzz(url="https://example.com/FUZZ", wordlist=wordlist, filter_codes="404", filter_size="0")
    cmd = fake_subprocess.last_call
    assert "-fc" in cmd and cmd[cmd.index("-fc") + 1] == "404"
    assert "-fs" in cmd and cmd[cmd.index("-fs") + 1] == "0"


def test_parse_ffuf_extracts_matches():
    parsed = _parse_ffuf(_SAMPLE_STDOUT)
    assert parsed["match_count"] == 1
    assert parsed["matches"][0]["url"] == "https://example.com/admin"
    assert parsed["matches"][0]["status"] == 200


def test_parse_ffuf_ignores_non_json_lines():
    parsed = _parse_ffuf("not json\nalso not json\n")
    assert parsed["match_count"] == 0
