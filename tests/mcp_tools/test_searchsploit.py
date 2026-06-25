import json

from mcp_servers.tools.searchsploit import _parse_searchsploit, searchsploit_lookup

_SAMPLE_STDOUT = json.dumps({
    "RESULTS_EXPLOIT": [
        {"Title": "Apache 2.4.49 - Path Traversal", "Path": "/usr/share/exploitdb/exploits/x.py", "EDB-ID": "50383"},
    ]
})


def test_searchsploit_lookup_requires_query():
    assert searchsploit_lookup(query="")["status"] == "error"


def test_searchsploit_lookup_builds_expected_argv(fake_subprocess):
    fake_subprocess.stdout = _SAMPLE_STDOUT
    searchsploit_lookup(query="Apache 2.4.49")
    assert fake_subprocess.last_call == ["searchsploit", "--json", "Apache", "2.4.49"]


def test_parse_searchsploit_extracts_exploits():
    parsed = _parse_searchsploit(_SAMPLE_STDOUT)
    assert len(parsed["exploits"]) == 1
    assert parsed["exploits"][0] == {
        "title": "Apache 2.4.49 - Path Traversal",
        "path": "/usr/share/exploitdb/exploits/x.py",
        "edb_id": "50383",
    }


def test_parse_searchsploit_handles_invalid_json():
    parsed = _parse_searchsploit("not json at all")
    assert "Could not parse JSON output" in parsed["summary"]
    assert "raw_preview" in parsed
