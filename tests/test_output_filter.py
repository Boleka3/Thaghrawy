from output_filter import ToolOutputFilter


def test_filter_nmap_extracts_only_open_tcp_lines():
    raw = (
        "Starting Nmap\n"
        "22/tcp open  ssh     OpenSSH 8.2\n"
        "80/tcp open  http    Apache 2.4.25\n"
        "81/tcp closed http\n"
        "Not a port line\n"
    )
    found = ToolOutputFilter.filter_nmap(raw)
    assert found == ["22/tcp open  ssh     OpenSSH 8.2", "80/tcp open  http    Apache 2.4.25"]


def test_filter_sqlmap_extracts_injectable_payload_lines():
    raw = (
        "[10:00:00] [INFO] testing connection to the target URL\n"
        "[10:00:01] [CRITICAL] payload: id=1' AND SLEEP(5)--\n"
        "[10:00:02] [INFO] title: MySQL >= 5.0 AND time-based blind\n"
        "random unrelated line\n"
    )
    found = ToolOutputFilter.filter_sqlmap(raw)
    assert found == [
        "[10:00:01] [CRITICAL] payload: id=1' AND SLEEP(5)--",
        "[10:00:02] [INFO] title: MySQL >= 5.0 AND time-based blind",
    ]


def test_filter_nikto_extracts_osvdb_and_vulnerability_lines():
    raw = (
        "- Nikto v2.5.0\n"
        "+ OSVDB-3092: /admin/: This might be interesting\n"
        "+ Server may be vulnerable to Vulnerability XSS\n"
        "+ Target IP: 10.0.0.1\n"
    )
    found = ToolOutputFilter.filter_nikto(raw)
    assert len(found) == 2
    assert any("OSVDB-3092" in line for line in found)
    assert any("Vulnerability" in line for line in found)


def test_filter_generic_returns_unchanged_when_under_limit():
    raw = "short output"
    assert ToolOutputFilter.filter_generic(raw, max_chars=2000) == raw


def test_filter_generic_truncates_head_and_tail_when_over_limit():
    raw = "A" * 3000
    result = ToolOutputFilter.filter_generic(raw, max_chars=100)
    assert "[... TRUNCATED BY FILTER ...]" in result
    assert result.startswith("A" * 50)
    assert result.endswith("A" * 50)
    assert len(result) < len(raw)


def test_filter_generic_exactly_at_limit_returns_unchanged():
    raw = "B" * 100
    assert ToolOutputFilter.filter_generic(raw, max_chars=100) == raw


def test_apply_filter_dispatches_by_tool_name_case_insensitive():
    result = ToolOutputFilter.apply_filter("NMAP_scan", "22/tcp open ssh\n")
    assert result["findings"] == ["22/tcp open ssh"]
    assert result["count"] == 1
    assert "summary" in result


def test_apply_filter_unknown_tool_falls_back_to_generic():
    result = ToolOutputFilter.apply_filter("some_unknown_tool", "just some raw output")
    assert "raw_truncated" in result
    assert "summary" in result
    assert result["count"] == 1


def test_apply_filter_handles_empty_tool_name():
    result = ToolOutputFilter.apply_filter("", "raw output here")
    assert "raw_truncated" in result
    assert result["count"] == 1


def test_apply_filter_handles_none_tool_name():
    result = ToolOutputFilter.apply_filter(None, "raw output here")
    assert "raw_truncated" in result
