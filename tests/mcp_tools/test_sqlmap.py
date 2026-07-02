from mcp_servers.tools.sqlmap import _parse_sqlmap, sqlmap_scan

_INJECTABLE_STDOUT = (
    "sqlmap identified the following injection point(s):\n"
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
    "back-end DBMS: MySQL >= 5.0\n"
)


def test_sqlmap_scan_requires_url():
    assert sqlmap_scan(url="")["status"] == "error"


def test_sqlmap_scan_builds_expected_command(fake_subprocess):
    fake_subprocess.stdout = _INJECTABLE_STDOUT
    sqlmap_scan(url="https://example.com/login?id=1&x=2", batch=True)
    assert fake_subprocess.last_call == [
        "sqlmap", "-u", "https://example.com/login?id=1&x=2", "--batch", "--random-agent",
    ]


def test_sqlmap_scan_without_batch_omits_flag(fake_subprocess):
    fake_subprocess.stdout = "nothing"
    sqlmap_scan(url="https://example.com", batch=False)
    assert "--batch" not in fake_subprocess.last_call


def test_sqlmap_scan_returns_structured_envelope(fake_subprocess):
    fake_subprocess.stdout = _INJECTABLE_STDOUT
    result = sqlmap_scan(url="https://example.com/?id=1")
    assert result["status"] == "success"
    assert result["tool"] == "sqlmap"
    assert result["injectable"] is True
    assert "id" in result["parameters"]


def test_parse_sqlmap_detects_injection_and_dbms():
    parsed = _parse_sqlmap(_INJECTABLE_STDOUT)
    assert parsed["injectable"] is True
    assert parsed["parameters"] == ["id"]
    assert "boolean-based blind" in parsed["injection_types"]
    assert parsed["dbms"].startswith("MySQL")


def test_parse_sqlmap_no_injection():
    parsed = _parse_sqlmap("all tested parameters do not appear to be injectable")
    assert parsed["injectable"] is False
    assert parsed["parameters"] == []
