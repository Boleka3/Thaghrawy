from mcp_servers.tools.xxe_test import xxe_test


_LEAKED_RESPONSE = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"

_ERROR_RESPONSE = """<html><body><pre>SAXParseException: Entity resolution failed</pre></body></html>"""


def test_xxe_test_requires_url():
    assert xxe_test(url="")["status"] == "error"


def test_xxe_test_detects_file_leak(fake_httpx):
    fake_httpx.set_response(status_code=200, text=_LEAKED_RESPONSE)
    result = xxe_test("http://target/xml")
    assert result["status"] == "success"
    assert result["vulnerable_count"] > 0


def test_xxe_test_detects_error_reflection(fake_httpx):
    fake_httpx.set_response(status_code=500, text=_ERROR_RESPONSE)
    result = xxe_test("http://target/xml")
    assert result["status"] == "success"
    assert result["vulnerable_count"] > 0


def test_xxe_test_no_vuln_on_clean_response(fake_httpx):
    fake_httpx.set_response(status_code=200, text="<response><status>ok</status></response>")
    result = xxe_test("http://target/xml")
    assert result["status"] == "success"
    assert result["vulnerable_count"] == 0
    assert "No XXE indicators found" in result["summary"]


def test_xxe_test_uses_put_method(fake_httpx):
    fake_httpx.set_response(status_code=200, text="ok")
    result = xxe_test("http://target/xml", method="PUT")
    assert result["status"] == "success"
    # Verify the calls were made with PUT
    assert all(c["method"] == "PUT" for c in fake_httpx.calls)


def test_xxe_test_request_error(fake_httpx, monkeypatch):
    import httpx

    def _raise(*a, **kw):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("httpx.request", _raise)
    result = xxe_test("http://target/xml")
    assert result["status"] == "success"
    assert all(r.get("error") for r in result["results"])
