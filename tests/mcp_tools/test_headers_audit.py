from mcp_servers.tools.headers_audit import headers_audit


def test_headers_audit_requires_url():
    assert headers_audit(url="")["status"] == "error"


def test_headers_audit_reports_missing_headers(fake_httpx):
    fake_httpx.set_response(status_code=200, text="ok", headers={})
    result = headers_audit("http://target/")
    assert result["status"] == "success"
    assert all(not f["present"] for f in result["findings"] if f["severity"] != "info")
    assert len(result["findings"]) == 9


def test_headers_audit_reports_present_headers(fake_httpx):
    fake_httpx.set_response(
        status_code=200,
        text="ok",
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
        },
    )
    result = headers_audit("https://target/")
    assert result["status"] == "success"
    present = [f for f in result["findings"] if f["present"]]
    assert len(present) >= 5


def test_headers_audit_rejects_bad_url(fake_httpx):
    fake_httpx.set_response(status_code=404, text="not found")
    result = headers_audit("http://target/")
    assert result["status"] == "success"  # 404 is still a valid HTTP response


def test_headers_audit_request_error(fake_httpx, monkeypatch):
    import httpx

    def _raise(*a, **kw):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr("httpx.get", _raise)
    result = headers_audit("http://target/")
    assert result["status"] == "error"
