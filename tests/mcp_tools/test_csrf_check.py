from mcp_servers.tools.csrf_check import csrf_check


_HTML_WITH_CSRF = """<html><body>
<form action="/login" method="POST">
<input type="hidden" name="csrfmiddlewaretoken" value="abc123">
<input type="text" name="username">
<input type="submit">
</form>
</body></html>"""

_HTML_NO_CSRF = """<html><body>
<form action="/login" method="POST">
<input type="text" name="username">
<input type="password" name="password">
<input type="submit">
</form>
</body></html>"""

_HTML_NO_FORMS = "<html><body><p>hello</p></body></html>"

_HTML_MULTI_FORM = """<html><body>
<form action="/login" method="POST"><input name="user"></form>
<form action="/search" method="GET"><input name="q"></form>
</body></html>"""


def test_csrf_check_requires_url():
    assert csrf_check(url="")["status"] == "error"


def test_csrf_check_detects_protected_forms(fake_httpx):
    fake_httpx.set_response(status_code=200, text=_HTML_WITH_CSRF)
    result = csrf_check("http://target/login")
    assert result["status"] == "success"
    assert result["has_csrf_protection"] is True
    assert result["forms_found"] == 1


def test_csrf_check_identifies_unprotected_post_form(fake_httpx):
    fake_httpx.set_response(status_code=200, text=_HTML_NO_CSRF)
    result = csrf_check("http://target/login")
    assert result["status"] == "success"
    assert result["has_csrf_protection"] is False
    assert result["post_forms"] == 1
    assert result["severity"] == "high"


def test_csrf_check_no_forms_no_issue(fake_httpx):
    fake_httpx.set_response(status_code=200, text=_HTML_NO_FORMS)
    result = csrf_check("http://target/")
    assert result["status"] == "success"
    assert result["forms_found"] == 0
    assert result["has_csrf_protection"] is False
    assert result["severity"] == "info"


def test_csrf_check_multi_form_detection(fake_httpx):
    fake_httpx.set_response(status_code=200, text=_HTML_MULTI_FORM)
    result = csrf_check("http://target/")
    assert result["forms_found"] == 2
    assert result["post_forms"] == 1
