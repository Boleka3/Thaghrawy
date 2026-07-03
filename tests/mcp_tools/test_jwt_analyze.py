import json

from mcp_servers.tools.jwt_analyze import jwt_analyze


def _make_jwt(header: dict, payload: dict) -> str:
    import base64

    def _b64(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}.signature"


def test_jwt_analyze_requires_token():
    assert jwt_analyze(token="")["status"] == "error"


def test_jwt_analyze_invalid_format():
    assert jwt_analyze(token="no-dots")["status"] == "error"
    assert jwt_analyze(token="")["status"] == "error"


def test_jwt_analyze_reports_alg_none():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "123", "admin": True})
    result = jwt_analyze(token)
    assert result["status"] == "success"
    assert any(f["issue"] == "alg:none" for f in result["findings"])
    assert result["severity"] == "critical"


def test_jwt_analyze_reports_missing_expiry():
    token = _make_jwt({"alg": "HS256"}, {"sub": "user123"})
    result = jwt_analyze(token)
    assert any(f["issue"] == "no_expiration" for f in result["findings"])


def test_jwt_analyze_reports_expiry_present():
    token = _make_jwt({"alg": "HS256"}, {"sub": "user123", "exp": 9999999999, "iss": "app"})
    result = jwt_analyze(token)
    assert not any(f["issue"] == "no_expiration" for f in result["findings"])


def test_jwt_analyze_reports_kid_present():
    token = _make_jwt({"alg": "HS256", "kid": "../../../etc/passwd"}, {"sub": "user123"})
    result = jwt_analyze(token)
    assert any(f["issue"] == "kid_present" for f in result["findings"])
    assert any(f["severity"] == "medium" for f in result["findings"])


def test_jwt_analyze_well_formed_token_minimal_findings():
    token = _make_jwt({"alg": "HS256"}, {"sub": "user123", "exp": 9999999999, "iss": "app", "nbf": 1000000000})
    result = jwt_analyze(token)
    assert result["status"] == "success"
    assert len([f for f in result["findings"] if f["severity"] in ("critical", "high")]) == 0
