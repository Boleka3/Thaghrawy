from mcp_servers.tools.ssrf import _SSRF_PAYLOADS, _parse_curl_metrics, ssrf_test


def test_ssrf_test_requires_url_and_param():
    assert ssrf_test(url="", param="u")["status"] == "error"
    assert ssrf_test(url="http://x/", param="")["status"] == "error"


def test_parse_curl_metrics_splits_code_and_size():
    assert _parse_curl_metrics("200:1024") == {"http_code": "200", "response_size": 1024}
    assert _parse_curl_metrics("") == {"http_code": "ERR", "response_size": 0}


def test_ssrf_test_runs_every_payload_and_flags_suspicious(fake_subprocess):
    fake_subprocess.stdout = "200:1024"
    result = ssrf_test(url="http://target/fetch?url=", param="url")
    assert result["status"] == "success"
    assert len(result["results"]) == len(_SSRF_PAYLOADS)
    # 200 + non-empty body for every payload -> all flagged suspicious.
    assert len(result["suspicious_payloads"]) == len(_SSRF_PAYLOADS)


def test_ssrf_test_no_indicators_when_empty_body(fake_subprocess):
    fake_subprocess.stdout = "200:0"
    result = ssrf_test(url="http://target/fetch?url=", param="url")
    assert result["suspicious_payloads"] == []
    assert "No SSRF indicators found" in result["summary"]
