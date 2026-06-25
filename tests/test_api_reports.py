def _create_engagement(api_client):
    return api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()


def _save_finding(api_client, engagement_id):
    api_client.post("/api/findings", json={
        "id": "f-1", "title": "SQL Injection in login", "severity": "high", "vuln_type": "SQL Injection",
        "description": "d", "reproduction_steps": "r", "technique_used": "sqlmap",
        "target": "https://acme.example.com/login", "engagement_id": engagement_id, "date": "2026-06-01",
        "business_impact": "Customer data could be exfiltrated.", "remediation": "Use parameterized queries.",
    })


def test_generate_reports_for_unknown_engagement_404(api_client):
    response = api_client.post("/api/engagements/does-not-exist/reports")
    assert response.status_code == 404


def test_generate_reports_returns_technical_and_executive_paths(api_client):
    engagement = _create_engagement(api_client)
    _save_finding(api_client, engagement["id"])

    response = api_client.post(f"/api/engagements/{engagement['id']}/reports")
    assert response.status_code == 200
    body = response.json()
    assert "markdown" in body["technical"] and "pdf" in body["technical"]
    assert "markdown" in body["executive"] and "pdf" in body["executive"]


def test_list_reports_for_unknown_engagement_404(api_client):
    response = api_client.get("/api/engagements/does-not-exist/reports")
    assert response.status_code == 404


def test_list_reports_only_returns_matching_engagement(api_client):
    engagement_a = _create_engagement(api_client)
    _save_finding(api_client, engagement_a["id"])
    api_client.post(f"/api/engagements/{engagement_a['id']}/reports")

    engagement_b = api_client.post("/api/engagements", json={"name": "B", "target": "https://b.com"}).json()

    response_a = api_client.get(f"/api/engagements/{engagement_a['id']}/reports")
    response_b = api_client.get(f"/api/engagements/{engagement_b['id']}/reports")

    assert len(response_a.json()) == 4  # technical md+pdf, executive md+pdf
    assert response_b.json() == []
    types = {r["type"] for r in response_a.json()}
    assert types == {"technical", "executive"}


def test_download_report_returns_file_contents(api_client):
    engagement = _create_engagement(api_client)
    _save_finding(api_client, engagement["id"])
    api_client.post(f"/api/engagements/{engagement['id']}/reports")

    listing = api_client.get(f"/api/engagements/{engagement['id']}/reports").json()
    md_report = next(r for r in listing if r["format"] == "md" and r["type"] == "executive")

    response = api_client.get(f"/api/reports/{md_report['filename']}")
    assert response.status_code == 200
    assert "Executive Summary" in response.text


def test_download_unknown_report_404(api_client):
    response = api_client.get("/api/reports/does-not-exist.pdf")
    assert response.status_code == 404


def test_download_report_blocks_path_traversal(api_client):
    # %2F-encoded slashes survive client-side dot-segment normalization, so
    # this is what actually reaches the router as "../../etc/passwd" rather
    # than being resolved away before the request is even sent. Starlette's
    # plain string path converter rejects an embedded "/" outright (404)
    # before it would even reach our own ".." check (400) - either outcome
    # means the traversal never resolves to a real file.
    response = api_client.get("/api/reports/..%2F..%2Fetc%2Fpasswd")
    assert response.status_code in (400, 404)


def test_download_report_rejects_dotdot_filename_at_handler_level(api_client):
    # A single path segment with no "/" reaches the handler's own ".."
    # substring check directly. A bare ".." segment gets resolved away by
    # client-side URL dot-segment normalization (RFC 3986) before the
    # request is even sent, so embed it in a non-dot-only segment instead.
    response = api_client.get("/api/reports/..secret")
    assert response.status_code == 400
