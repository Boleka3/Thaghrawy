def _create_engagement(api_client, name="Acme", target="https://acme.example.com"):
    return api_client.post("/api/engagements", json={"name": name, "target": target}).json()


def _finding_payload(engagement_id, **overrides):
    payload = {
        "id": "f-1",
        "title": "SQL Injection in login",
        "severity": "high",
        "vuln_type": "SQL Injection",
        "description": "d",
        "reproduction_steps": "r",
        "technique_used": "sqlmap",
        "target": "https://acme.example.com/login",
        "engagement_id": engagement_id,
        "date": "2026-06-01",
    }
    payload.update(overrides)
    return payload


def test_save_finding_increments_engagement_findings_count(api_client):
    engagement = _create_engagement(api_client)
    response = api_client.post("/api/findings", json=_finding_payload(engagement["id"]))
    assert response.status_code == 200
    assert response.json()["status"] == "saved"

    updated = api_client.get(f"/api/engagements/{engagement['id']}").json()
    assert updated["findings_count"] == 1


def test_list_engagement_findings(api_client):
    engagement = _create_engagement(api_client)
    api_client.post("/api/findings", json=_finding_payload(engagement["id"]))

    response = api_client.get(f"/api/findings/engagement/{engagement['id']}")
    assert response.status_code == 200
    findings = response.json()
    assert len(findings) == 1
    assert findings[0]["metadata"]["title"] == "SQL Injection in login"


def test_list_engagement_findings_empty_for_unknown_engagement(api_client):
    response = api_client.get("/api/findings/engagement/does-not-exist")
    assert response.status_code == 200
    assert response.json() == []


def test_search_findings(api_client):
    engagement = _create_engagement(api_client)
    api_client.post("/api/findings", json=_finding_payload(engagement["id"]))

    response = api_client.post("/api/findings/search", json={"query": "SQL injection", "top_k": 3})
    assert response.status_code == 200
    results = response.json()
    assert len(results) >= 1
    assert results[0]["id"] == "f-1"


def test_search_findings_scoped_to_engagement(api_client):
    engagement_a = _create_engagement(api_client, name="A")
    engagement_b = _create_engagement(api_client, name="B")
    api_client.post("/api/findings", json=_finding_payload(engagement_a["id"], id="f-a"))
    api_client.post("/api/findings", json=_finding_payload(engagement_b["id"], id="f-b"))

    response = api_client.post(
        "/api/findings/search",
        json={"query": "SQL injection", "top_k": 5, "engagement_id": engagement_a["id"]},
    )
    ids = {r["id"] for r in response.json()}
    assert ids == {"f-a"}
