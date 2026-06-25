def _create_engagement(api_client):
    return api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()


def _save_finding(api_client, engagement_id):
    api_client.post("/api/findings", json={
        "id": "f-1", "title": "SQL Injection in login", "severity": "high", "vuln_type": "SQL Injection",
        "description": "d", "reproduction_steps": "r", "technique_used": "sqlmap",
        "target": "https://acme.example.com/login", "engagement_id": engagement_id, "date": "2026-06-01",
    })


def test_memory_search_findings_collection(api_client):
    engagement = _create_engagement(api_client)
    _save_finding(api_client, engagement["id"])

    response = api_client.post("/api/memory/search", json={"query": "SQL injection", "collection": "findings"})
    assert response.status_code == 200
    assert "findings" in response.json()
    assert len(response.json()["findings"]) >= 1


def test_memory_search_both_collections_default(api_client):
    engagement = _create_engagement(api_client)
    _save_finding(api_client, engagement["id"])

    response = api_client.post("/api/memory/search", json={"query": "SQL injection"})
    body = response.json()
    assert "findings" in body
    assert "techniques" in body


def test_memory_stats_reflects_saved_finding(api_client):
    engagement = _create_engagement(api_client)
    _save_finding(api_client, engagement["id"])

    response = api_client.get("/api/memory/stats")
    assert response.status_code == 200
    assert response.json()["findings_count"] >= 1
