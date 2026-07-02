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


# ── PATCH (curation) ──


def test_patch_finding_updates_vuln_type(api_client):
    eng = _create_engagement(api_client)
    api_client.post("/api/findings", json=_finding_payload(eng["id"]))

    resp = api_client.patch("/api/findings/f-1", json={"severity": "medium", "tags": ["reviewed"]})
    assert resp.status_code == 200
    updated = resp.json()["finding"]
    assert updated["severity"] == "medium"
    assert updated["tags"] == ["reviewed"]

    # persisted
    findings = api_client.get(f"/api/findings/engagement/{eng['id']}").json()
    assert findings[0]["metadata"]["severity"] == "medium"


def test_patch_unknown_finding_404(api_client):
    resp = api_client.patch("/api/findings/nope", json={"severity": "low"})
    assert resp.status_code == 404


def test_patch_invalid_severity_422(api_client):
    eng = _create_engagement(api_client)
    api_client.post("/api/findings", json=_finding_payload(eng["id"]))
    resp = api_client.patch("/api/findings/f-1", json={"severity": "catastrophic"})
    assert resp.status_code == 422


def test_patch_no_fields_400(api_client):
    eng = _create_engagement(api_client)
    api_client.post("/api/findings", json=_finding_payload(eng["id"]))
    resp = api_client.patch("/api/findings/f-1", json={})
    assert resp.status_code == 400


# ── DELETE (mark false positive) ──


def test_delete_finding_decrements_count(api_client):
    eng = _create_engagement(api_client)
    api_client.post("/api/findings", json=_finding_payload(eng["id"]))
    assert api_client.get(f"/api/engagements/{eng['id']}").json()["findings_count"] == 1

    resp = api_client.delete("/api/findings/f-1")
    assert resp.status_code == 200
    assert api_client.get(f"/api/engagements/{eng['id']}").json()["findings_count"] == 0
    assert api_client.get(f"/api/findings/engagement/{eng['id']}").json() == []


def test_delete_unknown_finding_404(api_client):
    assert api_client.delete("/api/findings/nope").status_code == 404


# ── promote (result -> draft) ──


def test_promote_nuclei_result_returns_drafts(api_client):
    eng = _create_engagement(api_client)
    resp = api_client.post("/api/findings/promote", json={
        "tool": "nuclei_scan",
        "engagement_id": eng["id"],
        "target": "http://t",
        "result": {"findings": [{"template": "missing-csp", "severity": "low", "matched": "http://t/"}]},
    })
    assert resp.status_code == 200
    drafts = resp.json()["drafts"]
    assert len(drafts) == 1
    assert drafts[0]["vuln_type"] == "Security Misconfiguration"
    assert drafts[0]["engagement_id"] == eng["id"]


# ── human-run-a-tool ──


def test_run_tool_executes_and_records(api_client):
    eng = _create_engagement(api_client)
    resp = api_client.post(
        f"/api/engagements/{eng['id']}/tools/search_memory",
        json={"query": "anything"},
    )
    assert resp.status_code == 200
    assert resp.json()["tool"] == "search_memory"
    assert "output" in resp.json()


def test_run_unknown_tool_404(api_client):
    eng = _create_engagement(api_client)
    resp = api_client.post(f"/api/engagements/{eng['id']}/tools/no_such_tool", json={})
    assert resp.status_code == 404
