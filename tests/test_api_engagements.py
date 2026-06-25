def test_create_and_get_engagement(api_client):
    created = api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"})
    assert created.status_code == 200
    engagement_id = created.json()["id"]

    fetched = api_client.get(f"/api/engagements/{engagement_id}")
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "Acme"


def test_create_with_scope_and_tech_stack(api_client):
    response = api_client.post("/api/engagements", json={
        "name": "Acme", "target": "https://acme.example.com",
        "scope": "acme.example.com", "tech_stack": ["django"],
    })
    body = response.json()
    assert body["scope"] == "acme.example.com"
    assert body["tech_stack"] == ["django"]


def test_create_defaults_to_full_analysis_mode(api_client):
    created = api_client.post("/api/engagements", json={"name": "X", "target": "https://x.com"}).json()
    assert created["analysis_mode"] == "full_analysis"


def test_create_with_recon_only_mode_round_trips(api_client):
    created = api_client.post("/api/engagements", json={
        "name": "X", "target": "https://x.com", "analysis_mode": "recon_only",
    }).json()
    assert created["analysis_mode"] == "recon_only"
    fetched = api_client.get(f"/api/engagements/{created['id']}").json()
    assert fetched["analysis_mode"] == "recon_only"


def test_list_engagements_includes_created(api_client):
    api_client.post("/api/engagements", json={"name": "X", "target": "https://x.com"})
    response = api_client.get("/api/engagements")
    assert response.status_code == 200
    names = [e["name"] for e in response.json()]
    assert "X" in names


def test_get_unknown_engagement_404(api_client):
    response = api_client.get("/api/engagements/does-not-exist")
    assert response.status_code == 404


def test_patch_updates_fields(api_client):
    created = api_client.post("/api/engagements", json={"name": "X", "target": "https://x.com"}).json()
    response = api_client.patch(f"/api/engagements/{created['id']}", json={"notes": "found something"})
    assert response.status_code == 200
    assert response.json()["notes"] == "found something"


def test_patch_unknown_engagement_404(api_client):
    response = api_client.patch("/api/engagements/does-not-exist", json={"notes": "x"})
    assert response.status_code == 404


def test_close_engagement(api_client):
    created = api_client.post("/api/engagements", json={"name": "X", "target": "https://x.com"}).json()
    response = api_client.post(f"/api/engagements/{created['id']}/close")
    assert response.status_code == 200
    assert response.json()["status"] == "completed"


def test_close_unknown_engagement_404(api_client):
    response = api_client.post("/api/engagements/does-not-exist/close")
    assert response.status_code == 404


def test_get_log_returns_creation_entry(api_client):
    created = api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()
    response = api_client.get(f"/api/engagements/{created['id']}/log")
    assert response.status_code == 200
    assert "Acme" in response.json()["log"]


def test_delete_engagement(api_client):
    created = api_client.post("/api/engagements", json={"name": "X", "target": "https://x.com"}).json()
    response = api_client.delete(f"/api/engagements/{created['id']}")
    assert response.status_code == 200
    assert api_client.get(f"/api/engagements/{created['id']}").status_code == 404


def test_delete_unknown_engagement_404(api_client):
    response = api_client.delete("/api/engagements/does-not-exist")
    assert response.status_code == 404
