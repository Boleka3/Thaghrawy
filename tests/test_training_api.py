"""Tests for the /api/training/export endpoint (training.py route)."""
import json


def _create_engagement(api_client):
    return api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()


def _save_finding(api_client, engagement_id, **kw):
    payload = {
        "id": "f-1", "title": "SQL Injection in login", "severity": "high", "vuln_type": "SQL Injection",
        "description": "d", "reproduction_steps": "r", "technique_used": "sqlmap",
        "target": "https://acme.example.com/login", "engagement_id": engagement_id, "date": "2026-06-01",
    }
    payload.update(kw)
    api_client.post("/api/findings", json=payload)


def test_training_export_messages_format(api_client):
    eng = _create_engagement(api_client)
    _save_finding(api_client, eng["id"])
    resp = api_client.get("/api/training/export?format=messages")
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "messages"
    assert body["count"] >= 1
    assert all("messages" in ex for ex in body["examples"])
    assert body["sources"]["findings"] >= 1


def test_training_export_sft_format(api_client):
    eng = _create_engagement(api_client)
    _save_finding(api_client, eng["id"])
    resp = api_client.get("/api/training/export?format=sft")
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "sft"
    assert all(("prompt" in ex and "completion" in ex) for ex in body["examples"])


def test_training_export_preference_format(api_client):
    eng = _create_engagement(api_client)
    _save_finding(api_client, eng["id"])
    resp = api_client.get("/api/training/export?format=preference")
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "preference"
    # No trajectory records exist, so preference should be empty
    assert body["count"] == 0


def test_training_export_empty_no_findings(api_client):
    resp = api_client.get("/api/training/export?format=messages")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_training_export_invalid_format_422(api_client):
    resp = api_client.get("/api/training/export?format=csv")
    assert resp.status_code == 422


def test_training_export_with_flag_finding(api_client):
    eng = _create_engagement(api_client)
    _save_finding(api_client, eng["id"],
                  id="f-flag",
                  title="Secret/flag captured: picoCTF{test_export_flag}",
                  vuln_type="Sensitive Data Exposure",
                  technique_used="shell",
                  tags=["flag", "auto-ingested"])
    resp = api_client.get("/api/training/export?format=messages")
    assert resp.status_code == 200
    examples = resp.json()["examples"]
    flags = [ex for ex in examples if "picoCTF{test_export_flag}" in str(ex)]
    assert len(flags) >= 1


def test_training_export_includes_techniques(api_client):
    from memory.schemas import Technique
    memory = api_client.app.state.memory
    # Persist a technique directly via the store
    t = Technique(
        id="t-export-1", name="JWT alg=none",
        description="Strip the JWT signature.",
        works_against=["JWT"], platform="api",
        engagement_id="eng-1", date="2026-06-01",
    )
    memory.add_technique(t)
    resp = api_client.get("/api/training/export?format=messages")
    assert resp.status_code == 200
    body = resp.json()
    assert body["sources"]["techniques"] >= 1
