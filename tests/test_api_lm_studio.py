"""Tests for api/routes/lm_studio.py - the LM Studio readiness probe."""
import config
from api.routes import lm_studio


class _FakeResp:
    def __init__(self, model_ids):
        self._ids = model_ids

    def json(self):
        return {"data": [{"id": m} for m in self._ids]}


class _FakeClient:
    response = None
    raise_exc = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        if _FakeClient.raise_exc:
            raise _FakeClient.raise_exc
        return _FakeClient.response


def test_status_returns_false_when_provider_not_openai(api_client, monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "anthropic")
    resp = api_client.get("/api/lm-studio/status")
    assert resp.status_code == 200
    assert resp.json()["lm_studio"] is False


def test_status_reports_loaded_model(api_client, monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(config, "OPENAI_BASE_URL", "http://lmstudio.local/v1")
    monkeypatch.setattr(config, "OPENAI_MODEL", "qwen3")
    _FakeClient.raise_exc = None
    _FakeClient.response = _FakeResp(["qwen3", "other"])
    monkeypatch.setattr(lm_studio.httpx, "AsyncClient", _FakeClient)

    resp = api_client.get("/api/lm-studio/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["lm_studio"] is True
    assert body["loaded"] is True


def test_status_returns_503_when_endpoint_unreachable(api_client, monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(config, "OPENAI_BASE_URL", "http://lmstudio.local/v1")
    monkeypatch.setattr(config, "OPENAI_MODEL", "qwen3")
    _FakeClient.response = None
    _FakeClient.raise_exc = ConnectionError("refused")
    monkeypatch.setattr(lm_studio.httpx, "AsyncClient", _FakeClient)

    resp = api_client.get("/api/lm-studio/status")
    assert resp.status_code == 503
    assert resp.json()["loaded"] is False
