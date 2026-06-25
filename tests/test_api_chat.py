"""Neither POST /api/chat nor WS /ws/chat take their PentestAgent via
FastAPI Depends() - both call get_or_create_agent/_get_or_create_agent as
plain functions (api/deps.py), which only construct a real agent (and call
the real get_provider()) if engagement_id isn't already in app.state.agents.
So tests pre-seed that dict with an agent built from a fake provider,
sidestepping any real LLM call entirely."""
from core.agent import PentestAgent


def _seed_fake_agent(api_client, fake_provider, engagement_id: str, scripts: list[list[dict]]):
    memory = api_client.app.state.memory
    provider = fake_provider(scripts=scripts)
    agent = PentestAgent(
        engagement_id=engagement_id, target="https://acme.example.com",
        memory=memory, provider=provider,
    )
    api_client.app.state.agents[engagement_id] = agent
    return provider


def test_post_chat_returns_full_event_list(api_client, fake_provider):
    engagement = api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()
    _seed_fake_agent(api_client, fake_provider, engagement["id"], scripts=[
        [{"type": "token", "content": "Hello there"}],
    ])

    response = api_client.post("/api/chat", json={"engagement_id": engagement["id"], "message": "hi"})
    assert response.status_code == 200
    events = response.json()["events"]
    types = [e["type"] for e in events]
    assert "token" in types
    assert types[-1] == "done"


def test_post_chat_reuses_seeded_agent_without_calling_real_provider(api_client, fake_provider):
    engagement = api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()
    provider = _seed_fake_agent(api_client, fake_provider, engagement["id"], scripts=[
        [{"type": "token", "content": "first"}],
        [{"type": "token", "content": "second"}],
    ])

    api_client.post("/api/chat", json={"engagement_id": engagement["id"], "message": "one"})
    api_client.post("/api/chat", json={"engagement_id": engagement["id"], "message": "two"})

    assert len(provider.calls) == 2


def test_websocket_chat_relays_events_in_order(api_client, fake_provider):
    engagement = api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()
    _seed_fake_agent(api_client, fake_provider, engagement["id"], scripts=[
        [{"type": "token", "content": "Streaming reply"}],
    ])

    with api_client.websocket_connect(f"/ws/chat?engagement_id={engagement['id']}") as ws:
        ws.send_text("hi")
        received = []
        while True:
            event = ws.receive_json()
            received.append(event)
            if event["type"] == "done":
                break

    types = [e["type"] for e in received]
    assert "token" in types
    assert types[-1] == "done"


def test_websocket_chat_relays_error_event_on_provider_failure(api_client, fake_provider):
    engagement = api_client.post("/api/engagements", json={"name": "Acme", "target": "https://acme.example.com"}).json()
    _seed_fake_agent(api_client, fake_provider, engagement["id"], scripts=[[RuntimeError("LLM is down")]])

    with api_client.websocket_connect(f"/ws/chat?engagement_id={engagement['id']}") as ws:
        ws.send_text("hi")
        event = ws.receive_json()

    assert event["type"] == "error"
    assert "LLM is down" in event["message"]
