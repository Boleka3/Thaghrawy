"""End-to-end WebSocket protocol tests over the concurrent reader/worker.

These exercise control paths that don't need the LLM (help / set_phase / run_tool
of a safe memory tool), so no provider call is made.
"""

from api.websocket import _HELP, _parse_slash
from core.agent import PentestAgent


def _create_engagement(api_client):
    return api_client.post("/api/engagements", json={"name": "E", "target": "http://t"}).json()


def _seed_agent(api_client, fake_provider, engagement_id, scripts):
    """Seed a fake-provider agent that also carries the app's real engagement
    manager, so chat-transcript persistence has somewhere to write."""
    agent = PentestAgent(
        engagement_id=engagement_id,
        target="http://t",
        memory=api_client.app.state.memory,
        engagement_manager=api_client.app.state.engagements,
        provider=fake_provider(scripts=scripts),
    )
    api_client.app.state.agents[engagement_id] = agent
    return agent


def _drain_until_done(ws):
    types = []
    while True:
        msg = ws.receive_json()
        types.append(msg["type"])
        if msg["type"] == "done":
            return types


def test_parse_slash_tools_command():
    assert _parse_slash("/tools") == {"type": "list_tools"}


def test_parse_slash_tools_command_ignores_trailing_args():
    # Unlike /run or /edit, /tools takes no arguments - anything after it is dropped.
    assert _parse_slash("/tools whatever") == {"type": "list_tools"}


def test_help_text_lists_tools_command():
    assert any(line.startswith("/tools") for line in _HELP)


def test_help_command_over_websocket(api_client):
    eng = _create_engagement(api_client)
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_text("/help")
        msg = ws.receive_json()
        assert msg["type"] == "help"
        assert any("/approve" in c for c in msg["commands"])


def test_tools_command_over_websocket(api_client):
    eng = _create_engagement(api_client)
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_text("/tools")
        msg = ws.receive_json()
        assert msg["type"] == "tools"
        assert any(t["name"] == "search_memory" for t in msg["tools"])
        assert {"name", "description", "dangerous"} <= msg["tools"][0].keys()


def test_set_phase_over_websocket(api_client):
    eng = _create_engagement(api_client)
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_json({"type": "set_phase", "phase": "collab"})
        msg = ws.receive_json()
        assert msg == {"type": "phase", "phase": "collaboration"}


def test_run_tool_over_websocket(api_client):
    eng = _create_engagement(api_client)
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_json({"type": "run_tool", "tool": "search_memory", "arguments": {"query": "x"}})
        msg = ws.receive_json()
        assert msg["type"] == "tool_result"
        assert msg["tool"] == "search_memory"
        assert msg["source"] == "human"


def test_unknown_tool_run_over_websocket_surfaces_error(api_client):
    eng = _create_engagement(api_client)
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_json({"type": "run_tool", "tool": "does_not_exist", "arguments": {}})
        msg = ws.receive_json()
        # registry.execute returns a structured {"error": ...}; the worker relays it.
        assert msg["type"] == "tool_result"
        assert "error" in msg["output"]


def test_chat_transcript_is_persisted_and_served(api_client, fake_provider):
    eng = _create_engagement(api_client)
    _seed_agent(api_client, fake_provider, eng["id"], scripts=[[{"type": "token", "content": "hi there"}]])
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_text("hello agent")
        _drain_until_done(ws)

    transcript = api_client.get(f"/api/engagements/{eng['id']}/chat").json()
    types = [e["type"] for e in transcript]
    assert "user" in types and "agent_message" in types
    user_ev = next(e for e in transcript if e["type"] == "user")
    assert user_ev["text"] == "hello agent"
    # Streamed tokens are collapsed into a single persisted agent_message.
    agent_ev = next(e for e in transcript if e["type"] == "agent_message")
    assert agent_ev["content"] == "hi there"


def test_suggest_runs_a_model_turn_not_the_dead_fallback(api_client, fake_provider):
    eng = _create_engagement(api_client)
    _seed_agent(api_client, fake_provider, eng["id"], scripts=[[{"type": "token", "content": "try nuclei next"}]])
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_text("/suggest")
        types = _drain_until_done(ws)
    # It actually streams a model turn now, not the old "not available yet" info.
    assert "token" in types
    assert "info" not in types


def test_promote_without_prior_result_explains_itself(api_client, fake_provider):
    eng = _create_engagement(api_client)
    _seed_agent(api_client, fake_provider, eng["id"], scripts=[])
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_text("/promote")
        msg = ws.receive_json()
    assert msg["type"] == "info"
    assert "No recent tool result" in msg["message"]


def test_compact_over_websocket_summarizes_and_overwrites_transcript(api_client, fake_provider):
    eng = _create_engagement(api_client)
    agent = _seed_agent(api_client, fake_provider, eng["id"], scripts=[])
    agent.messages = [
        {"role": "user", "content": "scan the target"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "name": "nmap_scan", "arguments": {}}]},
        {"role": "tool", "tool_call_id": "1", "name": "nmap_scan", "content": "ports"},
    ]
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_text("/compact")
        msg = ws.receive_json()

    assert msg["type"] == "compacted"
    assert "nmap_scan" in msg["summary"]
    assert len(agent.messages) == 1  # context collapsed
    # The persisted transcript is replaced with the single compaction marker.
    transcript = api_client.get(f"/api/engagements/{eng['id']}/chat").json()
    assert transcript == [{"type": "compacted", "summary": msg["summary"]}]


def test_interrupt_over_websocket_runs_the_new_instruction(api_client, fake_provider):
    eng = _create_engagement(api_client)
    _seed_agent(api_client, fake_provider, eng["id"], scripts=[[{"type": "token", "content": "new plan"}]])
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_json({"type": "interrupt", "text": "stop and do this instead"})
        types = _drain_until_done(ws)
    # The queued instruction ran as a fresh turn (tokens streamed).
    assert "token" in types
