"""End-to-end WebSocket protocol tests over the concurrent reader/worker.

These exercise control paths that don't need the LLM (help / set_phase / run_tool
of a safe memory tool), so no provider call is made.
"""


def _create_engagement(api_client):
    return api_client.post("/api/engagements", json={"name": "E", "target": "http://t"}).json()


def test_help_command_over_websocket(api_client):
    eng = _create_engagement(api_client)
    with api_client.websocket_connect(f"/ws/chat?engagement_id={eng['id']}") as ws:
        ws.send_text("/help")
        msg = ws.receive_json()
        assert msg["type"] == "help"
        assert any("/approve" in c for c in msg["commands"])


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
