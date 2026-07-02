"""End-to-end WebSocket protocol tests over the concurrent reader/worker.

These exercise control paths that don't need the LLM (help / set_phase / run_tool
of a safe memory tool), so no provider call is made.
"""

from api.websocket import _HELP, _parse_slash


def _create_engagement(api_client):
    return api_client.post("/api/engagements", json={"name": "E", "target": "http://t"}).json()


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
