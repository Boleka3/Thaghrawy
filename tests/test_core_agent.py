import pytest

from core.agent import PentestAgent


def _events_of_type(events, event_type):
    return [e for e in events if e["type"] == event_type]


async def _drain(stream):
    return [event async for event in stream]


@pytest.mark.anyio
async def test_chat_plain_text_reply_no_tools(tmp_memory, real_registry, fake_provider):
    provider = fake_provider(scripts=[
        [{"type": "token", "content": "Hello, "}, {"type": "token", "content": "how can I help?"}],
    ])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )

    events = [event async for event in agent.chat("hi")]

    tokens = _events_of_type(events, "token")
    assert "".join(t["content"] for t in tokens) == "Hello, how can I help?"
    assert _events_of_type(events, "tool_call") == []
    assert events[-1] == {"type": "done", "steps": 0}
    assert len(provider.calls) == 1


@pytest.mark.anyio
async def test_chat_tool_call_then_final_text(tmp_memory, real_registry, fake_provider):
    finding_args = {
        "finding": {
            "title": "SQLi in login",
            "severity": "high",
            "vuln_type": "SQL Injection",
            "description": "d",
            "reproduction_steps": "r",
            "technique_used": "sqlmap",
            "target": "https://example.com/login",
            "engagement_id": "eng-1",
        }
    }
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "save_finding", "arguments": finding_args}],
        [{"type": "token", "content": "Saved the finding."}],
    ])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )

    events = [event async for event in agent.chat("save this finding")]
    types_in_order = [e["type"] for e in events]

    assert "tool_call" in types_in_order
    assert "tool_result" in types_in_order
    assert "finding_saved" in types_in_order
    assert types_in_order.index("tool_call") < types_in_order.index("tool_result")
    assert types_in_order.index("tool_result") < types_in_order.index("finding_saved")
    final_tokens = _events_of_type(events, "token")
    assert "".join(t["content"] for t in final_tokens) == "Saved the finding."
    assert events[-1] == {"type": "done", "steps": 1}
    steps = _events_of_type(events, "step")
    assert len(steps) == 1 and steps[0]["tool"] == "save_finding"
    assert len(provider.calls) == 2

    saved = tmp_memory.load_engagement_findings("eng-1")
    assert len(saved) == 1
    assert saved[0]["metadata"]["title"] == "SQLi in login"


@pytest.mark.anyio
async def test_chat_hits_max_tool_iterations(tmp_memory, real_registry, fake_provider):
    from core.agent import MAX_TOOL_ITERATIONS

    tool_call_event = [{
        "type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "anything"},
    }]
    provider = fake_provider(scripts=[tool_call_event for _ in range(MAX_TOOL_ITERATIONS)])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )

    events = [event async for event in agent.chat("keep searching forever")]
    errors = _events_of_type(events, "error")
    assert len(errors) == 1
    assert "iteration limit" in errors[0]["message"] or "tool-call limit" in errors[0]["message"]
    assert events[-1] == {"type": "done", "steps": MAX_TOOL_ITERATIONS}
    assert len(provider.calls) == MAX_TOOL_ITERATIONS


@pytest.mark.anyio
async def test_chat_persists_step_count_to_engagement(tmp_memory, real_registry, fake_provider, tmp_path):
    from engagements.manager import EngagementManager

    manager = EngagementManager(base_dir=str(tmp_path))
    engagement = manager.create(name="e", target="https://example.com")

    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "x"}}],
        [{"type": "token", "content": "done"}],
    ])
    agent = PentestAgent(
        engagement_id=engagement.id, target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
        engagement_manager=manager,
    )

    await _drain(agent.chat("go"))

    reloaded = manager.get(engagement.id)
    assert reloaded.total_steps == 1
    assert reloaded.turn_count == 1
    assert reloaded.average_steps_per_task == 1.0


@pytest.mark.anyio
async def test_chat_provider_exception_yields_error_and_stops(tmp_memory, real_registry, fake_provider):
    provider = fake_provider(scripts=[[RuntimeError("LLM is down")]])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )

    events = [event async for event in agent.chat("hi")]

    assert len(events) == 1
    assert events[0]["type"] == "error"
    assert "LLM is down" in events[0]["message"]


@pytest.mark.anyio
async def test_chat_memory_search_failure_still_proceeds(tmp_memory, real_registry, fake_provider, monkeypatch):
    def raise_search(*a, **k):
        raise RuntimeError("chroma is down")

    monkeypatch.setattr(tmp_memory, "search_context", raise_search)
    provider = fake_provider(scripts=[[{"type": "token", "content": "still working"}]])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )

    events = [event async for event in agent.chat("hi")]
    errors = _events_of_type(events, "error")
    assert len(errors) == 1
    assert "Memory search failed" in errors[0]["message"]
    assert "".join(t["content"] for t in _events_of_type(events, "token")) == "still working"
    assert events[-1] == {"type": "done", "steps": 0}
