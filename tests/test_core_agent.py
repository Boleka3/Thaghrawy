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


@pytest.mark.anyio
async def test_chat_emits_finding_draft_when_flag_in_tool_result(tmp_memory, real_registry, fake_provider):
    """Agent emits finding_draft when a tool result contains a flag pattern."""
    provider = fake_provider(scripts=[
        [
            {"type": "tool_call", "id": "t1", "name": "shell", "arguments": {"command": "cat /flag.txt"}},
        ],
    ])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )
    agent.registry.register("shell", lambda command: {
        "stdout": "picoCTF{agent_found_flag}",
        "exit_code": 0, "status": "success",
    }, dangerous=True)

    events = [event async for event in agent.chat("find the flag")]
    drafts = _events_of_type(events, "finding_draft")
    assert len(drafts) == 1
    draft = drafts[0]["draft"]
    assert draft["vuln_type"] == "Sensitive Data Exposure"
    assert "flag" in draft["tags"]
    assert "agent_found_flag" in draft["description"]

    # No finding was persisted — drafts are proposals only
    saved = tmp_memory.load_engagement_findings("eng-1")
    assert len(saved) == 0


@pytest.mark.anyio
async def test_chat_does_not_emit_finding_draft_on_clean_output(tmp_memory, real_registry, fake_provider):
    """No finding_draft when tool output has no flag pattern."""
    provider = fake_provider(scripts=[
        [
            {"type": "tool_call", "id": "t1", "name": "shell", "arguments": {"command": "ls"}},
        ],
    ])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )
    agent.registry.register("shell", lambda command: {
        "stdout": "file1.txt\nfile2.txt",
        "exit_code": 0, "status": "success",
    }, dangerous=True)

    events = [event async for event in agent.chat("list files")]
    drafts = _events_of_type(events, "finding_draft")
    assert drafts == []


@pytest.mark.anyio
async def test_chat_runs_independent_tool_calls_concurrently(tmp_memory, real_registry, fake_provider):
    """Two independent tool calls in one step overlap (finish in ~max latency,
    not the sum) while their events stay in input order."""
    import asyncio
    import time

    async def slow(**kwargs):
        await asyncio.sleep(0.2)
        return {"status": "success", "args": kwargs}

    real_registry.register("slow_a", slow)
    real_registry.register("slow_b", slow)

    provider = fake_provider(scripts=[
        [
            {"type": "tool_call", "id": "a", "name": "slow_a", "arguments": {"x": 1}},
            {"type": "tool_call", "id": "b", "name": "slow_b", "arguments": {"x": 2}},
        ],
        [{"type": "token", "content": "done"}],
    ])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )

    start = time.monotonic()
    events = [event async for event in agent.chat("go")]
    elapsed = time.monotonic() - start

    # Overlapping two 0.2s tools finishes well under the 0.4s sequential sum.
    assert elapsed < 0.35
    results = _events_of_type(events, "tool_result")
    assert [r["tool"] for r in results] == ["slow_a", "slow_b"]  # input order preserved
    steps = _events_of_type(events, "step")
    assert [s["count"] for s in steps] == [1, 2]
    assert [s["tool"] for s in steps] == ["slow_a", "slow_b"]
    assert events[-1] == {"type": "done", "steps": 2}


@pytest.mark.anyio
async def test_chat_batch_with_stateful_tool_persists_all_findings(tmp_memory, real_registry, fake_provider):
    """A step whose batch contains a stateful tool (save_finding) falls back to
    sequential execution; every finding is still persisted and reported."""
    def _finding(title):
        return {"finding": {
            "title": title, "severity": "high", "vuln_type": "SQL Injection",
            "description": "d", "reproduction_steps": "r", "technique_used": "sqlmap",
            "target": "https://example.com", "engagement_id": "eng-1",
        }}

    provider = fake_provider(scripts=[
        [
            {"type": "tool_call", "id": "t1", "name": "save_finding", "arguments": _finding("SQLi A")},
            {"type": "tool_call", "id": "t2", "name": "save_finding", "arguments": _finding("SQLi B")},
        ],
        [{"type": "token", "content": "done"}],
    ])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )

    events = [event async for event in agent.chat("save both")]

    assert len(_events_of_type(events, "finding_saved")) == 2
    titles = {f["metadata"]["title"] for f in tmp_memory.load_engagement_findings("eng-1")}
    assert titles == {"SQLi A", "SQLi B"}


def test_compact_summarizes_and_resets_messages(tmp_memory, real_registry, fake_provider):
    agent = PentestAgent(
        engagement_id="eng-1", target="http://target",
        memory=tmp_memory, registry=real_registry, provider=fake_provider(scripts=[]),
    )
    agent.messages = [
        {"role": "user", "content": "find sqli"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "name": "nmap_scan", "arguments": {}}]},
        {"role": "tool", "tool_call_id": "1", "name": "nmap_scan", "content": "open ports"},
        {"role": "assistant", "content": "Found an open port."},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "2", "name": "save_finding", "arguments": {}}]},
        {"role": "tool", "tool_call_id": "2", "name": "save_finding", "content": "{'status': 'saved'}"},
    ]
    recap = agent.compact()

    assert "nmap_scan×1" in recap
    assert "find sqli" in recap
    assert "Findings saved this session: 1" in recap
    assert "http://target" in recap
    # History collapses to a single well-formed user message = the recap.
    assert len(agent.messages) == 1
    assert agent.messages[0] == {"role": "user", "content": recap}


@pytest.mark.anyio
async def test_chat_stopped_before_stream_ends_turn_without_tools(tmp_memory, real_registry, fake_provider):
    from core.control import AgentControl

    provider = fake_provider(scripts=[[{"type": "token", "content": "should not stream"}]])
    agent = PentestAgent(
        engagement_id="eng-1", target="https://example.com",
        memory=tmp_memory, registry=real_registry, provider=provider,
    )
    control = AgentControl(phase="collaboration")
    control.stopped = True  # an interrupt landed before/at the turn start

    events = [event async for event in agent.chat("hi", control)]
    types = [e["type"] for e in events]
    assert "stopped" in types
    assert "token" not in types  # generation was preempted
    assert events[-1]["type"] == "done"
