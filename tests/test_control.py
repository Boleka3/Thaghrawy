import pytest

from core.agent import PentestAgent
from core.control import AgentControl


def _types(events):
    return [e["type"] for e in events]


def _of_type(events, t):
    return [e for e in events if e["type"] == t]


# ── AgentControl.needs_approval policy ──


def test_no_approval_outside_collaboration_phase():
    c = AgentControl(phase="enumeration", approval_mode="all")
    assert c.needs_approval(dangerous=True) is False
    assert c.needs_approval(dangerous=False) is False


def test_mode_all_gates_every_tool_in_collaboration():
    c = AgentControl(phase="collaboration", approval_mode="all")
    assert c.needs_approval(dangerous=False) is True
    assert c.needs_approval(dangerous=True) is True


def test_mode_dangerous_gates_only_dangerous():
    c = AgentControl(phase="collaboration", approval_mode="dangerous")
    assert c.needs_approval(dangerous=False) is False
    assert c.needs_approval(dangerous=True) is True


def test_mode_off_never_gates():
    c = AgentControl(phase="collaboration", approval_mode="off")
    assert c.needs_approval(dangerous=True) is False


def test_auto_approve_all_disables_gate():
    c = AgentControl(phase="collaboration", approval_mode="all")
    c.auto_approve = "all"
    assert c.needs_approval(dangerous=True) is False


def test_auto_approve_safe_only_lets_safe_through():
    c = AgentControl(phase="collaboration", approval_mode="all")
    c.auto_approve = "safe"
    assert c.needs_approval(dangerous=False) is False
    assert c.needs_approval(dangerous=True) is True


def test_begin_turn_clears_stop_and_drains():
    c = AgentControl(phase="collaboration")
    c.request_stop()
    c.push({"type": "approve"})
    c.begin_turn()
    assert c.stopped is False
    assert c._queue.empty()


# ── approval gate in the agent loop ──


def _collab_control(mode="all"):
    return AgentControl(phase="collaboration", approval_mode=mode)


@pytest.mark.anyio
async def test_approve_runs_the_tool(tmp_memory, real_registry, fake_provider):
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "x"}}],
        [{"type": "token", "content": "done"}],
    ])
    control = _collab_control()
    control.push({"type": "approve"})
    agent = PentestAgent(
        engagement_id="eng-1", target="x", memory=tmp_memory,
        registry=real_registry, provider=provider, control=control,
    )
    events = [e async for e in agent.chat("go")]
    assert "tool_call_pending" in _types(events)
    assert "tool_result" in _types(events)
    assert events[-1] == {"type": "done", "steps": 1}


@pytest.mark.anyio
async def test_reject_skips_tool_and_feeds_rejection(tmp_memory, real_registry, fake_provider):
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "x"}}],
        [{"type": "token", "content": "ok"}],
    ])
    control = _collab_control()
    control.push({"type": "reject"})
    agent = PentestAgent(
        engagement_id="eng-1", target="x", memory=tmp_memory,
        registry=real_registry, provider=provider, control=control,
    )
    events = [e async for e in agent.chat("go")]
    assert "tool_rejected" in _types(events)
    assert "tool_result" not in _types(events)
    assert events[-1] == {"type": "done", "steps": 0}
    # the model was told the call was rejected
    tool_msgs = [m for m in agent.messages if m.get("role") == "tool"]
    assert any("rejected by human" in m["content"] for m in tool_msgs)


@pytest.mark.anyio
async def test_edit_runs_tool_with_replacement_args(tmp_memory, real_registry, fake_provider):
    real_registry.register("echo", lambda **kw: kw)
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "echo", "arguments": {"x": 1}}],
        [{"type": "token", "content": "done"}],
    ])
    control = _collab_control()
    control.push({"type": "edit", "arguments": {"x": 2}})
    agent = PentestAgent(
        engagement_id="eng-1", target="x", memory=tmp_memory,
        registry=real_registry, provider=provider, control=control,
    )
    events = [e async for e in agent.chat("go")]
    assert "tool_edited" in _types(events)
    result = _of_type(events, "tool_result")[0]
    assert result["output"] == {"x": 2}


@pytest.mark.anyio
async def test_stop_halts_the_turn(tmp_memory, real_registry, fake_provider):
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "x"}}],
    ])
    control = _collab_control()
    control.push({"type": "stop"})
    agent = PentestAgent(
        engagement_id="eng-1", target="x", memory=tmp_memory,
        registry=real_registry, provider=provider, control=control,
    )
    events = [e async for e in agent.chat("go")]
    assert "stopped" in _types(events)
    assert "tool_result" not in _types(events)
    assert events[-1] == {"type": "done", "steps": 0}


@pytest.mark.anyio
async def test_enumeration_phase_runs_without_approval(tmp_memory, real_registry, fake_provider):
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "x"}}],
        [{"type": "token", "content": "done"}],
    ])
    control = AgentControl(phase="enumeration")  # no approvals; nothing pushed
    agent = PentestAgent(
        engagement_id="eng-1", target="x", memory=tmp_memory,
        registry=real_registry, provider=provider, control=control,
    )
    events = [e async for e in agent.chat("go")]
    assert "tool_call_pending" not in _types(events)
    assert "tool_result" in _types(events)


@pytest.mark.anyio
async def test_no_control_is_fully_autonomous(tmp_memory, real_registry, fake_provider):
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "x"}}],
        [{"type": "token", "content": "done"}],
    ])
    agent = PentestAgent(
        engagement_id="eng-1", target="x", memory=tmp_memory,
        registry=real_registry, provider=provider,  # control=None
    )
    events = [e async for e in agent.chat("go")]
    assert "tool_call_pending" not in _types(events)
    assert "tool_result" in _types(events)


@pytest.mark.anyio
async def test_on_decision_sink_captures_verdicts(tmp_memory, real_registry, fake_provider):
    records = []
    provider = fake_provider(scripts=[
        [{"type": "tool_call", "id": "t1", "name": "search_memory", "arguments": {"query": "x"}}],
        [{"type": "token", "content": "done"}],
    ])
    control = _collab_control()
    control.push({"type": "approve"})
    agent = PentestAgent(
        engagement_id="eng-1", target="x", memory=tmp_memory,
        registry=real_registry, provider=provider, control=control,
        on_decision=records.append,
    )
    await _drain(agent.chat("go"))
    assert len(records) == 1
    assert records[0]["verdict"] == "approve"
    assert records[0]["rejected"] is False
    assert records[0]["tool"] == "search_memory"


async def _drain(stream):
    return [e async for e in stream]


# ── autonomous enumeration + handoff ──


@pytest.mark.anyio
async def test_enumerate_auto_ingests_and_hands_off(tmp_memory, real_registry, fake_provider, tmp_path):
    from engagements.manager import EngagementManager

    manager = EngagementManager(base_dir=str(tmp_path))
    eng = manager.create(name="e", target="http://t")

    # Stub nuclei to return structured findings without touching the real binary.
    real_registry.register(
        "nuclei_scan",
        lambda target=None: {
            "status": "success",
            "findings": [
                {"template": "missing-csp-header", "severity": "low", "matched": "http://t/"},
                {"template": "CVE-2021-1", "severity": "high", "matched": "http://t/x"},
            ],
        },
    )
    control = AgentControl(phase="enumeration")
    agent = PentestAgent(
        engagement_id=eng.id, target="http://t", memory=tmp_memory,
        registry=real_registry, provider=fake_provider(scripts=[]),
        engagement_manager=manager, control=control,
    )

    events = [e async for e in agent.enumerate()]
    types = _types(events)

    assert types.count("finding_saved") == 2
    assert "handoff" in types
    handoff = _of_type(events, "handoff")[0]
    assert handoff["findings_saved"] == 2
    # phase flipped to collaboration (in-memory + persisted)
    assert control.phase == "collaboration"
    assert manager.get(eng.id).phase == "collaboration"
    # findings really persisted
    assert len(tmp_memory.load_engagement_findings(eng.id)) == 2
