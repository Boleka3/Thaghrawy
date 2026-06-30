"""Tests for api/deps._get_or_create_agent - the per-engagement agent cache."""
from types import SimpleNamespace

from api.deps import _get_or_create_agent


def _state(tmp_memory, tmp_engagements):
    return SimpleNamespace(memory=tmp_memory, engagements=tmp_engagements, agents={})


def test_get_or_create_agent_caches_per_engagement(tmp_memory, tmp_engagements):
    engagement = tmp_engagements.create(name="X", target="https://x.com")
    state = _state(tmp_memory, tmp_engagements)

    first = _get_or_create_agent(state, engagement.id)
    second = _get_or_create_agent(state, engagement.id)

    assert first is second
    assert first.target == "https://x.com"
    assert engagement.id in state.agents


def test_get_or_create_agent_unknown_engagement_uses_empty_target(tmp_memory, tmp_engagements):
    state = _state(tmp_memory, tmp_engagements)
    agent = _get_or_create_agent(state, "missing-id")
    assert agent.target == ""


def test_recon_only_engagement_excludes_exploit_tools(tmp_memory, tmp_engagements):
    engagement = tmp_engagements.create(
        name="ReconOnly", target="https://x.com", analysis_mode="recon_only"
    )
    state = _state(tmp_memory, tmp_engagements)
    agent = _get_or_create_agent(state, engagement.id)
    assert "sqlmap_scan" not in agent.registry.names()
    assert "nmap_scan" in agent.registry.names()
