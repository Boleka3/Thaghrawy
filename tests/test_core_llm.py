from types import SimpleNamespace

import pytest

import config
from core.llm import AnthropicProvider, OllamaProvider, OpenAIProvider, ToolSchema, get_provider


# ── ToolSchema ──


def test_tool_schema_holds_fields():
    schema = ToolSchema(name="nmap_scan", description="scan", parameters={"type": "object"})
    assert schema.name == "nmap_scan"
    assert schema.parameters == {"type": "object"}


# ── AnthropicProvider message/tool conversion ──


def test_anthropic_tools_returns_none_when_empty():
    assert AnthropicProvider._tools(None) is None
    assert AnthropicProvider._tools([]) is None


def test_anthropic_tools_converts_to_input_schema_shape():
    tools = [ToolSchema(name="nmap_scan", description="scan", parameters={"type": "object"})]
    converted = AnthropicProvider._tools(tools)
    assert converted == [{"name": "nmap_scan", "description": "scan", "input_schema": {"type": "object"}}]


def test_anthropic_messages_user_role():
    converted = AnthropicProvider._messages([{"role": "user", "content": "hello"}])
    assert converted == [{"role": "user", "content": "hello"}]


def test_anthropic_messages_assistant_with_tool_calls():
    messages = [{
        "role": "assistant",
        "content": "thinking...",
        "tool_calls": [{"id": "t1", "name": "nmap_scan", "arguments": {"target": "x"}}],
    }]
    converted = AnthropicProvider._messages(messages)
    assert converted == [{
        "role": "assistant",
        "content": [
            {"type": "text", "text": "thinking..."},
            {"type": "tool_use", "id": "t1", "name": "nmap_scan", "input": {"target": "x"}},
        ],
    }]


def test_anthropic_messages_assistant_without_content_omits_text_block():
    messages = [{"role": "assistant", "content": None, "tool_calls": [{"id": "t1", "name": "x", "arguments": {}}]}]
    converted = AnthropicProvider._messages(messages)
    assert converted[0]["content"] == [{"type": "tool_use", "id": "t1", "name": "x", "input": {}}]


def test_anthropic_messages_tool_role():
    messages = [{"role": "tool", "tool_call_id": "t1", "name": "nmap_scan", "content": "result text"}]
    converted = AnthropicProvider._messages(messages)
    assert converted == [{
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "result text"}],
    }]


# ── OpenAI / Ollama message/tool conversion (shared _openai_style_tools) ──


def test_openai_style_tools_returns_none_when_empty():
    assert OpenAIProvider._tools(None) is None


def test_openai_style_tools_converts_to_function_shape():
    tools = [ToolSchema(name="nmap_scan", description="scan", parameters={"type": "object"})]
    converted = OpenAIProvider._tools(tools)
    assert converted == [{
        "type": "function",
        "function": {"name": "nmap_scan", "description": "scan", "parameters": {"type": "object"}},
    }]


def test_openai_messages_assistant_with_tool_calls_serializes_arguments():
    messages = [{
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": "t1", "name": "nmap_scan", "arguments": {"target": "x"}}],
    }]
    converted = OpenAIProvider._messages(messages)
    assert converted[0]["tool_calls"][0]["function"]["arguments"] == '{"target": "x"}'


def test_openai_messages_tool_role():
    messages = [{"role": "tool", "tool_call_id": "t1", "content": "result"}]
    converted = OpenAIProvider._messages(messages)
    assert converted == [{"role": "tool", "tool_call_id": "t1", "content": "result"}]


def test_openai_messages_user_role_passthrough():
    converted = OpenAIProvider._messages([{"role": "user", "content": "hi"}])
    assert converted == [{"role": "user", "content": "hi"}]


def test_ollama_messages_assistant_with_tool_calls_keeps_dict_arguments():
    messages = [{
        "role": "assistant",
        "content": "",
        "tool_calls": [{"id": "t1", "name": "nmap_scan", "arguments": {"target": "x"}}],
    }]
    converted = OllamaProvider._messages(messages)
    assert converted[0]["tool_calls"] == [{"function": {"name": "nmap_scan", "arguments": {"target": "x"}}}]


def test_ollama_messages_tool_role():
    converted = OllamaProvider._messages([{"role": "tool", "content": "result"}])
    assert converted == [{"role": "tool", "content": "result"}]


# ── get_provider dispatch ──


def test_get_provider_anthropic(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "anthropic")
    provider = get_provider()
    assert isinstance(provider, AnthropicProvider)


def test_get_provider_openai(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "openai")
    provider = get_provider()
    assert isinstance(provider, OpenAIProvider)


def test_get_provider_ollama(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "ollama")
    provider = get_provider()
    assert isinstance(provider, OllamaProvider)


def test_get_provider_unknown_raises(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "bogus")
    with pytest.raises(ValueError, match="Unknown LLM_PROVIDER"):
        get_provider()


# ── AnthropicProvider.stream() event normalization ──


class _FakeAnthropicStreamContext:
    """Mimics `async with client.messages.stream(**kwargs) as stream:` -
    `.stream()` returns this directly (not a coroutine); it's an async
    context manager whose __aenter__ result is itself async-iterable."""

    def __init__(self, events):
        self._events = events

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        for event in self._events:
            yield event


@pytest.mark.anyio
async def test_anthropic_stream_normalizes_text_and_tool_call_events():
    events = [
        SimpleNamespace(type="content_block_delta", delta=SimpleNamespace(type="text_delta", text="Hello ")),
        SimpleNamespace(type="content_block_stop"),
        SimpleNamespace(
            type="content_block_start",
            content_block=SimpleNamespace(type="tool_use", id="tu1", name="save_finding"),
        ),
        SimpleNamespace(
            type="content_block_delta",
            delta=SimpleNamespace(type="input_json_delta", partial_json='{"title": "X"}'),
        ),
        SimpleNamespace(type="content_block_stop"),
    ]

    provider = AnthropicProvider(api_key="test-key", model="claude-test")
    provider.client.messages.stream = lambda **kwargs: _FakeAnthropicStreamContext(events)

    received = [event async for event in provider.stream(messages=[], system="sys")]
    assert received == [
        {"type": "token", "content": "Hello "},
        {"type": "tool_call", "id": "tu1", "name": "save_finding", "arguments": {"title": "X"}},
    ]


@pytest.mark.anyio
async def test_anthropic_stream_handles_malformed_tool_json_gracefully():
    events = [
        SimpleNamespace(
            type="content_block_start",
            content_block=SimpleNamespace(type="tool_use", id="tu1", name="save_finding"),
        ),
        SimpleNamespace(
            type="content_block_delta",
            delta=SimpleNamespace(type="input_json_delta", partial_json="not valid json"),
        ),
        SimpleNamespace(type="content_block_stop"),
    ]

    provider = AnthropicProvider(api_key="test-key", model="claude-test")
    provider.client.messages.stream = lambda **kwargs: _FakeAnthropicStreamContext(events)

    received = [event async for event in provider.stream(messages=[], system="sys")]
    assert received == [{"type": "tool_call", "id": "tu1", "name": "save_finding", "arguments": {}}]
