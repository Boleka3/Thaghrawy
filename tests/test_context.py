from core.context import ContextManager


def _msg(content: str) -> dict:
    return {"role": "user", "content": content}


def test_trim_returns_unchanged_when_under_budget():
    manager = ContextManager(max_chars=1000)
    messages = [_msg("short"), _msg("also short")]
    assert manager.trim(messages) == messages


def test_trim_returns_unchanged_when_exactly_at_budget():
    manager = ContextManager(max_chars=10)
    messages = [_msg("1234567890")]
    assert manager.trim(messages) == messages


def test_trim_drops_oldest_messages_until_under_budget():
    manager = ContextManager(max_chars=10)
    messages = [_msg("aaaaa"), _msg("bbbbb"), _msg("ccccc")]
    trimmed = manager.trim(messages)
    assert trimmed == [_msg("bbbbb"), _msg("ccccc")]


def test_trim_always_keeps_at_least_one_message_even_if_over_budget():
    manager = ContextManager(max_chars=3)
    messages = [_msg("aaaaa"), _msg("this one alone is already over budget")]
    trimmed = manager.trim(messages)
    assert len(trimmed) == 1
    assert trimmed[0]["content"] == "this one alone is already over budget"


def test_trim_drops_leading_orphan_tool_message():
    # After front-trimming, the window must not start on an orphaned tool result
    # (its assistant tool-call turn is gone) — that breaks weak model templates.
    manager = ContextManager(max_chars=10_000)
    messages = [
        {"role": "tool", "tool_call_id": "1", "name": "x", "content": "orphan result"},
        {"role": "user", "content": "hello"},
    ]
    trimmed = manager.trim(messages)
    assert trimmed[0]["role"] == "user"


def test_trim_drops_leading_assistant_with_tool_calls():
    manager = ContextManager(max_chars=10_000)
    messages = [
        {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "name": "x", "arguments": {}}]},
        {"role": "tool", "tool_call_id": "1", "name": "x", "content": "r"},
        {"role": "user", "content": "hi"},
    ]
    trimmed = manager.trim(messages)
    assert trimmed[0]["role"] == "user"


def test_trim_keeps_last_message_even_if_it_is_an_orphan():
    # Never strip below one message, even if that message is itself an orphan.
    manager = ContextManager(max_chars=10_000)
    messages = [{"role": "tool", "tool_call_id": "1", "name": "x", "content": "only"}]
    assert manager.trim(messages) == messages


def test_summarize_tool_output_unchanged_under_limit():
    output = "short tool output"
    assert ContextManager.summarize_tool_output(output, max_chars=1500) == output


def test_summarize_tool_output_truncates_head_and_tail_over_limit():
    output = "X" * 4000
    result = ContextManager.summarize_tool_output(output, max_chars=200)
    assert "[...TRUNCATED...]" in result
    assert result.startswith("X" * 100)
    assert result.endswith("X" * 100)
    assert len(result) < len(output)


def test_summarize_tool_output_exactly_at_limit_unchanged():
    output = "Y" * 50
    assert ContextManager.summarize_tool_output(output, max_chars=50) == output
