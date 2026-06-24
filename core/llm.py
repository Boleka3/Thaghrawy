"""Multi-provider LLM abstraction with streaming + tool use.

Every provider implements `stream()`, which yields a normalized event
stream regardless of how the underlying API actually streams:
    {"type": "token", "content": "..."}
    {"type": "tool_call", "id": "...", "name": "...", "arguments": {...}}

core/agent.py drives the ReAct loop entirely against this interface, so
adding a new provider never touches the agent loop.

Message format expected by `stream()` (provider-agnostic):
    {"role": "user", "content": "..."}
    {"role": "assistant", "content": "..." | None, "tool_calls": [{"id","name","arguments"}]}
    {"role": "tool", "tool_call_id": "...", "name": "...", "content": "..."}
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, AsyncIterator, Optional

import config


@dataclass
class ToolSchema:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema for the tool's arguments


class BaseLLMProvider(ABC):
    @abstractmethod
    def stream(
        self,
        messages: list[dict[str, Any]],
        system: str,
        tools: Optional[list[ToolSchema]] = None,
    ) -> AsyncIterator[dict[str, Any]]:
        ...


class AnthropicProvider(BaseLLMProvider):
    def __init__(self, api_key: str, model: str):
        from anthropic import AsyncAnthropic

        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model

    @staticmethod
    def _tools(tools: Optional[list[ToolSchema]]):
        if not tools:
            return None
        return [{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools]

    @staticmethod
    def _messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted = []
        for m in messages:
            role = m["role"]
            if role == "user":
                converted.append({"role": "user", "content": m["content"]})
            elif role == "assistant":
                content: list[dict[str, Any]] = []
                if m.get("content"):
                    content.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    content.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]})
                converted.append({"role": "assistant", "content": content})
            elif role == "tool":
                converted.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m["tool_call_id"],
                        "content": m["content"],
                    }],
                })
        return converted

    async def stream(self, messages, system, tools=None):
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": config.MAX_TOKENS,
            "temperature": config.TEMPERATURE,
            "system": system,
            "messages": self._messages(messages),
        }
        anthropic_tools = self._tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        async with self.client.messages.stream(**kwargs) as stream:
            current_tool: Optional[dict[str, Any]] = None
            tool_json = ""
            async for event in stream:
                if event.type == "content_block_start" and event.content_block.type == "tool_use":
                    current_tool = {"id": event.content_block.id, "name": event.content_block.name}
                    tool_json = ""
                elif event.type == "content_block_delta":
                    if event.delta.type == "text_delta":
                        yield {"type": "token", "content": event.delta.text}
                    elif event.delta.type == "input_json_delta":
                        tool_json += event.delta.partial_json
                elif event.type == "content_block_stop" and current_tool is not None:
                    try:
                        arguments = json.loads(tool_json) if tool_json else {}
                    except json.JSONDecodeError:
                        arguments = {}
                    yield {
                        "type": "tool_call",
                        "id": current_tool["id"],
                        "name": current_tool["name"],
                        "arguments": arguments,
                    }
                    current_tool = None


def _openai_style_tools(tools: Optional[list[ToolSchema]]):
    """Shared by OpenAIProvider and OllamaProvider - both speak the OpenAI tools schema."""
    if not tools:
        return None
    return [
        {
            "type": "function",
            "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
        }
        for t in tools
    ]


class OpenAIProvider(BaseLLMProvider):
    """Also used for any OpenAI-compatible endpoint (e.g. LM Studio) via base_url."""

    def __init__(self, api_key: str, model: str, base_url: Optional[str] = None):
        from openai import AsyncOpenAI

        self.client = AsyncOpenAI(api_key=api_key or "not-needed", base_url=base_url)
        self.model = model

    _tools = staticmethod(_openai_style_tools)

    @staticmethod
    def _messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted = []
        for m in messages:
            role = m["role"]
            if role == "assistant" and m.get("tool_calls"):
                tool_calls = [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])},
                    }
                    for tc in m["tool_calls"]
                ]
                converted.append({
                    "role": "assistant",
                    "content": m.get("content"),
                    "tool_calls": tool_calls,
                })
            elif role == "tool":
                converted.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                converted.append({"role": role, "content": m.get("content")})
        return converted

    async def stream(self, messages, system, tools=None):
        full_messages = [{"role": "system", "content": system}, *self._messages(messages)]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": full_messages,
            "max_tokens": config.MAX_TOKENS,
            "temperature": config.TEMPERATURE,
            "stream": True,
        }
        openai_tools = self._tools(tools)
        if openai_tools:
            kwargs["tools"] = openai_tools

        pending: dict[int, dict[str, Any]] = {}
        response = await self.client.chat.completions.create(**kwargs)
        async for chunk in response:
            choice = chunk.choices[0]
            delta = choice.delta
            if delta.content:
                yield {"type": "token", "content": delta.content}
            for tc in delta.tool_calls or []:
                entry = pending.setdefault(tc.index, {"id": None, "name": "", "arguments": ""})
                if tc.id:
                    entry["id"] = tc.id
                if tc.function and tc.function.name:
                    entry["name"] += tc.function.name
                if tc.function and tc.function.arguments:
                    entry["arguments"] += tc.function.arguments
            if choice.finish_reason == "tool_calls":
                for entry in pending.values():
                    try:
                        arguments = json.loads(entry["arguments"]) if entry["arguments"] else {}
                    except json.JSONDecodeError:
                        arguments = {}
                    yield {"type": "tool_call", "id": entry["id"], "name": entry["name"], "arguments": arguments}
                pending = {}


class OllamaProvider(BaseLLMProvider):
    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model

    _tools = staticmethod(_openai_style_tools)

    @staticmethod
    def _messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted = []
        for m in messages:
            role = m["role"]
            if role == "assistant" and m.get("tool_calls"):
                tool_calls = [
                    {"function": {"name": tc["name"], "arguments": tc["arguments"]}}
                    for tc in m["tool_calls"]
                ]
                converted.append({
                    "role": "assistant",
                    "content": m.get("content") or "",
                    "tool_calls": tool_calls,
                })
            elif role == "tool":
                converted.append({"role": "tool", "content": m["content"]})
            else:
                converted.append({"role": role, "content": m.get("content") or ""})
        return converted

    async def stream(self, messages, system, tools=None):
        import httpx

        full_messages = [{"role": "system", "content": system}, *self._messages(messages)]
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": full_messages,
            "stream": True,
            "options": {"temperature": config.TEMPERATURE},
        }
        ollama_tools = self._tools(tools)
        if ollama_tools:
            payload["tools"] = ollama_tools

        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream("POST", f"{self.base_url}/api/chat", json=payload) as response:
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    chunk = json.loads(line)
                    message = chunk.get("message", {})
                    if message.get("content"):
                        yield {"type": "token", "content": message["content"]}
                    for tc in message.get("tool_calls") or []:
                        fn = tc.get("function", {})
                        arguments = fn.get("arguments", {})
                        if isinstance(arguments, str):
                            try:
                                arguments = json.loads(arguments)
                            except json.JSONDecodeError:
                                arguments = {}
                        yield {
                            "type": "tool_call",
                            "id": f"{fn.get('name', 'tool')}_{id(tc)}",
                            "name": fn.get("name", ""),
                            "arguments": arguments,
                        }


def get_provider() -> BaseLLMProvider:
    provider = config.LLM_PROVIDER
    if provider == "anthropic":
        return AnthropicProvider(api_key=config.ANTHROPIC_API_KEY, model=config.ANTHROPIC_MODEL)
    if provider == "openai":
        return OpenAIProvider(api_key=config.OPENAI_API_KEY, model=config.OPENAI_MODEL, base_url=config.OPENAI_BASE_URL)
    if provider == "ollama":
        return OllamaProvider(base_url=config.OLLAMA_BASE_URL, model=config.OLLAMA_MODEL)
    raise ValueError(f"Unknown LLM_PROVIDER: {provider!r} (expected anthropic, openai, or ollama)")
