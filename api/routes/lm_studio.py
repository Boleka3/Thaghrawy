"""Proxy endpoint that checks whether the configured LM Studio model is loaded."""
from __future__ import annotations

import httpx
from fastapi import APIRouter

import config

router = APIRouter()


@router.get("/api/lm-studio/status")
async def lm_studio_status() -> dict:
    if config.LLM_PROVIDER != "openai" or not config.OPENAI_BASE_URL:
        return {"provider": config.LLM_PROVIDER, "lm_studio": False, "model": None}

    base = config.OPENAI_BASE_URL.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{base}/models")
        models = [m["id"] for m in r.json().get("data", [])]
        loaded = config.OPENAI_MODEL in models
        return {
            "provider": "lm_studio",
            "lm_studio": True,
            "model": config.OPENAI_MODEL,
            "loaded": loaded,
            "available_models": models,
        }
    except Exception as e:
        return {
            "provider": "lm_studio",
            "lm_studio": True,
            "model": config.OPENAI_MODEL,
            "loaded": False,
            "error": str(e),
        }
