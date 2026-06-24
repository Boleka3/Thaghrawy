"""Local sentence-transformers embedding model wrapper.

Set EMBEDDING_MODEL_PATH in .env to the local snapshot directory (already
downloaded - see .env.example) to avoid re-downloading the model. If unset,
sentence-transformers falls back to its normal HF Hub resolution/cache.
"""
from __future__ import annotations

from functools import lru_cache

import config


@lru_cache(maxsize=1)
def _get_model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(config.EMBEDDING_MODEL_PATH)


def embed_texts(texts: list[str]) -> list[list[float]]:
    model = _get_model()
    return model.encode(texts).tolist()


class LocalEmbeddingFunction:
    """ChromaDB-compatible embedding function: a callable taking a list of
    strings and returning a list of embedding vectors."""

    def __call__(self, input: list[str]) -> list[list[float]]:
        model = _get_model()
        return model.encode(list(input)).tolist()

    def name(self) -> str:
        return "local-sentence-transformers"
