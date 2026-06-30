"""Tests for memory/embeddings.py with the heavy SentenceTransformer mocked
out (we don't want to download/load a real model in unit tests)."""
from memory import embeddings
from memory.embeddings import LocalEmbeddingFunction, embed_texts


class _FakeEncoding:
    def tolist(self):
        return [[0.1, 0.2, 0.3]]


class _FakeModel:
    def __init__(self):
        self.seen = None

    def encode(self, texts):
        self.seen = texts
        return _FakeEncoding()


def test_local_embedding_function_name():
    assert LocalEmbeddingFunction().name() == "local-sentence-transformers"


def test_local_embedding_function_returns_vectors(monkeypatch):
    monkeypatch.setattr(embeddings, "_get_model", lambda: _FakeModel())
    out = LocalEmbeddingFunction()(["hello"])
    assert out == [[0.1, 0.2, 0.3]]


def test_embed_texts_delegates_to_model(monkeypatch):
    monkeypatch.setattr(embeddings, "_get_model", lambda: _FakeModel())
    assert embed_texts(["a", "b"]) == [[0.1, 0.2, 0.3]]
