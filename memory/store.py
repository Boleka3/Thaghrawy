"""ChromaDB interface - the only module that should ever touch ChromaDB
directly. Two collections: `findings` and `techniques`, both embedded with
the local sentence-transformers model (memory/embeddings.py)."""
from __future__ import annotations

import json
from typing import Any, Optional

import chromadb
from chromadb.config import Settings

import config
from memory.embeddings import LocalEmbeddingFunction
from memory.schemas import Finding, Technique


def _encode_list(values: list[str]) -> str:
    """JSON-encode a list for Chroma metadata (which only stores scalars), so a
    value containing a comma can't corrupt the round-trip the way ",".join did."""
    return json.dumps(values)


def _decode_list(raw: Any) -> list[str]:
    """Inverse of _encode_list, tolerant of the legacy comma-joined format."""
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        decoded = json.loads(raw)
        return decoded if isinstance(decoded, list) else [str(decoded)]
    except (ValueError, TypeError):
        return [part for part in str(raw).split(",") if part]


def _finding_to_metadata(finding: Finding) -> dict[str, Any]:
    """Derive Chroma metadata from the full Finding via model_dump, so adding a
    schema field can't silently break the stored<->reconstructed round-trip.
    Lists are JSON-encoded; None-valued optionals are omitted (Chroma rejects
    None); `id` is the Chroma document id, not metadata."""
    metadata: dict[str, Any] = {}
    for key, value in finding.model_dump().items():
        if key == "id" or value is None:
            continue
        metadata[key] = _encode_list(value) if isinstance(value, list) else value
    return metadata


class MemoryStore:
    def __init__(self, persist_dir: Optional[str] = None):
        self.client = chromadb.PersistentClient(
            path=persist_dir or config.CHROMA_PERSIST_DIR,
            settings=Settings(anonymized_telemetry=False),
        )
        embedding_fn = LocalEmbeddingFunction()
        self.findings = self.client.get_or_create_collection(
            name="findings", embedding_function=embedding_fn
        )
        self.techniques = self.client.get_or_create_collection(
            name="techniques", embedding_function=embedding_fn
        )

    # ── findings ──────────────────────────────────────────────
    def add_finding(self, finding: Finding) -> None:
        document = f"{finding.title}\n{finding.description}\n{finding.reproduction_steps}"
        self.findings.upsert(
            ids=[finding.id],
            documents=[document],
            metadatas=[_finding_to_metadata(finding)],
        )

    def search_findings(self, query: str, top_k: int = 3, engagement_id: Optional[str] = None) -> list[dict[str, Any]]:
        where = {"engagement_id": engagement_id} if engagement_id else None
        results = self.findings.query(query_texts=[query], n_results=top_k, where=where)
        return _format_query_results(results)

    def load_engagement_findings(self, engagement_id: str) -> list[dict[str, Any]]:
        results = self.findings.get(where={"engagement_id": engagement_id})
        return _format_get_results(results)

    def load_engagement_findings_as_models(self, engagement_id: str) -> list[Finding]:
        """Reconstruct full Finding objects (for report generation) from the
        metadata stored by add_finding - the metadata now mirrors every Finding
        field, so this is a straight rehydration rather than a guess."""
        findings = []
        for item in self.load_engagement_findings(engagement_id):
            fields = dict(item["metadata"])
            fields["id"] = item["id"]
            fields["tags"] = _decode_list(fields.get("tags"))
            try:
                findings.append(Finding(**fields))
            except ValueError as exc:
                raise ValueError(
                    f"Corrupt finding {item['id']} in engagement {engagement_id}: {exc}"
                ) from exc
        return findings

    # ── techniques ────────────────────────────────────────────
    def add_technique(self, technique: Technique) -> None:
        document = f"{technique.name}\n{technique.description}"
        self.techniques.upsert(
            ids=[technique.id],
            documents=[document],
            metadatas=[{
                "name": technique.name,
                "works_against": ",".join(technique.works_against),
                "platform": technique.platform,
                "engagement_id": technique.engagement_id,
                "date": technique.date,
                "tags": ",".join(technique.tags),
            }],
        )

    def search_techniques(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        results = self.techniques.query(query_texts=[query], n_results=top_k)
        return _format_query_results(results)

    # ── combined (used for prompt injection + memory_hit events) ────
    def search_context(
        self, query: str, engagement_id: Optional[str] = None, top_k: int = 3
    ) -> dict[str, list[dict[str, Any]]]:
        return {
            "findings": self.search_findings(query, top_k=top_k, engagement_id=engagement_id),
            "techniques": self.search_techniques(query, top_k=top_k),
        }

    def stats(self) -> dict[str, int]:
        return {"findings_count": self.findings.count(), "techniques_count": self.techniques.count()}


def _format_query_results(results: dict[str, Any]) -> list[dict[str, Any]]:
    formatted = []
    ids = results.get("ids", [[]])[0]
    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]
    for i, doc_id in enumerate(ids):
        distance = distances[i] if i < len(distances) else None
        similarity = (1 - distance) if distance is not None else None
        formatted.append({
            "id": doc_id,
            "document": documents[i] if i < len(documents) else "",
            "metadata": metadatas[i] if i < len(metadatas) else {},
            "similarity": similarity,
        })
    return formatted


def _format_get_results(results: dict[str, Any]) -> list[dict[str, Any]]:
    formatted = []
    ids = results.get("ids", [])
    documents = results.get("documents", [])
    metadatas = results.get("metadatas", [])
    for i, doc_id in enumerate(ids):
        formatted.append({
            "id": doc_id,
            "document": documents[i] if i < len(documents) else "",
            "metadata": metadatas[i] if i < len(metadatas) else {},
        })
    return formatted
