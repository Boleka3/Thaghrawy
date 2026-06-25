"""ChromaDB interface - the only module that should ever touch ChromaDB
directly. Two collections: `findings` and `techniques`, both embedded with
the local sentence-transformers model (memory/embeddings.py)."""
from __future__ import annotations

from typing import Any, Optional

import chromadb
from chromadb.config import Settings

import config
from memory.embeddings import LocalEmbeddingFunction
from memory.schemas import Finding, Technique


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
        metadata = {
            "title": finding.title,
            "severity": finding.severity,
            "vuln_type": finding.vuln_type,
            "description": finding.description,
            "reproduction_steps": finding.reproduction_steps,
            "technique_used": finding.technique_used,
            "target": finding.target,
            "engagement_id": finding.engagement_id,
            "date": finding.date,
            "tags": ",".join(finding.tags),
        }
        for optional_field in (
            "cvss_score", "dread_score", "affected_component", "business_impact", "remediation",
        ):
            value = getattr(finding, optional_field)
            if value is not None:
                metadata[optional_field] = value
        self.findings.upsert(ids=[finding.id], documents=[document], metadatas=[metadata])

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
            tags = fields.get("tags") or ""
            fields["tags"] = tags.split(",") if tags else []
            findings.append(Finding(**fields))
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
