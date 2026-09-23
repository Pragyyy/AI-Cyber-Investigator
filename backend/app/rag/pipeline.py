"""Ties chunking, embeddings and vector store together into build_index() / retrieve().

`retrieve_for_incident()` is the bridge to the rest of the app: it turns an incident's
detections and evidence into a query, retrieves relevant knowledge, and returns
candidate MITRE techniques - clearly labeled "candidate" and never "confirmed", per the
project brief's requirement not to present unsupported techniques as fact. Validating
these candidates against the evidence with an LLM is the Threat Intelligence agent's
job (Phase 5); this module only does retrieval.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .chunking import Chunk, load_and_chunk
from .config import RagConfig, rag_config
from .embeddings import get_embedder
from .store import get_store

_MANIFEST_NAME = "manifest.json"

CONFIDENCE_BANDS = (
    (0.55, "supported"),   # strong semantic match to the evidence text
    (0.35, "potential"),   # plausible but weaker match
    (0.0, "weak"),
)


def _confidence_label(score: float) -> str:
    for threshold, label in CONFIDENCE_BANDS:
        if score >= threshold:
            return label
    return "weak"


def _manifest_path(cfg: RagConfig) -> Path:
    return cfg.persist_path() / _MANIFEST_NAME


def get_status(cfg: RagConfig = rag_config) -> dict:
    path = _manifest_path(cfg)
    if not path.exists():
        return {"built": False}
    manifest = json.loads(path.read_text())
    manifest["built"] = True
    return manifest


def build_index(cfg: RagConfig = rag_config) -> dict:
    """(Re)build the knowledge base index. Safe to re-run any time the knowledge base
    files change; it fully replaces the previous index."""
    started = time.time()
    chunks: list[Chunk] = load_and_chunk(cfg.knowledge_base_dir, cfg.chunk_max_words,
                                         cfg.chunk_overlap_words)
    texts = [c.text for c in chunks]

    embedder = get_embedder(cfg.embedding_backend, cfg.embedding_model)
    embedder.fit_or_load(texts, cfg.persist_path())
    embeddings = embedder.embed(texts)

    store = get_store(cfg.vector_backend, cfg.persist_path())
    store.reset()
    store.add(
        ids=[c.chunk_id for c in chunks],
        embeddings=embeddings,
        documents=texts,
        metadatas=[{"doc_type": c.doc_type, "title": c.title, "source": c.source,
                   "url": c.url or "", **{k: str(v) for k, v in c.metadata.items()}}
                  for c in chunks],
    )

    technique_count = sum(1 for c in chunks if c.doc_type == "mitre_technique")
    manifest = {
        "embedding_backend": embedder.name,
        "vector_backend": store.name,
        "chunk_count": len(chunks),
        "technique_count": technique_count,
        "guideline_chunk_count": len(chunks) - technique_count,
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "build_seconds": round(time.time() - started, 2),
    }
    _manifest_path(cfg).write_text(json.dumps(manifest, indent=2))
    return manifest


def _load_runtime(cfg: RagConfig):
    if not _manifest_path(cfg).exists():
        raise RuntimeError("RAG index has not been built yet. Call build_index() first "
                          "(or POST /api/rag/reindex).")
    embedder = get_embedder(cfg.embedding_backend, cfg.embedding_model)
    load = getattr(embedder, "load", None)
    if load:
        load(cfg.persist_path())
    else:
        embedder.fit_or_load([], cfg.persist_path())
    store = get_store(cfg.vector_backend, cfg.persist_path())
    return embedder, store


def retrieve(query: str, k: int | None = None, cfg: RagConfig = rag_config) -> list[dict]:
    """Semantic search over the knowledge base. Returns chunks with a similarity score,
    highest first, with no filtering - callers apply their own score/threshold logic."""
    embedder, store = _load_runtime(cfg)
    query_vec = embedder.embed([query])[0]
    results = store.query(query_vec, k or cfg.top_k)
    results.sort(key=lambda r: -r["score"])
    return results


def retrieve_for_incident(incident: dict, evidence: dict, cfg: RagConfig = rag_config,
                          k: int | None = None) -> dict:
    """Retrieve relevant knowledge for an incident, one focused query per evidence item
    (plus one per detection rule), then merge the results.

    Querying per evidence item - rather than one giant combined query - mirrors how the
    project brief describes the mapping ("Observed behavior: repeated authentication
    failures -> Retrieved knowledge: T1110") and retrieves far more precisely than a
    single long query, where unrelated evidence dilutes the match for any one signal.
    """
    rule_labels = {"BRUTE_FORCE": "brute force repeated failed login attempts",
                  "SUSPICIOUS_POWERSHELL": "suspicious PowerShell execution",
                  "UNUSUAL_LOGIN": "unusual or suspicious authentication",
                  "SUSPICIOUS_OUTBOUND": "suspicious outbound network connection",
                  "SUSPICIOUS_COMMAND": "discovery or persistence command execution"}

    sub_queries = [(rule_labels.get(r, r), f"rule:{r}") for r in incident["rules"]]
    sub_queries += [(item["statement"], item["evidence_id"]) for item in evidence["evidence_items"]]

    per_query_k = k or max(cfg.top_k, 4)
    technique_best: dict[str, dict] = {}
    guidance_best: dict[str, dict] = {}

    for query_text, origin in sub_queries:
        for r in retrieve(query_text, per_query_k, cfg):
            if r["score"] < cfg.min_score:
                continue
            if r["metadata"]["doc_type"] == "mitre_technique":
                tid = r["metadata"]["technique_id"]
                existing = technique_best.get(tid)
                if existing is None or r["score"] > existing["score"]:
                    technique_best[tid] = {
                        "technique_id": tid,
                        "technique_name": r["metadata"]["technique_name"],
                        "tactic": r["metadata"]["tactic"],
                        "confidence": _confidence_label(r["score"]),
                        "score": round(r["score"], 3),
                        "excerpt": r["document"],
                        "url": r["metadata"].get("url") or None,
                        "matched_evidence": {origin},
                    }
                else:
                    existing["matched_evidence"].add(origin)
            else:
                key = r["id"]
                existing = guidance_best.get(key)
                if existing is None or r["score"] > existing["score"]:
                    guidance_best[key] = {
                        "title": r["metadata"]["title"],
                        "source": r["metadata"]["source"],
                        "score": round(r["score"], 3),
                        "excerpt": r["document"],
                        "matched_evidence": {origin},
                    }
                else:
                    existing["matched_evidence"].add(origin)

    def finalize(d: dict) -> dict:
        d["matched_evidence"] = sorted(d["matched_evidence"])
        return d

    techniques = sorted((finalize(t) for t in technique_best.values()), key=lambda t: -t["score"])
    guidance = sorted((finalize(g) for g in guidance_best.values()), key=lambda g: -g["score"])

    return {
        "incident_id": incident["incident_id"],
        "queries_run": len(sub_queries),
        "candidate_techniques": techniques,
        "supporting_guidance": guidance,
        "note": ("Each candidate technique was retrieved from at least one piece of "
                "evidence (see matched_evidence) by semantic similarity; these are "
                "retrieval candidates, not confirmed mappings. Confidence bands: "
                "'supported' (strong match), 'potential' (plausible), 'weak' (below "
                "the display threshold and already filtered out). Final validation "
                "against the specific evidence is performed by the investigation "
                "agent."),
    }
