"""RAG configuration.

Embedding and vector-store backends are pluggable (see embeddings.py / store.py) so the
project can run on modest hardware. Defaults match the project brief's recommended
stack (Sentence Transformers + ChromaDB); set RAG_EMBEDDING_BACKEND=tfidf and
RAG_VECTOR_BACKEND=memory for a dependency-light mode that needs no downloads and
works well on low-RAM machines or for quick local testing.
"""
import os
from dataclasses import dataclass
from pathlib import Path

from ..config import ROOT


@dataclass(frozen=True)
class RagConfig:
    embedding_backend: str = os.getenv("RAG_EMBEDDING_BACKEND", "sentence_transformers")
    vector_backend: str = os.getenv("RAG_VECTOR_BACKEND", "chroma")
    embedding_model: str = os.getenv("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    persist_dir: str = os.getenv("RAG_PERSIST_DIR", str(ROOT / "data" / "rag_index"))
    knowledge_base_dir: str = str(ROOT / "data" / "knowledge_base")
    top_k: int = int(os.getenv("RAG_TOP_K", "5"))
    min_score: float = float(os.getenv("RAG_MIN_SCORE", "0.15"))
    chunk_max_words: int = 180
    chunk_overlap_words: int = 30

    def persist_path(self) -> Path:
        p = Path(self.persist_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p


rag_config = RagConfig()
