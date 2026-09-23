"""Pluggable text-embedding backends.

Both implementations expose the same interface: fit_or_load(texts) once at index-build
time, then embed(texts) -> np.ndarray of shape (n, dim), L2-normalized so a dot product
equals cosine similarity.
"""
from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np


class BaseEmbedder:
    name: str
    dim: int

    def fit_or_load(self, corpus_texts: list[str], persist_path: Path) -> None:
        raise NotImplementedError

    def embed(self, texts: list[str]) -> np.ndarray:
        raise NotImplementedError


class TfidfEmbedder(BaseEmbedder):
    """Lightweight, dependency-light fallback (scikit-learn only, no downloads).

    Good for low-RAM machines or fast local testing. Weaker at matching paraphrases
    than a neural embedder, since it matches on shared vocabulary rather than meaning.
    """
    name = "tfidf"

    def __init__(self):
        self._vectorizer = None
        self.dim = 0

    def _file(self, persist_path: Path) -> Path:
        return persist_path / "tfidf_vectorizer.pkl"

    def fit_or_load(self, corpus_texts: list[str], persist_path: Path) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self._vectorizer = TfidfVectorizer(stop_words="english", max_features=4096,
                                           ngram_range=(1, 2))
        self._vectorizer.fit(corpus_texts)
        self.dim = len(self._vectorizer.vocabulary_)
        with open(self._file(persist_path), "wb") as f:
            pickle.dump(self._vectorizer, f)

    def load(self, persist_path: Path) -> None:
        with open(self._file(persist_path), "rb") as f:
            self._vectorizer = pickle.load(f)
        self.dim = len(self._vectorizer.vocabulary_)

    def embed(self, texts: list[str]) -> np.ndarray:
        if self._vectorizer is None:
            raise RuntimeError("TfidfEmbedder not fitted/loaded yet.")
        matrix = self._vectorizer.transform(texts).toarray().astype("float32")
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return matrix / norms


class SentenceTransformerEmbedder(BaseEmbedder):
    """The project brief's recommended embedder. Downloads the model (~90 MB) on first
    use and needs `sentence-transformers` installed. CPU-only is fine for this corpus
    size; expect a short pause the first time a process starts."""
    name = "sentence_transformers"

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        self.dim = 384  # all-MiniLM-L6-v2's output size

    def _ensure_loaded(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise RuntimeError(
                    "sentence-transformers is not installed. Run "
                    "`pip install sentence-transformers` on the machine hosting the "
                    "backend, or set RAG_EMBEDDING_BACKEND=tfidf for a lighter mode."
                ) from exc
            self._model = SentenceTransformer(self.model_name)

    def fit_or_load(self, corpus_texts: list[str], persist_path: Path) -> None:
        self._ensure_loaded()  # nothing to fit; the model is pre-trained

    def load(self, persist_path: Path) -> None:
        self._ensure_loaded()

    def embed(self, texts: list[str]) -> np.ndarray:
        self._ensure_loaded()
        return np.asarray(
            self._model.encode(texts, normalize_embeddings=True, show_progress_bar=False),
            dtype="float32",
        )


_BACKENDS = {"tfidf": TfidfEmbedder, "sentence_transformers": SentenceTransformerEmbedder}


def get_embedder(backend: str, model_name: str | None = None) -> BaseEmbedder:
    if backend not in _BACKENDS:
        raise ValueError(f"Unknown embedding backend '{backend}'. Choose from {list(_BACKENDS)}.")
    if backend == "sentence_transformers" and model_name:
        return _BACKENDS[backend](model_name)
    return _BACKENDS[backend]()
