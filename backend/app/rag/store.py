"""Pluggable vector-store backends. Both expose: reset(), add(ids, embeddings,
documents, metadatas), query(embedding, k) -> list of {id, document, metadata, score},
and count().
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np


class BaseStore:
    name: str

    def reset(self) -> None:
        raise NotImplementedError

    def add(self, ids, embeddings, documents, metadatas) -> None:
        raise NotImplementedError

    def query(self, embedding, k: int) -> list[dict]:
        raise NotImplementedError

    def count(self) -> int:
        raise NotImplementedError


class NumpyStore(BaseStore):
    """Dependency-light fallback: embeddings kept in a numpy array, persisted to disk as
    .npz + a JSON sidecar for documents/metadata. Fine for a knowledge base of this size
    (tens to low hundreds of chunks); not meant to scale to a large corpus."""
    name = "memory"

    def __init__(self, persist_path: Path):
        self.persist_path = persist_path
        self._ids: list[str] = []
        self._embeddings: np.ndarray | None = None
        self._documents: list[str] = []
        self._metadatas: list[dict] = []
        self._load_if_present()

    def _files(self):
        return self.persist_path / "numpy_store.npz", self.persist_path / "numpy_store.json"

    def _load_if_present(self):
        npz_file, json_file = self._files()
        if npz_file.exists() and json_file.exists():
            data = np.load(npz_file)
            self._embeddings = data["embeddings"]
            self._ids = list(data["ids"])
            sidecar = json.loads(json_file.read_text())
            self._documents = sidecar["documents"]
            self._metadatas = sidecar["metadatas"]

    def reset(self) -> None:
        self._ids, self._documents, self._metadatas = [], [], []
        self._embeddings = None
        for f in self._files():
            f.unlink(missing_ok=True)

    def add(self, ids, embeddings, documents, metadatas) -> None:
        self._ids = list(ids)
        self._embeddings = np.asarray(embeddings, dtype="float32")
        self._documents = list(documents)
        self._metadatas = list(metadatas)
        npz_file, json_file = self._files()
        np.savez(npz_file, embeddings=self._embeddings, ids=np.array(self._ids))
        json_file.write_text(json.dumps({"documents": self._documents,
                                         "metadatas": self._metadatas}))

    def query(self, embedding, k: int) -> list[dict]:
        if self._embeddings is None or len(self._ids) == 0:
            return []
        query_vec = np.asarray(embedding, dtype="float32")
        scores = self._embeddings @ query_vec  # cosine similarity (vectors are normalized)
        top = np.argsort(-scores)[:k]
        return [
            {"id": self._ids[i], "document": self._documents[i],
             "metadata": self._metadatas[i], "score": float(scores[i])}
            for i in top
        ]

    def count(self) -> int:
        return len(self._ids)


def _to_float_rows(embeddings) -> list[list[float]]:
    """Chroma's validation rejects numpy scalar types (e.g. numpy.float32), so each row
    must be converted to plain Python floats, not just wrapped in list()."""
    return [np.asarray(e, dtype="float64").tolist() for e in embeddings]


class ChromaStore(BaseStore):
    """The project brief's recommended vector database."""
    name = "chroma"
    _COLLECTION = "knowledge_base"

    def __init__(self, persist_path: Path):
        try:
            import chromadb
        except ImportError as exc:
            raise RuntimeError(
                "chromadb is not installed. Run `pip install chromadb` on the machine "
                "hosting the backend, or set RAG_VECTOR_BACKEND=memory for a lighter mode."
            ) from exc
        self._client = chromadb.PersistentClient(path=str(persist_path))
        self._collection = self._client.get_or_create_collection(self._COLLECTION)

    def reset(self) -> None:
        try:
            self._client.delete_collection(self._COLLECTION)
        except Exception:
            pass
        self._collection = self._client.get_or_create_collection(self._COLLECTION)

    def add(self, ids, embeddings, documents, metadatas) -> None:
        vectors = _to_float_rows(embeddings)
        self._collection.upsert(ids=list(ids), embeddings=vectors,
                                documents=list(documents), metadatas=list(metadatas))

    def query(self, embedding, k: int) -> list[dict]:
        if self._collection.count() == 0:
            return []
        query_vec = _to_float_rows([embedding])[0]
        result = self._collection.query(query_embeddings=[query_vec],
                                        n_results=min(k, self._collection.count()))
        out = []
        for i in range(len(result["ids"][0])):
            distance = result["distances"][0][i]  # chroma default: squared L2 on normalized vectors
            similarity = 1 - distance / 2  # convert back to cosine similarity, range [-1, 1]
            out.append({"id": result["ids"][0][i], "document": result["documents"][0][i],
                       "metadata": result["metadatas"][0][i], "score": float(similarity)})
        return out

    def count(self) -> int:
        return self._collection.count()


def get_store(backend: str, persist_path: Path) -> BaseStore:
    if backend == "memory":
        return NumpyStore(persist_path)
    if backend == "chroma":
        return ChromaStore(persist_path)
    raise ValueError(f"Unknown vector backend '{backend}'. Choose from ['memory', 'chroma'].")
