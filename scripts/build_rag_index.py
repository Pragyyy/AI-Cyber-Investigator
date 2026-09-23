#!/usr/bin/env python3
"""Build (or rebuild) the RAG knowledge base index.

Run this once after installing dependencies, and again any time you edit files under
data/knowledge_base/ (add a technique, edit a guideline doc, etc.).

    python scripts/build_rag_index.py

The backend also builds the index automatically on first startup if none exists, so
running this manually is optional - useful mainly to see timing/output directly, or to
force a rebuild after an edit.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.rag import build_index, rag_config  # noqa: E402


def main():
    print(f"Embedding backend: {rag_config.embedding_backend}")
    print(f"Vector backend:    {rag_config.vector_backend}")
    print(f"Persist dir:       {rag_config.persist_dir}")
    print("Building index...")
    manifest = build_index(rag_config)
    print(f"\nDone in {manifest['build_seconds']}s: {manifest['chunk_count']} chunks "
         f"({manifest['technique_count']} MITRE techniques, "
         f"{manifest['guideline_chunk_count']} guideline chunks).")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
