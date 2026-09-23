"""Load the knowledge base (MITRE ATT&CK techniques + guideline docs) and split it into
retrievable chunks.

Each chunk carries enough metadata to cite its source in a report: for a technique
chunk, the MITRE technique ID and a reference URL; for a guideline chunk, the source
file and section title.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Chunk:
    chunk_id: str
    doc_type: str          # "mitre_technique" | "guideline"
    title: str
    text: str
    source: str             # display name of the source (technique ID+name, or filename)
    url: str | None = None  # reference link, if any
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _split_words(text: str, max_words: int, overlap: int) -> list[str]:
    words = text.split()
    if len(words) <= max_words:
        return [text]
    parts, start = [], 0
    step = max(max_words - overlap, 1)
    while start < len(words):
        parts.append(" ".join(words[start:start + max_words]))
        start += step
    return parts


def _load_mitre_techniques(kb_dir: Path) -> list[Chunk]:
    path = kb_dir / "mitre_attck.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    url_pattern = data.get("reference_url_pattern", "")
    chunks = []
    for t in data["techniques"]:
        text = (f"{t['id']} - {t['name']} (Tactic: {t['tactic']}). {t['description']} "
                f"Detection notes: {t['detection_notes']}")
        chunks.append(Chunk(
            chunk_id=f"mitre::{t['id']}",
            doc_type="mitre_technique",
            title=f"{t['id']} - {t['name']}",
            text=text,
            source=f"MITRE ATT&CK {t['id']}",
            url=url_pattern.format(id=t["id"]) if url_pattern else None,
            metadata={"technique_id": t["id"], "technique_name": t["name"],
                     "tactic": t["tactic"]},
        ))
    return chunks


_HEADER_RE = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)


def _sections(markdown: str) -> list[tuple[str, str]]:
    """Split a markdown file into (heading, body) sections on '##' headers."""
    matches = list(_HEADER_RE.finditer(markdown))
    if not matches:
        return [("", markdown.strip())]
    sections = []
    doc_title = matches[0].group(1).strip() if markdown.lstrip().startswith("# ") else ""
    for i, m in enumerate(matches):
        if m.group(0).startswith("# ") and not m.group(0).startswith("## "):
            continue  # document title, not a section
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(markdown)
        body = markdown[start:end].strip()
        if body:
            sections.append((m.group(1).strip(), body))
    return sections or [(doc_title, markdown.strip())]


def _load_guideline_docs(kb_dir: Path, max_words: int, overlap: int) -> list[Chunk]:
    docs_dir = kb_dir / "docs"
    if not docs_dir.is_dir():
        return []
    chunks = []
    for path in sorted(docs_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title_match = re.match(r"^#\s+(.*)$", text.lstrip(), re.MULTILINE)
        doc_title = title_match.group(1).strip() if title_match else path.stem.replace("_", " ").title()
        for i, (heading, body) in enumerate(_sections(text)):
            body = re.sub(r"\s+", " ", body).strip()
            for j, part in enumerate(_split_words(body, max_words, overlap)):
                suffix = f".{i}.{j}" if j else f".{i}"
                chunks.append(Chunk(
                    chunk_id=f"doc::{path.stem}{suffix}",
                    doc_type="guideline",
                    title=f"{doc_title} - {heading}" if heading else doc_title,
                    text=f"{doc_title}: {heading}. {part}" if heading else f"{doc_title}. {part}",
                    source=path.name,
                    metadata={"file": path.name, "section": heading},
                ))
    return chunks


def load_and_chunk(kb_dir: str, max_words: int = 180, overlap: int = 30) -> list[Chunk]:
    kb_path = Path(kb_dir)
    chunks = _load_mitre_techniques(kb_path) + _load_guideline_docs(kb_path, max_words, overlap)
    if not chunks:
        raise ValueError(f"No knowledge base content found under {kb_path}.")
    return chunks
