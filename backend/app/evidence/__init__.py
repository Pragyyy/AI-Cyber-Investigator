"""Evidence extraction (Phase 3): turn an incident's detections into a structured,
traceable evidence package for the report."""
from __future__ import annotations

from .extract import build_evidence

__all__ = ["build_evidence"]
