"""Report generation (Phase 7): assembles the multi-agent investigation output into a
normalized report structure and renders it as a PDF."""
from .actions import get_recommended_actions
from .builder import build_report_data
from .pdf import render_pdf

__all__ = ["build_report_data", "render_pdf", "get_recommended_actions"]
