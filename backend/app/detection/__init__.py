"""Detection engine: log events in, detections and incidents out."""
from __future__ import annotations

from .common import Context
from .config import DetectionConfig
from .correlate import build_incidents
from .rules import (detect_brute_force, detect_suspicious_commands,
                    detect_suspicious_outbound, detect_suspicious_powershell,
                    detect_unusual_login)

__all__ = ["run_detection", "DetectionConfig"]


def run_detection(events: list[dict], cfg: DetectionConfig | None = None) -> dict:
    """Run every rule over the events and correlate the results into incidents.

    Returns {"detections": [...], "incidents": [...]}. Deterministic: the same events
    and config always give the same result.
    """
    cfg = cfg or DetectionConfig()
    ctx = Context(events)

    brute = detect_brute_force(ctx, cfg)
    detections = (
        brute
        + detect_suspicious_powershell(ctx, cfg, brute)
        + detect_unusual_login(ctx, cfg)
        + detect_suspicious_outbound(ctx, cfg)
        + detect_suspicious_commands(ctx, cfg)
    )
    incidents = build_incidents(detections, ctx, cfg)
    return {"detections": [d.to_dict() for d in detections], "incidents": incidents}
