"""FastAPI entry point.

Run from the backend/ folder:
    uvicorn app.main:app --reload
Interactive API docs: http://127.0.0.1:8000/docs
"""
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from . import db
from .config import settings
from .detection import DetectionConfig, run_detection
from .evidence import build_evidence
from .parser import SUPPORTED_EXTENSIONS, LogParseError, parse_log_file


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="AI Cybersecurity Investigator", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)


def _detect(upload_id: str, cfg: DetectionConfig | None = None) -> dict:
    """Run the detection engine on a stored upload and save the resulting incidents."""
    result = run_detection(db.get_all_events(upload_id), cfg)
    db.replace_incidents(upload_id, result["incidents"])
    return result


def _ingest(content: bytes, filename: str) -> dict:
    try:
        result = parse_log_file(content, filename)
    except LogParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    upload = db.save_upload(filename, result)
    upload["incident_count"] = len(_detect(upload["upload_id"])["incidents"])
    return upload


def _require_upload(upload_id: str) -> dict:
    upload = db.get_upload(upload_id)
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found.")
    return upload


def _sample_files() -> dict[str, Path]:
    folder = Path(settings.sample_dir)
    if not folder.is_dir():
        return {}
    return {p.name: p for p in sorted(folder.iterdir())
            if p.suffix.lower() in SUPPORTED_EXTENSIONS and p.name != "manifest.json"}


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.post("/api/uploads", status_code=201)
def upload_logs(file: UploadFile = File(...)):
    """Upload a CSV / JSON / JSONL log file; it is parsed, normalized and stored."""
    content = file.file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=413,
                            detail=f"File is larger than {settings.max_upload_mb} MB.")
    return _ingest(content, file.filename or "")


@app.get("/api/uploads")
def list_uploads():
    return db.list_uploads()


@app.get("/api/uploads/{upload_id}")
def get_upload(upload_id: str):
    upload = db.get_upload(upload_id)
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found.")
    return upload


@app.delete("/api/uploads/{upload_id}", status_code=204)
def delete_upload(upload_id: str):
    if not db.delete_upload(upload_id):
        raise HTTPException(status_code=404, detail="Upload not found.")


@app.get("/api/uploads/{upload_id}/events")
def get_events(
    upload_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    event_type: str | None = None,
    status: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    hostname: str | None = None,
    search: str | None = None,
):
    if not db.get_upload(upload_id):
        raise HTTPException(status_code=404, detail="Upload not found.")
    total, events = db.query_events(
        upload_id, limit, offset, event_type, username, source_ip, hostname, status, search
    )
    return {"total": total, "limit": limit, "offset": offset, "events": events}


@app.get("/api/samples")
def list_samples():
    """Bundled demo datasets (used by the dashboard's 'Load sample data' button)."""
    return [{"name": name, "size_bytes": path.stat().st_size}
            for name, path in _sample_files().items()]


@app.post("/api/samples/{name}/load", status_code=201)
def load_sample(name: str):
    path = _sample_files().get(name)  # whitelist lookup - no path traversal possible
    if path is None:
        raise HTTPException(status_code=404, detail="Sample file not found.")
    return _ingest(path.read_bytes(), name)


# --------------------------------------------------------------------------
# Detection and incidents (Phase 2)
# --------------------------------------------------------------------------
@app.post("/api/uploads/{upload_id}/detect")
def run_detection_endpoint(
    upload_id: str,
    brute_force_threshold: int | None = Query(None, ge=2, description="Failed logins needed"),
    brute_force_window_minutes: int | None = Query(None, ge=1, description="Time window"),
):
    """(Re)run detection on an upload, optionally with different brute-force thresholds.
    Replaces the upload's previous incidents."""
    _require_upload(upload_id)
    cfg = DetectionConfig()
    if brute_force_threshold is not None:
        cfg = replace(cfg, brute_force_threshold=brute_force_threshold)
    if brute_force_window_minutes is not None:
        cfg = replace(cfg, brute_force_window_minutes=brute_force_window_minutes)
    result = _detect(upload_id, cfg)
    return {"incident_count": len(result["incidents"]), "incidents": db.list_incidents(upload_id)}


@app.get("/api/uploads/{upload_id}/incidents")
def list_incidents(upload_id: str):
    _require_upload(upload_id)
    return db.list_incidents(upload_id)


@app.get("/api/uploads/{upload_id}/incidents/{incident_id}")
def get_incident(upload_id: str, incident_id: str):
    _require_upload(upload_id)
    incident = db.get_incident(upload_id, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


@app.get("/api/uploads/{upload_id}/stats")
def get_stats(upload_id: str):
    """Headline numbers for the dashboard home page."""
    _require_upload(upload_id)
    return db.dashboard_stats(upload_id)


# --------------------------------------------------------------------------
# Evidence (Phase 3)
# --------------------------------------------------------------------------
@app.get("/api/uploads/{upload_id}/incidents/{incident_id}/evidence")
def get_evidence(upload_id: str, incident_id: str, refresh: bool = False):
    """Evidence package for one incident: statements, indicators, related events -
    every item traceable back to log rows. Cached after the first call; pass
    ?refresh=true to rebuild it."""
    _require_upload(upload_id)
    incident = db.get_incident(upload_id, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    if not refresh:
        cached = db.get_evidence(upload_id, incident_id)
        if cached:
            return cached

    evidence = build_evidence(incident, db.get_all_events(upload_id))
    db.save_evidence(upload_id, incident_id, evidence)
    return evidence
