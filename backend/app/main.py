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
from fastapi.responses import FileResponse, RedirectResponse

from . import db
from .config import ROOT, settings
from .detection import DetectionConfig, run_detection
from .evidence import build_evidence
from . import rag as rag_module
from .rag import rag_config
from .agents import run_investigation
from .report import build_report_data, render_pdf
from .parser import SUPPORTED_EXTENSIONS, LogParseError, parse_log_file


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    if not rag_module.get_status(rag_config)["built"]:
        try:
            rag_module.build_index(rag_config)
        except (RuntimeError, ValueError) as exc:
            print(f"[startup] RAG index not built yet: {exc}\n"
                 f"[startup] Threat-intel endpoints will return 409 until you run "
                 f"'python scripts/build_rag_index.py' or POST /api/rag/reindex.")
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


# --------------------------------------------------------------------------
# RAG knowledge base (Phase 4)
# --------------------------------------------------------------------------
@app.get("/api/rag/status")
def rag_status():
    """Whether the knowledge base index has been built, and with which backends."""
    return rag_module.get_status(rag_config)


@app.post("/api/rag/reindex")
def rag_reindex():
    """(Re)build the MITRE ATT&CK + guideline knowledge base index. Run this once
    after setup, and again any time files under data/knowledge_base change."""
    try:
        return rag_module.build_index(rag_config)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/rag/search")
def rag_search(q: str, k: int = Query(5, ge=1, le=20)):
    """Manual knowledge-base search, mainly for testing the RAG pipeline directly."""
    try:
        return rag_module.retrieve(q, k, rag_config)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/api/uploads/{upload_id}/incidents/{incident_id}/threat-intel")
def get_threat_intel(upload_id: str, incident_id: str, refresh: bool = False):
    """Candidate MITRE ATT&CK techniques and supporting guidance retrieved for this
    incident's evidence via RAG. These are retrieval candidates, not confirmed
    mappings - see the response's "note" field. Cached after the first call."""
    _require_upload(upload_id)
    incident = db.get_incident(upload_id, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    if not refresh:
        cached = db.get_threat_intel(upload_id, incident_id)
        if cached:
            return cached

    evidence = db.get_evidence(upload_id, incident_id)
    if not evidence:
        evidence = build_evidence(incident, db.get_all_events(upload_id))
        db.save_evidence(upload_id, incident_id, evidence)

    try:
        result = rag_module.retrieve_for_incident(incident, evidence, rag_config)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    db.save_threat_intel(upload_id, incident_id, result)
    return result


# --------------------------------------------------------------------------
# Multi-agent investigation (Phase 5): Detection/Analysis -> Evidence -> Threat Intel
# --------------------------------------------------------------------------
@app.post("/api/uploads/{upload_id}/incidents/{incident_id}/investigate")
def investigate(upload_id: str, incident_id: str, refresh: bool = False):
    """Run the multi-agent workflow for this incident and return the combined result.
    Cached after the first call; pass ?refresh=true to re-run it (e.g. after changing
    LLM_PROVIDER). Each agent's output is tagged with "generated_by": "llm" if a real
    model produced it, or "fallback" if the deterministic stand-in was used (no
    provider configured, or the live call failed)."""
    _require_upload(upload_id)
    incident = db.get_incident(upload_id, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    if not refresh:
        cached = db.get_investigation(upload_id, incident_id)
        if cached:
            return cached

    evidence = db.get_evidence(upload_id, incident_id)
    if not evidence:
        evidence = build_evidence(incident, db.get_all_events(upload_id))
        db.save_evidence(upload_id, incident_id, evidence)

    rag_result = db.get_threat_intel(upload_id, incident_id)
    if not rag_result:
        try:
            rag_result = rag_module.retrieve_for_incident(incident, evidence, rag_config)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        db.save_threat_intel(upload_id, incident_id, rag_result)

    result = run_investigation(incident, evidence, rag_result)
    db.save_investigation(upload_id, incident_id, result)
    return result


@app.get("/api/uploads/{upload_id}/incidents/{incident_id}/investigation")
def get_investigation(upload_id: str, incident_id: str):
    """Fetch a previously-run investigation without re-running it. Returns 404 if
    /investigate hasn't been called for this incident yet."""
    _require_upload(upload_id)
    if not db.get_incident(upload_id, incident_id):
        raise HTTPException(status_code=404, detail="Incident not found.")
    result = db.get_investigation(upload_id, incident_id)
    if not result:
        raise HTTPException(status_code=404, detail="No investigation has been run for "
                            "this incident yet. POST to /investigate first.")
    return result


# --------------------------------------------------------------------------
# Report generation (Phase 7)
# --------------------------------------------------------------------------
REPORTS_DIR = ROOT / "reports"


@app.get("/api/uploads/{upload_id}/incidents/{incident_id}/report/data")
def get_report_data(upload_id: str, incident_id: str):
    """The normalized report data (everything the PDF is built from) as JSON - useful
    for a dashboard "report" view that doesn't need the PDF file itself. Requires
    /investigate to have been run first."""
    _require_upload(upload_id)
    incident = db.get_incident(upload_id, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    investigation_result = db.get_investigation(upload_id, incident_id)
    if not investigation_result:
        raise HTTPException(status_code=409, detail="No investigation has been run for "
                            "this incident yet. POST to /investigate first.")
    evidence = db.get_evidence(upload_id, incident_id) or build_evidence(
        incident, db.get_all_events(upload_id))
    rag_result = db.get_threat_intel(upload_id, incident_id)
    return build_report_data(incident, evidence, investigation_result, rag_result)


@app.post("/api/uploads/{upload_id}/incidents/{incident_id}/report")
def generate_report(upload_id: str, incident_id: str):
    """Generate the PDF incident report and return it as a file download. Requires
    /investigate to have been run first (run it automatically is deliberately NOT done
    here - report generation should reflect a deliberate, already-reviewed
    investigation, not trigger a fresh LLM run as a side effect of a download click)."""
    report_data = get_report_data(upload_id, incident_id)  # reuses all the same checks
    output_path = REPORTS_DIR / upload_id / f"{incident_id}_report.pdf"
    render_pdf(report_data, str(output_path))
    return FileResponse(output_path, media_type="application/pdf",
                        filename=f"{incident_id}_report.pdf")
