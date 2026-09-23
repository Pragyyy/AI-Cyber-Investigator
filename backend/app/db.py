"""SQLite storage (stdlib sqlite3 - no ORM, easy to read and to swap for PostgreSQL later)."""
from __future__ import annotations

import json
import sqlite3
import uuid
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .parser import ParseResult

EVENT_COLUMNS = [
    "event_id", "row_number", "timestamp", "username", "source_ip", "destination_ip",
    "destination_port", "event_type", "action", "status", "hostname", "process",
    "command_line", "file_hash", "message",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    upload_id    TEXT PRIMARY KEY,
    filename     TEXT NOT NULL,
    file_format  TEXT NOT NULL,
    uploaded_at  TEXT NOT NULL,
    event_count  INTEGER NOT NULL,
    skipped_rows INTEGER NOT NULL,
    warnings     TEXT NOT NULL,   -- JSON list
    summary      TEXT NOT NULL    -- JSON object
);

CREATE TABLE IF NOT EXISTS events (
    upload_id        TEXT NOT NULL REFERENCES uploads(upload_id) ON DELETE CASCADE,
    event_id         TEXT NOT NULL,
    row_number       INTEGER NOT NULL,
    timestamp        TEXT NOT NULL,
    username         TEXT,
    source_ip        TEXT,
    destination_ip   TEXT,
    destination_port INTEGER,
    event_type       TEXT,
    action           TEXT,
    status           TEXT,
    hostname         TEXT,
    process          TEXT,
    command_line     TEXT,
    file_hash        TEXT,
    message          TEXT,
    raw              TEXT NOT NULL,   -- original record as JSON, for traceability
    PRIMARY KEY (upload_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(upload_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src  ON events(upload_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(upload_id, username);

CREATE TABLE IF NOT EXISTS incidents (
    upload_id      TEXT NOT NULL REFERENCES uploads(upload_id) ON DELETE CASCADE,
    incident_id    TEXT NOT NULL,
    incident_type  TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    severity_score INTEGER NOT NULL,
    status         TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    event_count    INTEGER NOT NULL,
    data           TEXT NOT NULL,   -- full incident object as JSON
    PRIMARY KEY (upload_id, incident_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    upload_id   TEXT NOT NULL REFERENCES uploads(upload_id) ON DELETE CASCADE,
    incident_id TEXT NOT NULL,
    data        TEXT NOT NULL,   -- evidence package as JSON
    PRIMARY KEY (upload_id, incident_id)
);

CREATE TABLE IF NOT EXISTS threat_intel (
    upload_id   TEXT NOT NULL REFERENCES uploads(upload_id) ON DELETE CASCADE,
    incident_id TEXT NOT NULL,
    data        TEXT NOT NULL,   -- RAG retrieval result as JSON
    PRIMARY KEY (upload_id, incident_id)
);
"""


@contextmanager
def get_conn():
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def _summarize(events: list[dict]) -> dict:
    timestamps = [e["timestamp"] for e in events]
    return {
        "time_start": min(timestamps),
        "time_end": max(timestamps),
        "unique_users": len({e["username"] for e in events if e["username"]}),
        "unique_source_ips": len({e["source_ip"] for e in events if e["source_ip"]}),
        "unique_hosts": len({e["hostname"] for e in events if e["hostname"]}),
        "event_type_counts": dict(Counter(e["event_type"] or "UNKNOWN" for e in events)),
        "status_counts": dict(Counter(e["status"] or "UNKNOWN" for e in events)),
    }


def _upload_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "upload_id": row["upload_id"],
        "filename": row["filename"],
        "file_format": row["file_format"],
        "uploaded_at": row["uploaded_at"],
        "event_count": row["event_count"],
        "skipped_rows": row["skipped_rows"],
        "warnings": json.loads(row["warnings"]),
        "summary": json.loads(row["summary"]),
    }


def save_upload(filename: str, result: ParseResult) -> dict:
    upload_id = f"UPL-{uuid.uuid4().hex[:8]}"
    uploaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    summary = _summarize(result.events)

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO uploads VALUES (?,?,?,?,?,?,?,?)",
            (upload_id, filename, result.file_format, uploaded_at, len(result.events),
             result.skipped_rows, json.dumps(result.warnings), json.dumps(summary)),
        )
        placeholders = ",".join("?" * (len(EVENT_COLUMNS) + 2))
        conn.executemany(
            f"INSERT INTO events (upload_id,{','.join(EVENT_COLUMNS)},raw) VALUES ({placeholders})",
            [
                (upload_id, *[e[c] for c in EVENT_COLUMNS], json.dumps(e["raw"]))
                for e in result.events
            ],
        )
    return get_upload(upload_id)


def get_upload(upload_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM uploads WHERE upload_id = ?", (upload_id,)).fetchone()
    return _upload_row_to_dict(row) if row else None


def list_uploads() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM uploads ORDER BY uploaded_at DESC, upload_id").fetchall()
    return [_upload_row_to_dict(r) for r in rows]


def delete_upload(upload_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM uploads WHERE upload_id = ?", (upload_id,))
    return cur.rowcount > 0


def query_events(
    upload_id: str,
    limit: int = 100,
    offset: int = 0,
    event_type: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    hostname: str | None = None,
    status: str | None = None,
    search: str | None = None,
) -> tuple[int, list[dict]]:
    """Return (total_matching, page_of_events), ordered by time."""
    where, params = ["upload_id = ?"], [upload_id]
    for column, value in (("event_type", event_type and event_type.upper()),
                          ("status", status and status.upper()),
                          ("username", username),
                          ("source_ip", source_ip),
                          ("hostname", hostname)):
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if search:
        where.append("(message LIKE ? OR command_line LIKE ? OR process LIKE ?)")
        params += [f"%{search}%"] * 3
    clause = " AND ".join(where)

    with get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM events WHERE {clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM events WHERE {clause} ORDER BY timestamp, row_number LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

    events = []
    for r in rows:
        e = {c: r[c] for c in EVENT_COLUMNS}
        e["raw"] = json.loads(r["raw"])
        events.append(e)
    return total, events


# --------------------------------------------------------------------------
# Detection input, incidents, dashboard numbers
# --------------------------------------------------------------------------
def get_all_events(upload_id: str) -> list[dict]:
    """Every normalized event of an upload (without the raw record), for the detection engine."""
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT {','.join(EVENT_COLUMNS)} FROM events WHERE upload_id = ? "
            "ORDER BY timestamp, row_number", (upload_id,)).fetchall()
    return [{c: r[c] for c in EVENT_COLUMNS} for r in rows]


def replace_incidents(upload_id: str, incidents: list[dict]) -> None:
    """Store the result of a detection run, replacing any earlier run for this upload."""
    with get_conn() as conn:
        conn.execute("DELETE FROM incidents WHERE upload_id = ?", (upload_id,))
        conn.execute("DELETE FROM evidence WHERE upload_id = ?", (upload_id,))
        conn.execute("DELETE FROM threat_intel WHERE upload_id = ?", (upload_id,))
        conn.executemany(
            "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [(upload_id, i["incident_id"], i["incident_type"], i["title"], i["severity"],
              i["severity_score"], i["status"], i["first_seen"], i["last_seen"],
              i["event_count"], json.dumps(i)) for i in incidents],
        )


def list_incidents(upload_id: str) -> list[dict]:
    """Incidents, most severe first, then earliest first."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT data FROM incidents WHERE upload_id = ? "
            "ORDER BY severity_score DESC, first_seen, incident_id", (upload_id,)).fetchall()
    return [json.loads(r["data"]) for r in rows]


def get_incident(upload_id: str, incident_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT data FROM incidents WHERE upload_id = ? AND incident_id = ?",
                           (upload_id, incident_id)).fetchone()
    return json.loads(row["data"]) if row else None


def dashboard_stats(upload_id: str) -> dict:
    """The four headline numbers for the dashboard home page, plus a severity breakdown."""
    incidents = list_incidents(upload_id)
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events WHERE upload_id = ?",
                             (upload_id,)).fetchone()[0]
    suspicious = {eid for i in incidents for eid in i["event_ids"]}
    by_severity = Counter(i["severity"] for i in incidents)
    return {
        "total_events": total,
        "suspicious_events": len(suspicious),
        "active_incidents": sum(1 for i in incidents if i["status"] != "closed"),
        "high_severity_incidents": by_severity["HIGH"] + by_severity["CRITICAL"],
        "severity_counts": {k: by_severity.get(k, 0) for k in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
    }


# --------------------------------------------------------------------------
# Evidence (Phase 3)
# --------------------------------------------------------------------------
def save_evidence(upload_id: str, incident_id: str, evidence: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO evidence (upload_id, incident_id, data) VALUES (?,?,?) "
            "ON CONFLICT(upload_id, incident_id) DO UPDATE SET data = excluded.data",
            (upload_id, incident_id, json.dumps(evidence)),
        )


def get_evidence(upload_id: str, incident_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT data FROM evidence WHERE upload_id = ? AND incident_id = ?",
            (upload_id, incident_id)).fetchone()
    return json.loads(row["data"]) if row else None


# --------------------------------------------------------------------------
# Threat intelligence / RAG results (Phase 4)
# --------------------------------------------------------------------------
def save_threat_intel(upload_id: str, incident_id: str, result: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO threat_intel (upload_id, incident_id, data) VALUES (?,?,?) "
            "ON CONFLICT(upload_id, incident_id) DO UPDATE SET data = excluded.data",
            (upload_id, incident_id, json.dumps(result)),
        )


def get_threat_intel(upload_id: str, incident_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT data FROM threat_intel WHERE upload_id = ? AND incident_id = ?",
            (upload_id, incident_id)).fetchone()
    return json.loads(row["data"]) if row else None
