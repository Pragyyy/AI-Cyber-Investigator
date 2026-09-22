"""Log parsing and normalization.

Turns an uploaded CSV / JSON / JSONL file into a list of normalized event dicts.

Design goals
- Tolerant: accepts common column-name variants (src_ip, user, host, ...), several
  timestamp formats, and header-less CSVs in the project-brief column order.
- Traceable: every event keeps its original row number (event_id = EVT-<row>) and
  the untouched original record under "raw", so later evidence can point back to it.
- Honest: bad rows are skipped and reported as warnings, never silently dropped.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from pathlib import Path

MAX_WARNINGS = 20
SUPPORTED_EXTENSIONS = {".csv", ".json", ".jsonl", ".ndjson"}

CANONICAL_FIELDS = [
    "timestamp", "username", "source_ip", "destination_ip", "destination_port",
    "event_type", "action", "status", "hostname", "process", "command_line",
    "file_hash", "message",
]

# Column order used when a CSV has no header row (matches the project brief).
HEADERLESS_ORDER = [
    "timestamp", "username", "source_ip", "destination_ip", "event_type",
    "action", "status", "hostname", "process", "message",
]

ALIASES = {
    "timestamp": {"timestamp", "time", "datetime", "date_time", "@timestamp",
                  "eventtime", "event_time", "ts"},
    "username": {"username", "user", "user_name", "account", "account_name",
                 "target_user"},
    "source_ip": {"source_ip", "src_ip", "srcip", "src", "source", "source_address",
                  "ip"},
    "destination_ip": {"destination_ip", "dest_ip", "dst_ip", "dstip", "dst",
                       "destination", "dest", "destination_address"},
    "destination_port": {"destination_port", "dest_port", "dst_port", "dport", "port"},
    "event_type": {"event_type", "eventtype", "type", "category", "event"},
    "action": {"action", "activity", "operation"},
    "status": {"status", "result", "outcome"},
    "hostname": {"hostname", "host", "host_name", "computer", "computer_name",
                 "device"},
    "process": {"process", "process_name", "image", "exe"},
    "command_line": {"command_line", "commandline", "cmdline", "command", "cmd"},
    "file_hash": {"file_hash", "hash", "sha256", "md5", "sha1"},
    "message": {"message", "msg", "description", "details", "raw"},
}
_KEY_LOOKUP = {alias: canon for canon, names in ALIASES.items() for alias in names}

STATUS_MAP = {
    "FAIL": "FAILED", "FAILURE": "FAILED", "FAILED": "FAILED",
    "SUCCESS": "SUCCESS", "SUCCEEDED": "SUCCESS", "SUCCESSFUL": "SUCCESS", "OK": "SUCCESS",
}

_TIME_ONLY = re.compile(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?$")
_EPOCH = re.compile(r"^\d{10}(\.\d+)?$|^\d{13}$")
_DATETIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S", "%d-%b-%Y %H:%M:%S", "%b %d %Y %H:%M:%S",
)


class LogParseError(ValueError):
    """The file cannot be parsed at all (row-level problems become warnings instead)."""


@dataclass
class ParseResult:
    file_format: str
    total_rows: int = 0
    skipped_rows: int = 0
    events: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


class _Warnings:
    """Collects warnings but caps how many are stored."""

    def __init__(self):
        self.items: list[str] = []
        self.suppressed = 0

    def add(self, message: str):
        if len(self.items) < MAX_WARNINGS:
            self.items.append(message)
        else:
            self.suppressed += 1

    def finish(self) -> list[str]:
        if self.suppressed:
            self.items.append(f"... and {self.suppressed} more warnings not shown")
        return self.items


# --------------------------------------------------------------------------
# Value helpers
# --------------------------------------------------------------------------
def _norm_key(key) -> str:
    return re.sub(r"[\s\-]+", "_", str(key).strip().lower())


def _clean(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str):
        value = value.strip()
        return None if value in ("", "-") else value
    return value


def parse_timestamp(value, default_date: date):
    """Return (naive UTC datetime | None, date_was_assumed)."""
    if value is None:
        return None, False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value >= 1e12 else value
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None), False
        except (OverflowError, OSError, ValueError):
            return None, False

    s = str(value).strip()
    if not s:
        return None, False
    if _EPOCH.match(s):
        return parse_timestamp(float(s), default_date)

    m = _TIME_ONLY.match(s)
    if m:
        hh, mm, ss = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
        if hh < 24 and mm < 60 and ss < 60:
            return datetime.combine(default_date, time(hh, mm, ss)), True
        return None, False

    dt = None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        for fmt in _DATETIME_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None, False
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt, False


def _normalize_record(record: dict) -> dict:
    out = {f: None for f in CANONICAL_FIELDS}
    for key, value in record.items():
        canon = _KEY_LOOKUP.get(_norm_key(key))
        if canon and out[canon] is None:  # first matching column wins
            out[canon] = _clean(value)

    if isinstance(out["event_type"], str):
        out["event_type"] = out["event_type"].upper()
    if isinstance(out["status"], str):
        upper = out["status"].upper()
        out["status"] = STATUS_MAP.get(upper, upper)
    if out["destination_port"] is not None:
        try:
            out["destination_port"] = int(float(out["destination_port"]))
        except (TypeError, ValueError):
            out["destination_port"] = None
    for key in ("username", "source_ip", "destination_ip", "action", "hostname",
                "process", "command_line", "file_hash", "message"):
        if out[key] is not None and not isinstance(out[key], str):
            out[key] = str(out[key])
    return out


# --------------------------------------------------------------------------
# Reading rows from each file format
# --------------------------------------------------------------------------
def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1")


def _records_from_csv(text: str, default_date: date, warnings: _Warnings):
    """Yield (row_number, raw_record_dict)."""
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ","
    rows = [r for r in csv.reader(io.StringIO(text), delimiter=delimiter)
            if any(cell.strip() for cell in r)]
    if not rows:
        raise LogParseError("The file is empty.")

    first = rows[0]
    header_matches = [_KEY_LOOKUP.get(_norm_key(c)) for c in first]
    if any(header_matches):
        if "timestamp" not in header_matches:
            raise LogParseError(
                "No timestamp column found. Accepted names: "
                + ", ".join(sorted(ALIASES["timestamp"]))
            )
        header, data = [c.strip() for c in first], rows[1:]
    else:
        ts, _ = parse_timestamp(first[0], default_date)
        if ts is None:
            raise LogParseError(
                "No header row found, and the first column does not look like a "
                "timestamp. Add a header row (e.g. timestamp,username,source_ip,...)."
            )
        width = len(first)
        header = HEADERLESS_ORDER[:width] + [f"column_{i + 1}" for i in range(len(HEADERLESS_ORDER), width)]
        data = rows
        warnings.add("No header row detected; assumed column order: "
                     + ",".join(header[:min(width, len(HEADERLESS_ORDER))]))

    for i, row in enumerate(data, start=1):
        if len(row) > len(header):
            warnings.add(f"Row {i}: more values than header columns; extra values ignored.")
        yield i, dict(zip(header, row))


def _records_from_json(text: str, warnings: _Warnings):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LogParseError(f"Invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno}).")

    if isinstance(data, dict):
        for key in ("events", "logs", "records", "data", "items"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            raise LogParseError(
                "JSON object found, but no list of events. Use a top-level list, or an "
                "object with an 'events' (or logs/records/data/items) list."
            )
    if not isinstance(data, list):
        raise LogParseError("JSON must contain a list of event objects.")
    for i, record in enumerate(data, start=1):
        if isinstance(record, dict):
            yield i, record
        else:
            warnings.add(f"Record {i}: not a JSON object; skipped.")
            yield i, None


def _records_from_jsonl(text: str, warnings: _Warnings):
    n = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        n += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            warnings.add(f"Line {n}: invalid JSON; skipped.")
            yield n, None
            continue
        if isinstance(record, dict):
            yield n, record
        else:
            warnings.add(f"Line {n}: not a JSON object; skipped.")
            yield n, None


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------
def parse_log_file(content: bytes, filename: str, default_date: date | None = None) -> ParseResult:
    """Parse an uploaded log file into normalized events.

    `default_date` is only used for time-only timestamps such as "12:01".
    """
    ext = Path(filename or "").suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise LogParseError(
            f"Unsupported file type '{ext or 'none'}'. Upload a "
            + ", ".join(sorted(SUPPORTED_EXTENSIONS)) + " file."
        )
    if not content or not content.strip():
        raise LogParseError("The file is empty.")

    default_date = default_date or date.today()
    text = _decode(content)
    warnings = _Warnings()

    if ext == ".csv":
        fmt, records = "csv", _records_from_csv(text, default_date, warnings)
    elif ext == ".json":
        fmt, records = "json", _records_from_json(text, warnings)
    else:
        fmt, records = "jsonl", _records_from_jsonl(text, warnings)

    result = ParseResult(file_format=fmt)
    date_assumed = False

    for row_number, raw in records:
        result.total_rows += 1
        if raw is None:
            result.skipped_rows += 1
            continue
        normalized = _normalize_record(raw)
        ts, assumed = parse_timestamp(
            normalized["timestamp"] if normalized["timestamp"] is not None else None,
            default_date,
        )
        if ts is None:
            result.skipped_rows += 1
            warnings.add(f"Row {row_number}: missing or unreadable timestamp "
                         f"({normalized['timestamp']!r}); skipped.")
            continue
        date_assumed = date_assumed or assumed
        normalized["timestamp"] = ts.isoformat()
        result.events.append({
            "event_id": f"EVT-{row_number:06d}",
            "row_number": row_number,
            **normalized,
            "raw": raw,
        })

    if not result.events:
        raise LogParseError(
            f"No valid events found ({result.skipped_rows} of {result.total_rows} rows skipped)."
        )
    if date_assumed:
        warnings.add(f"Some timestamps had no date; assumed {default_date.isoformat()}.")

    result.events.sort(key=lambda e: (e["timestamp"], e["row_number"]))
    result.warnings = warnings.finish()
    return result
