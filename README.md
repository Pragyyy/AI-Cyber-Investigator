# AI Cybersecurity Investigator

A software-only prototype that takes security logs, detects suspicious activity, and
(in later phases) investigates it with multiple specialised AI agents, retrieves
knowledge with RAG (MITRE ATT&CK and security documents), builds an attack timeline,
and generates an evidence-based incident report.

> **Status: Phase 3 of 10 complete** (backend, log parsing, sample data, detection engine, evidence extraction).

> **Safety note:** all data in this repo is simulated. The tool is for defensive
> analysis. Public IPs come from reserved documentation ranges and the "encoded"
> PowerShell payload is a harmless print statement.

## Roadmap

- [x] Phase 1 - Backend, dataset, log parsing, storage
- [x] Phase 2 - Detection engine and incident creation
- [x] Phase 3 - Evidence extraction (traceable to original log rows)
- [ ] Phase 3 - Evidence extraction (traceable to original log rows)
- [ ] Phase 4 - RAG knowledge base + ChromaDB
- [ ] Phase 5 - Multi-agent workflow (LangGraph)
- [ ] Phase 6 - Investigation and correlation
- [ ] Phase 7 - Report generation (PDF)
- [ ] Phase 8 - React dashboard
- [ ] Phase 9 - Integration
- [ ] Phase 10 - Testing across all scenarios

## Requirements

- Python **3.10 or newer**
- (Later phases) Node.js 18+ for the dashboard, and an LLM API key

## Quick start (Windows PowerShell shown; on Mac/Linux use `source venv/bin/activate`)

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# generate the simulated datasets (already included, safe to re-run)
python ..\scripts\generate_sample_logs.py

# run the API
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs to try the API in your browser.

Run the tests (from `backend/`): `pytest` (or `python -m unittest discover -s tests -t .`).

## API

| Method | Path | What it does |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/uploads` | Upload a CSV / JSON / JSONL log file |
| GET | `/api/uploads` | List uploads |
| GET | `/api/uploads/{id}` | Upload summary and parse warnings |
| DELETE | `/api/uploads/{id}` | Delete an upload and its events |
| GET | `/api/uploads/{id}/events` | Events, with filters and paging |
| POST | `/api/uploads/{id}/detect` | Re-run detection (optional `brute_force_threshold`, `brute_force_window_minutes`) |
| GET | `/api/uploads/{id}/incidents` | Incidents for an upload, most severe first |
| GET | `/api/uploads/{id}/incidents/{incident_id}` | One incident with its detections and event IDs |
| GET | `/api/uploads/{id}/stats` | Dashboard headline numbers |
| GET | `/api/uploads/{id}/incidents/{incident_id}/evidence` | Evidence package for one incident (cached; add `?refresh=true` to rebuild) |
| GET | `/api/samples` | List bundled sample datasets |
| POST | `/api/samples/{name}/load` | Load a bundled sample dataset |

## Detection engine (Phase 2)

Detection runs automatically on upload. Five explainable rules each produce
*detections* that list the exact event IDs that triggered them and a plain-English reason:

| Rule | Fires when |
|---|---|
| `BRUTE_FORCE` | 10+ failed logins from one IP within 10 minutes (also notes a following successful login) |
| `SUSPICIOUS_POWERSHELL` | PowerShell with encoded commands, download-and-execute patterns, Office parent, or right after a post-brute-force login |
| `UNUSUAL_LOGIN` | Successful login with 2+ of: external source IP, rarely-used source for that account, outside business hours |
| `SUSPICIOUS_OUTBOUND` | Scripting engine or known-bad port connecting to an external address (flags beaconing-like regularity) |
| `SUSPICIOUS_COMMAND` | Discovery, persistence, or download-utility commands (whoami, schtasks /create, certutil -urlcache, ...) |

Detections that share a user or source IP and occur within 60 minutes are merged into one
**incident** with a type, severity and the union of their evidence event IDs. Three or more
rules together, or a brute force that succeeded followed by post-login activity, make an
`attack_chain` (severity CRITICAL). All thresholds live in `backend/app/detection/config.py`.

The sample generator's `manifest.json` records the expected incidents, and the test
suite checks the engine against it, including that normal activity produces no incidents.

## Evidence extraction (Phase 3)

For each incident, `build_evidence()` turns its detections into a numbered list of
plain-English evidence items (`EV-001`, `EV-002`, ...), each citing the exact log rows
that support it - so the final report can always answer "why did the system reach this
conclusion?" It also:

- **Looks for related context events** within 5 minutes of the incident that share the
  same user, source IP, or host but weren't matched by any detection rule. This is how
  the dropped-file event (with its SHA-256 hash) in the attack-chain scenario gets
  pulled into evidence even though no rule directly flags file creation.
- **Aggregates indicators**: unique source/destination IPs, usernames, hostnames,
  processes, file hashes, and destination ports across all cited evidence.
- **States facts only.** This layer does not interpret ("possible brute force") or map
  to MITRE ATT&CK - that's the Threat Intelligence and Investigation agents (Phases 5-6),
  which reason on top of this evidence rather than re-reading raw logs.

Results are cached per incident and invalidated automatically if detection is re-run.

## Sample datasets (`data/sample_logs/`)

| File | Scenario |
|---|---|
| `normal_activity.csv` | Ordinary staff activity + a legitimate admin PowerShell command |
| `brute_force.csv` | 30 failed logins from one IP, no success |
| `suspicious_powershell.csv` | Word spawns encoded / download-cradle PowerShell |
| `suspicious_auth_endpoint.csv` | 03:12 login from an unseen IP, then discovery commands |
| `attack_chain.csv` | Brute force -> login -> PowerShell -> C2-style traffic -> persistence |
| `security_logs.csv` / `.json` | Combined dataset (same events in both formats) |
| `spec_example_no_header.csv` | Header-less example in the original brief's format |
| `manifest.json` | Expected incidents per file (ground truth for testing) |

## Project structure

```
backend/app/     FastAPI app: config, parser, db, main
backend/app/detection/  Rules, correlation, thresholds
backend/app/evidence/   Evidence extraction, indicators, related events
backend/tests/   Unit tests
data/sample_logs Simulated datasets + manifest
scripts/         Sample data generator
docs/            Design notes and screenshots (later)
```

## Limitations and future work

_(To be completed as the project grows. Planned honest notes: CSV/JSON authentication
and process logs only; rule-based detection tuned on simulated data; LLM wording varies
between runs; no live threat-intel lookups.)_

## License

MIT - see `LICENSE`. MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation;
its data is used under MITRE's terms of use (attribution added when RAG is built).
