# AI Cybersecurity Investigator

A software-only prototype that takes security logs, detects suspicious activity, and
(in later phases) investigates it with multiple specialised AI agents, retrieves
knowledge with RAG (MITRE ATT&CK and security documents), builds an attack timeline,
and generates an evidence-based incident report.

> **Status: Phase 4 of 10 complete** (backend, log parsing, sample data, detection engine, evidence extraction, RAG knowledge base).

> **Safety note:** all data in this repo is simulated. The tool is for defensive
> analysis. Public IPs come from reserved documentation ranges and the "encoded"
> PowerShell payload is a harmless print statement.

## Roadmap

- [x] Phase 1 - Backend, dataset, log parsing, storage
- [x] Phase 2 - Detection engine and incident creation
- [x] Phase 3 - Evidence extraction (traceable to original log rows)
- [x] Phase 4 - RAG knowledge base (MITRE ATT&CK + guidelines) with ChromaDB
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

# build the RAG knowledge base index (also happens automatically on first startup)
python ..\scripts\build_rag_index.py

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
| GET | `/api/rag/status` | Whether the knowledge base index is built, and with which backends |
| POST | `/api/rag/reindex` | (Re)build the knowledge base index |
| GET | `/api/rag/search?q=...&k=5` | Manual knowledge-base search (for testing the pipeline directly) |
| GET | `/api/uploads/{id}/incidents/{incident_id}/threat-intel` | Candidate MITRE techniques + guidance for an incident (cached; `?refresh=true` to rebuild) |
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

## RAG knowledge base (Phase 4)

`build_index()` chunks two kinds of content and embeds them into a vector store:

- **17 curated MITRE ATT&CK techniques** (`data/knowledge_base/mitre_attck.json`) -
  covering everything the detection rules can find: brute force, valid accounts,
  PowerShell abuse, obfuscation, tool transfer, C2 over web protocols, non-standard
  ports, four discovery techniques, and four persistence techniques. Descriptions are
  original paraphrases (not copied from attack.mitre.org), with technique IDs/names and
  a reference URL cited per MITRE's terms of use.
- **5 original guideline documents** (`data/knowledge_base/docs/*.md`) on responding to
  brute force, investigating PowerShell abuse, recognizing C2 beaconing, common
  persistence techniques, and telling discovery commands apart from normal admin work.

Both the embedder and the vector store are pluggable (`backend/app/rag/embeddings.py`,
`store.py`), the same modularity principle the project brief asks for with the LLM
integration:

| | Recommended (default) | Lightweight fallback |
|---|---|---|
| Embeddings | `sentence-transformers` (`all-MiniLM-L6-v2`) | `tfidf` (scikit-learn, no downloads) |
| Vector store | `chromadb` | `memory` (numpy, persisted to disk) |

Set `RAG_EMBEDDING_BACKEND` / `RAG_VECTOR_BACKEND` in `.env` to switch. The fallback
needs no model download and works fully offline - useful on the 8GB-RAM laptop this
project targets, or for quick local testing (it's what the automated test suite uses).

**How incidents get mapped to techniques:** `retrieve_for_incident()` runs one focused
retrieval query per evidence item (and per detection rule) rather than one big combined
query - this mirrors the project brief's own examples ("Observed behavior: repeated
authentication failures -> Retrieved knowledge: T1110") and retrieves far more
precisely, since unrelated evidence can't dilute the match for any one signal. Results
are clearly labeled **candidate** techniques with a confidence band (`supported` /
`potential` / `weak`, filtered below `RAG_MIN_SCORE`) and cite exactly which evidence
item(s) retrieved them - this module does retrieval only, not judgment; validating a
candidate against the specific evidence is the Threat Intelligence agent's job
(Phase 5), consistent with the brief's requirement not to present unsupported
techniques as fact.

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
backend/app/rag/        Chunking, embeddings, vector store, retrieval pipeline
data/knowledge_base/    MITRE ATT&CK subset + guideline docs (RAG source content)
backend/tests/   Unit tests
data/sample_logs Simulated datasets + manifest
scripts/         Sample data generator, RAG index builder
docs/            Design notes and screenshots (later)
```

## Limitations and future work

- CSV/JSON authentication and process logs only; other log types are designed for but
  not yet built.
- Detection rules are tuned on simulated data; a real deployment would need threshold
  tuning against an organization's actual traffic.
- The bundled MITRE ATT&CK knowledge base is a curated subset (17 techniques covering
  what the detection rules find), not the full framework.
- RAG retrieval quality depends on the embedding backend: the default
  `sentence-transformers` mode retrieves by meaning; the lightweight `tfidf` fallback
  retrieves by shared vocabulary and is noticeably weaker on paraphrased queries.
- Candidate MITRE techniques from RAG are retrieval suggestions, not verified mappings,
  until the Threat Intelligence agent (Phase 5) validates them against the evidence.
- No live threat-intelligence lookups (IP/hash reputation) - only the local knowledge
  base.
- LLM-generated wording (from Phase 5 onward) will vary between runs even when the
  underlying evidence and detections are identical.

## License

MIT - see `LICENSE`. MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation;
its data is used under MITRE's terms of use (attribution added when RAG is built).
