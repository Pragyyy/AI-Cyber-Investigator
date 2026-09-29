# AI Cybersecurity Investigator

A software-only prototype that takes security logs, detects suspicious activity, and
(in later phases) investigates it with multiple specialised AI agents, retrieves
knowledge with RAG (MITRE ATT&CK and security documents), builds an attack timeline,
and generates an evidence-based incident report.

> **Status: All 10 phases complete.** Software-only AI cybersecurity investigation platform: log ingestion, rule-based detection, evidence extraction, RAG over MITRE ATT&CK, a 4-agent LangGraph investigation pipeline, PDF reporting, a React dashboard, and a randomized evaluation of the detection engine (see `docs/EVALUATION.md`).

> **Safety note:** all data in this repo is simulated. The tool is for defensive
> analysis. Public IPs come from reserved documentation ranges and the "encoded"
> PowerShell payload is a harmless print statement.

## Roadmap

- [x] Phase 1 - Backend, dataset, log parsing, storage
- [x] Phase 2 - Detection engine and incident creation
- [x] Phase 3 - Evidence extraction (traceable to original log rows)
- [x] Phase 4 - RAG knowledge base (MITRE ATT&CK + guidelines) with ChromaDB
- [x] Phase 5 - Multi-agent workflow (LangGraph): Detection/Analysis, Evidence, Threat Intelligence agents
- [x] Phase 6 - Investigation/Correlation agent: attack timeline, sequence narrative, gaps and uncertainty
- [x] Phase 7 - Report generation (PDF)
- [x] Phase 8 - React dashboard
- [x] Phase 9 - Integration: rate-limit hardening, dataset deletion, RAG preflight check, end-to-end walkthrough
- [x] Phase 10 - Testing: randomized detection evaluation, performance benchmarks (see `docs/EVALUATION.md`)

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

# run the API - works immediately with no LLM key (LLM_PROVIDER=mock by default)
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs to try the API in your browser.

Run the tests (from `backend/`): `pytest` (or `python -m unittest discover -s tests -t .`).

### Frontend (Phase 8)

In a second terminal, with the backend still running:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The backend's default CORS settings already allow this
origin (see `CORS_ORIGINS` in `.env.example`), so no extra configuration is needed for
local development. `npm install` will generate a `package-lock.json` - commit it, so
anyone who clones the repo gets the exact same dependency versions you tested with.

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
| POST | `/api/uploads/{id}/incidents/{incident_id}/investigate` | Run the multi-agent workflow for this incident (cached; `?refresh=true` to re-run) |
| GET | `/api/uploads/{id}/incidents/{incident_id}/investigation` | Fetch a previously-run investigation without re-running it |
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

## Multi-agent investigation (Phase 5)

Three specialized agents run in sequence, each with its own role, its own prompt, and
its own LLM call - not one big prompt doing everything:

1. **Detection/Analysis agent** - reads the rule engine's output (Phase 2) and writes a
   short headline, reasoning, and initial hypothesis.
2. **Evidence agent** - reads the extracted evidence (Phase 3) and organizes it into a
   narrative, citing evidence IDs (EV-xxx) inline, and picks out the 3-6 most important
   items.
3. **Threat Intelligence agent** - reads the RAG candidate techniques (Phase 4) *plus*
   the first two agents' output, and decides, for each candidate, whether the evidence
   actually supports it (verdict `supported` / `potential` / `weak`, with a
   justification citing specific evidence). It's expected and correct for it to reject
   weak candidates rather than assign every technique RAG retrieved - this is what the
   project brief's "should not blindly assign techniques" requirement means in
   practice.

Agent 3 genuinely depends on Agents 1 and 2's output (their hypothesis and prioritized
evidence are part of its prompt), so this is a real information handoff through shared
graph state, not three independent calls run back-to-back for appearances.

**Works with no API key.** `LLM_PROVIDER=mock` (the default) uses a deterministic,
data-only fallback for every agent, so the whole pipeline - including the tests - runs
with zero setup and zero cost. Every agent's output is tagged `"generated_by": "llm"`
or `"fallback"` in the response, so it's always clear which agents used real reasoning.
The same fallback also kicks in automatically if a real provider is configured but a
call fails (bad key, network error, rate limit) - a single agent's hiccup never crashes
the investigation.

**To use a real model**, set in `.env`:
```
LLM_PROVIDER=anthropic          # or: openai_compatible
LLM_MODEL=claude-haiku-4-5-20251001
LLM_API_KEY=sk-...
```
`openai_compatible` works with any OpenAI-style `/chat/completions` endpoint - useful
free-tier options include [Groq](https://console.groq.com) (fast, generous free tier)
and [OpenRouter](https://openrouter.ai). Set `LLM_BASE_URL` accordingly, e.g.
`https://api.groq.com/openai/v1`.

**Orchestration** is [LangGraph](https://github.com/langchain-ai/langgraph) by default
(`AGENT_GRAPH_BACKEND=langgraph`), with a dependency-light `sequential` fallback that
runs the identical node logic without needing the package installed - this is what the
automated test suite uses, and it's why the agent logic itself is fully tested even in
environments without `langgraph`.

## Investigation and correlation (Phase 6)

A fourth agent - **Investigation/Correlation**, the "main investigator" from the
project brief's architecture diagram - now runs last in the chain, after Detection,
Evidence, and Threat Intelligence. It receives all three earlier agents' output plus a
**deterministic timeline** built in pure Python (`app/agents/timeline.py`, no LLM
involved) before it ever calls a model:

- **One phase per detection** (each detection is already a time-bounded, grouped
  cluster of related events from the rule engine), ordered by time.
- **Phase labels prefer a validated MITRE tactic** from the Threat Intelligence agent's
  output where one covers that phase's evidence (e.g. "Command and Control" from a
  supported T1071.001 match), falling back to a generic rule-based label otherwise.
- **Gaps between phases are computed and flagged** when notable (>= 2 minutes with no
  observed activity) - these are exactly the kind of silence a real analyst would want
  called out, since they may hide unlogged attacker actions.

The agent's LLM step then synthesizes all of this into:
- `attack_sequence_narrative` - prose describing the phases in order
- `affected_scope` - which accounts/hosts were involved
- `investigation_summary` - a short overall analyst summary
- `gaps_and_uncertainty` - explicitly surfaces rejected/low-confidence technique
  matches and unexplained timing gaps, rather than presenting a falsely tidy picture
- `recommended_priority`

Like the other three agents, it degrades to a deterministic, fact-only fallback (same
`"generated_by": "llm"` / `"fallback"` / `"fallback_parse_error"` tagging) if no LLM is
configured or a call fails - and a `debug_note` is attached to the trace entry on a
parse failure, showing a preview of the raw response and the exact parse error, so a
bad response from a reasoning model's verbose "thinking" output (a real issue hit
during development with an open-weights model on Groq) is diagnosable instead of a
silent mystery.

This completes the multi-agent pipeline end to end: `/investigate` now returns
`detection_analysis`, `evidence_summary`, `threat_intel`, `timeline`, and
`investigation` together - everything Phase 7's PDF report will need, with nothing left
to compute at report-generation time beyond formatting.

## Report generation (Phase 7)

Two endpoints turn a completed investigation into a report:

| Method | Path | What it does |
|---|---|---|
| GET | `/api/uploads/{id}/incidents/{incident_id}/report/data` | The normalized report data as JSON (for a future dashboard report view) |
| POST | `/api/uploads/{id}/incidents/{incident_id}/report` | Generates and downloads the PDF report |

Both require `/investigate` to have already been run for that incident (409 if not) -
report generation deliberately never triggers a fresh LLM run as a side effect of a
download click; it reports on an investigation that already happened.

**`app/report/builder.py`** assembles the normalized report structure purely by
organizing what Phases 2-6 already computed - no new analysis happens here. The one
new piece is **Recommended Actions** (`app/report/actions.py`): a fixed, reviewed
lookup table of 2-4 concrete actions per detection rule, deduplicated across the
incident's rules and always closed with two universal actions (preserve logs, document
findings). This is deliberately **not** LLM-generated - recommended actions are
operational guidance with real consequences if wrong, so, like detection and evidence,
they come from a reviewed table rather than a model's improvisation.

**`app/report/pdf.py`** renders the PDF with reportlab: a summary table, the incident
timeline, evidence with indicators of compromise, the MITRE ATT&CK mapping (color-coded
by verdict), the AI investigation narrative, RAG sources actually retrieved, and
recommended actions - matching the project brief's report format section by section.

A real bug worth knowing about if you extend this: reportlab's `Paragraph` markup
parser treats `&`, `<`, and `>` as the start of XML markup. Since report content
includes LLM-generated text (which can absolutely contain any of those), every piece of
dynamic text is passed through an `_esc()` helper before reaching a `Paragraph` - this
was caught by actually rendering a PDF and reading the text back out with `pypdf` during
development (a heading literally read "MITRE ATT&CK; Mapping" before the fix), and is
covered by a regression test plus a deliberate stress test with `<script>` tags and
stray `&`/`<`/`>` characters.

## React dashboard (Phase 8)

A two-page dashboard (Vite + React + React Router), talking to the backend entirely
through the real endpoints built in Phases 1-7 - every button performs the actual
action it describes, per the project brief's requirement that this not be a UI mockup:

- **Landing** (`/`) - upload a CSV/JSON log file, or load one of the bundled sample
  datasets. Both actually call `POST /api/uploads` or `POST /api/samples/{name}/load`.
- **Dashboard** (`/uploads/:uploadId`) - the four headline stat cards, a severity
  distribution chart (Recharts), and the incident table, all from
  `GET /api/uploads/{id}/stats` and `.../incidents`. Clicking a row navigates to detail.
- **Incident Detail** (`/uploads/:uploadId/incidents/:incidentId`) - incident header,
  evidence and indicators of compromise (shown immediately - these don't need an LLM),
  an **Investigate** button that calls `POST .../investigate` and then renders the full
  multi-agent output (timeline, attack sequence, MITRE ATT&CK mapping, RAG sources,
  recommended actions), and a **Generate Report** button that downloads the actual PDF
  from Phase 7. A small badge next to each agent's output shows whether it came from a
  real LLM call or the deterministic fallback (`generated_by`), surfacing the
  pipeline's own transparency tagging directly in the UI.

The Incident Detail page's on-screen "investigated" view is built from
`GET .../report/data` (Phase 7's normalized report structure) rather than re-deriving
timeline/MITRE/evidence formatting client-side - one source of truth for both the PDF
and the on-screen view.

### A note on how this phase was verified

Every backend phase (1-7) was verified by actually running the code and its test
suite. This environment has no network access for `npm install`, so that same
verification wasn't possible here: I could not install React/Vite/Recharts or run the
dev server. What I *could* do, and did: used `esbuild` (bundled with a pre-installed
tool in this container) to syntax-check every file individually, then did a full bundle
build resolving all local cross-file imports (catching import-path typos and
export/import mismatches) while treating npm packages as external - both passed clean.
That check also caught one real bug during development: `useEffect(load, [dep])`
passed a function that implicitly returns a Promise from a `.then()` chain, which
React logs a dev-mode warning about; fixed to `useEffect(() => { load(); }, [dep])` in
both places it occurred.

That's meaningfully more scrutiny than "written but never checked" - but it is **not**
the same as actually running it in a browser and clicking through the upload -> 
investigate -> report flow. Please run `npm install && npm run dev`, click through that
flow, and report back anything that looks wrong (a blank section, a console error, a
button that doesn't do what its label says) - this is the one phase where that report
is genuinely the first real-world test.

## Integration pass (Phase 9)

With every piece built (Phases 1-8), this phase closed the gaps between them rather
than adding new capability:

**Rate-limit hardening.** Real use with a free-tier provider (Groq) surfaced 429s
under a burst of 4 agent calls per incident. Two independent fixes, both opt-in via
`.env` and both no-ops for the default mock provider (so local dev and the test suite
stay fast):
- `LLM_REQUEST_DELAY_SECONDS` - a proactive pause between agent calls.
- `LLM_MAX_RETRIES` / `LLM_RETRY_BACKOFF_SECONDS` - a reactive retry-with-backoff on a
  429 specifically (honoring the provider's own `Retry-After` header when it sends
  one), so a burst that slips past the delay still recovers instead of falling back.

**Frontend/backend wiring audit.** Every function in `frontend/src/api.js` was checked
against the actual FastAPI routes - all matched. Two functions existed but weren't
called from any component yet (dead code, not a bug): `deleteUpload` is now wired into
the dataset switcher (a ✕ button per entry, with a confirm step); `getRagStatus` now
drives a preflight warning on the Landing page if the knowledge base index hasn't been
built yet, rather than letting someone discover that as a confusing 409 several clicks
into Investigate. `getEvents` (raw paginated event browsing) remains unused - the
backend endpoint exists and works, but no UI was built for it; that's a real scope gap,
not a wiring bug, and would be a reasonable place to extend the dashboard next.

### End-to-end walkthrough

This is the project brief's own demonstration flow (Section 16), mapped to what to
actually click:

1. Start the backend (`uvicorn app.main:app --reload`) and frontend (`npm run dev`).
2. Open http://localhost:5173 - the **Landing** page.
3. Load `attack_chain.csv` from the sample dropdown (or upload your own CSV/JSON).
4. You land on the **Dashboard**: stat cards, severity chart, and one CRITICAL
   incident already detected - purely rule-based, no LLM involved yet.
5. Click the incident row to open **Incident Detail**. Evidence and indicators of
   compromise are already visible.
6. Click **Investigate**. This runs the real 4-agent LangGraph chain (Detection ->
   Evidence -> Threat Intelligence -> Investigation/Correlation).
7. The page now shows the executive summary, timeline, MITRE ATT&CK mapping, RAG
   sources, and recommended actions - each agent's output tagged `● LLM` or
   `○ Deterministic fallback`.
8. Click **Generate Report (PDF)** - downloads the real PDF built in Phase 7.
9. Use **Switch dataset** in the header to move between uploads, or the ✕ to delete one.

## Testing at scale (Phase 10)

The five bundled sample scenarios (below) are fixed templates - passing them proves the
engine handles those specific inputs, not that it generalizes. Phase 10 adds a
randomized evaluation that generates many varied instances of each attack, embedded in
realistic background activity (including deliberately tricky legitimate admin activity
that looks similar to early attack stages), and scores the real parser + detection code
against known ground truth:

```
python scripts/evaluate_detection.py                    # full report, printed
python scripts/evaluate_detection.py --markdown docs/EVALUATION.md   # regenerate the doc
python scripts/evaluate_detection.py --seed 7 --per-attack 200       # larger run
```

Deterministic for a given `--seed`. A small-N version of the same evaluation runs as
part of the normal test suite (`backend/tests/test_evaluation.py`) as a regression
guard - it does not assert "false positives should be near zero" (that would assert
something false about the current engine), it pins today's measured behavior as a
baseline so a large unexplained swing gets caught in review.

**Read `docs/EVALUATION.md` for the full results**, including two findings worth
knowing before presenting this project: attack detection is 100% across all four
scenario types at 150 randomized instances each (one single-instance classification
labeling nuance is traced and explained in detail), but roughly a third of completely
ordinary days produce one false positive from the `UNUSUAL_LOGIN` rule - and the report
explains precisely why (remote/hybrid worker logins look statistically "rare" within a
single day of data) and lays out concrete tuning options without unilaterally changing
detection behavior. It also documents known evasion cases (low-and-slow brute force,
distributed brute force, beaconing over a standard port) as honest, named limitations
rather than hiding them, and includes performance benchmarks up to 100,000 events.

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
backend/app/llm/        Pluggable LLM provider (mock, Anthropic, OpenAI-compatible)
backend/app/agents/     Multi-agent graph: state, prompts, fallback, nodes, timeline, LangGraph/sequential runner
backend/app/report/     Report data builder, recommended actions, PDF rendering
data/knowledge_base/    MITRE ATT&CK subset + guideline docs (RAG source content)
backend/tests/   Unit tests
data/sample_logs Simulated datasets + manifest
scripts/         Sample data generator, RAG index builder
docs/            Design notes and screenshots (later)
reports/         Generated PDF reports (gitignored)
frontend/src/            App.jsx, main.jsx, api.js, index.css
frontend/src/components/ Reusable UI: Header, tables, badges, timeline, charts, panels
frontend/src/pages/      Landing, Dashboard, IncidentDetail
```

## Limitations and future work

- No UI for browsing raw events directly (the backend's paginated/filtered events
  endpoint works and is used internally, but the dashboard only surfaces events
  through incidents and evidence, not a standalone event browser).
- CSV/JSON authentication and process logs only; other log types are designed for but
  not yet built.
- Detection rules are tuned on simulated data; a real deployment would need threshold
  tuning against an organization's actual traffic.
- The bundled MITRE ATT&CK knowledge base is a curated subset (17 techniques covering
  what the detection rules find), not the full framework.
- RAG retrieval quality depends on the embedding backend: the default
  `sentence-transformers` mode retrieves by meaning; the lightweight `tfidf` fallback
  retrieves by shared vocabulary and is noticeably weaker on paraphrased queries.
- Candidate MITRE techniques from RAG are retrieval suggestions; the Threat Intelligence
  agent validates or rejects them, but even a validated mapping is the model's judgment,
  not a guarantee.
- No live threat-intelligence lookups (IP/hash reputation) - only the local knowledge
  base.
- The React dashboard (Phase 8) could not be installed or run in the development environment (no network access for npm); it was syntax- and bundle-checked with esbuild but not executed in a real browser before being handed off.
- LLM-generated wording will vary between runs (and between providers/models) even when
  the underlying evidence and detections are identical. Everything the wording is based
  on - the detections, evidence, and candidate techniques - is deterministic; only the
  prose describing it varies.
- The default `mock` LLM provider produces clearly-labeled, deterministic, data-only
  text rather than genuine reasoning - useful for development, testing, and demoing
  without cost, but the analytical quality of the write-up depends on switching to a
  real model.

## License

MIT - see `LICENSE`. MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation;
its data is used under MITRE's terms of use (attribution added when RAG is built).
