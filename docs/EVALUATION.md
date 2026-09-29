# Detection Engine Evaluation (Phase 10)

This is a randomized evaluation of the rule-based detection engine (Phase 2), run
through the real parser and detection code - the same path an uploaded file takes -
against synthetic data with known ground truth. It exists because the five bundled
sample scenarios are fixed templates: passing them proves the engine handles *those*
specific inputs, not that it generalizes.

Regenerate with `python scripts/evaluate_detection.py` (deterministic for a given
`--seed`). A small-N version of this same evaluation runs as part of the normal test
suite (`backend/tests/test_evaluation.py`) as a regression guard.

Seed `42` - fully reproducible (`python scripts/evaluate_detection.py --seed 42`).

### Detection of randomized attacks

Each attack instance has randomized parameters and is shuffled into a fresh normal working day. "Detected" means an incident overlaps the attack's events; "correct type" means that incident was classified as the intended scenario; "fragmented" means the attack was split across more than one incident.

| Scenario | Instances | Detected | Correct type | Fragmented |
|---|---|---|---|---|
| brute_force | 150 | 150 (100.0%) | 150 (100.0%) | 0 |
| suspicious_powershell | 150 | 150 (100.0%) | 149 (99.3%) | 0 |
| suspicious_authentication | 150 | 150 (100.0%) | 150 (100.0%) | 0 |
| attack_chain | 150 | 150 (100.0%) | 150 (100.0%) | 0 |

### False alarms on days with no attack

"Any incident" counts every incident, including LOW-severity ones an analyst would treat as informational. "MEDIUM or higher" is the rate that would actually page someone.

| Day type | Days | Any incident | MEDIUM or higher | Incidents (LOW / MED / HIGH / CRIT) |
|---|---|---|---|---|
| Ordinary working day | 300 | 105 (35.0%) | 105 (35.0%) | 0 / 128 / 0 / 0 |
| Working day + legitimate IT-admin activity | 300 | 300 (100.0%) | 289 (96.3%) | 21 / 305 / 77 / 32 |

False incidents on admin-activity days, by the rules that produced them:

- `UNUSUAL_LOGIN`: 135
- `SUSPICIOUS_COMMAND`: 105
- `SUSPICIOUS_POWERSHELL + SUSPICIOUS_COMMAND`: 65
- `SUSPICIOUS_OUTBOUND + SUSPICIOUS_COMMAND`: 51
- `SUSPICIOUS_POWERSHELL + SUSPICIOUS_OUTBOUND + SUSPICIOUS_COMMAND`: 32
- `SUSPICIOUS_POWERSHELL`: 21
- `SUSPICIOUS_OUTBOUND`: 17
- `SUSPICIOUS_POWERSHELL + SUSPICIOUS_OUTBOUND`: 9

False incidents on ordinary days, by the rules that produced them:

- `UNUSUAL_LOGIN`: 128

Across the 600 attack days, the background activity alone produced 241 additional false incident(s).

### Known evasion cases (documented limitations)

| Case | Designed to catch? | Detected? | Why |
|---|---|---|---|
| Low-and-slow brute force (30 failures, 1 per 90 s) | no | no | Per-IP rule needs 10 failures inside any 10-minute window. |
| Distributed brute force (20 IPs x 3 failures, one account) | no | no | The rule counts per source IP, never per target account. |
| Beaconing over port 443 by a non-scripting process | no | no | Outbound rule only considers scripting engines and known-bad ports. |
| Password spraying (1 IP, 25 accounts, 1-2 failures each) | yes | yes | The per-IP rule aggregates across accounts, so this is caught. |
| Legitimate user locked out (12 failures from own workstation, then success) | no | yes | Indistinguishable from a successful brute force using only these log fields. |

### Brute-force threshold boundary

Failed logins from one IP, 5 seconds apart (rule: 10 within 10 minutes):

| Failures | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|---|---|---|---|
| Detected | no | no | no | no | no | yes | yes | yes | yes | yes |

## The one finding worth reading closely: `UNUSUAL_LOGIN` false positives

On a completely ordinary working day with no attack, roughly a third of runs produce
one false incident, and every single one traces to the `UNUSUAL_LOGIN` rule - never
brute force, PowerShell, outbound, or command detections misfiring on benign activity.

**The mechanism:** `UNUSUAL_LOGIN` treats a source IP as "rare" when it accounts for a
small fraction of that user's logged activity. A remote or hybrid worker's login event
carries their home/VPN IP, but everything they do *after* logging in typically gets
logged under their normal internal workstation IP (VPN and remote-desktop traffic looks
local once connected). Within a single day of data, that means the login IP is - by
definition - the *only* event using that IP, so it always looks "rare," regardless of
whether that person has worked remotely for years. This isn't an artifact of the test
data; it's an accurate model of how many real logging setups actually behave.

**Why this matters:** any organization with remote or hybrid staff should expect this
rule to fire on legitimate logins at a meaningfully high rate, not just on attacks.

**Why it wasn't silently changed:** fixing this properly means tracking each user's
known-good source IPs over a longer historical window (weeks, not one day's batch) -
a real design decision (What counts as "known"? How long is "history"? Where does that
state live?) that belongs to whoever owns the detection rules, not something to change
quietly while writing an evaluation report. The concrete options, roughly in order of
effort: (1) require more than one signal to hit MEDIUM severity for this rule
specifically, trading detection sensitivity for fewer alerts; (2) maintain a persistent
per-user "seen source IPs" store across uploads rather than judging rarity from a single
batch; (3) accept the trade-off and document it as an operational reality, the same way
real EDR/SIEM products tune these rules against an organization's actual traffic over
time. This report documents the finding precisely enough to act on later; it doesn't
decide which option to take.

## A second, smaller finding: one classification label out of 600 attack instances

At larger sample sizes, `suspicious_powershell` scored 149/150 (99.3%) on "correct type"
rather than 100%. Tracing that one case: **no evidence was lost or missed.** The
PowerShell attack was injected for a randomly-chosen user who, coincidentally, also
had an unrelated `UNUSUAL_LOGIN` false positive of their own in that day's background
activity. Because both detections shared the same username within the 60-minute
correlation window, they were correctly merged into one incident - the merge itself is
right; two closely-timed, same-user findings genuinely are more useful presented
together than apart. The incident's `detections` list contains both, in full. The only
"miss" is that this report's scoring counts it as `suspicious_authentication` (the
higher-precedence rule in `correlate.py`'s naming order) rather than
`suspicious_powershell`, and its actual title -
*"Suspicious Authentication Followed by Endpoint Activity"* - is, if anything, a more
accurate description of what happened than either single label. This is a labeling
edge case in a simple precedence heuristic, triggered by test-harness randomness
(a coincidental same-user collision, ~0.2% of instances at this sample size), not a
detection failure.

## Performance at scale

Your original spec asked for a system that could "given a set of cybersecurity logs,
automatically detect suspicious activity" - and the first question in this whole
project was whether an 8GB-RAM laptop could handle it. Measured on this development
machine (parsing + detection only, no LLM calls):

| Events | Parse time | Detection time | Incidents found |
|---|---|---|---|
| 5,000 | 0.11s | 0.03s | 98 |
| 20,000 | 0.43s | 0.08s | 98 |
| 50,000 | 1.15s | 0.93s | 659 |
| 100,000 | 2.20s | 3.45s | 1,295 |

Both stages scale roughly linearly with event count, well within the "thousands to
tens of thousands of events" scope discussed at the start of this project. Detection
time grows a bit faster than parse time at higher volumes because the correlation step
compares detections pairwise within each actor's activity - not a concern at this
scale, but the first place to look if a future dataset is 10x larger again. The LLM
agent steps (Phases 5-6) dominate total wall-clock time in practice - each real model
call takes seconds, run sequentially across 4 agents per incident - not the
deterministic detection engine measured here.

## What this evaluation does not cover

- **Detection quality on real-world messy data** - typos in fields, missing values
  beyond what the parser already tolerates, clock skew, timezone mixing. The parser's
  own tolerance (Phase 1) is unit-tested separately; this evaluation assumes clean,
  well-formed rows throughout.
- **Adversarial evasion by a motivated attacker** - the evasion cases here are
  parameter variations (slower, distributed, different port), not an attacker actively
  reading these rules and crafting traffic specifically to slip under each threshold.
- **The AI agents (Phases 5-6) or RAG retrieval (Phase 4)** - this evaluation is scoped
  to the deterministic rule engine only, which is what it's possible to score against
  exact ground truth. LLM-generated narrative text doesn't have a single correct
  answer to score against the way "was this incident detected" does.

(Generated in 7.0s)
