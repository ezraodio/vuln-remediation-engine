# Vulnerability Remediation Engine

An event-driven automation that continuously scans a target repository for
vulnerabilities, opens tracking issues, and dispatches Devin sessions to
remediate them — with an observability surface so an engineering leader can
actually tell whether it is working.

Target repo in this demo: [`ezraodio/superset`](https://github.com/ezraodio/superset) (fork of Apache Superset).

## What it does

```
┌────────────────────┐   findings   ┌──────────────────────────────┐   v3 API   ┌────────────┐
│  GitHub Action     │─────────────▶│  Orchestrator (FastAPI)      │──────────▶│  Devin     │
│  (scheduled +      │              │  • /ingest    (scanner POST) │           │  session   │
│   dispatch)        │              │  • /verify/result (re-scan)  │           └────────────┘
│  pip-audit +       │              │  • /stats     (JSON)         │                 │
│  bandit            │◀─┐           │  • /dashboard (HTML)         │  REST API       │
└────────────────────┘  │           │  • SQLite dedupe + routing   │─────────┐       │
                        │           └──────────────────────────────┘         │       │
                        │ re-scan          │                                 ▼       ▼
            ┌───────────┴──────────┐       │                         ┌──────────────────────┐
            │ verify-devin-pr.yml  │       │                         │  GitHub  issues + PRs │
            │ (runs on PR)         │       └────────────────────────▶│  in ezraodio/superset │
            └──────────────────────┘                                 └──────────────────────┘
```

1. A scheduled GitHub Action in the target repo runs `pip-audit`, `bandit`,
   and friends, normalizes findings, and POSTs them to the orchestrator.
2. The orchestrator deduplicates each finding across three layers:
   - **SQLite** (local remediation store, stable hash of repo + rule + package/location)
   - **GitHub** (searches for an open issue carrying the same dedupe key in its body)
   - **Devin** (searches the org's sessions for an active one tagged `vuln:<key>`)
3. Findings below the severity/CVSS floor get recorded and silently dropped.
4. Surviving findings are **routed**:
   - `SAST` findings → always dispatched to Devin (code judgment required).
   - Dep CVEs with no patched version → Devin (needs first-party mitigation).
   - Dep CVEs with a patched version → Devin with the lowest-fix bump target in the prompt, so Devin upgrades AND re-runs the test suite against the new version.
5. The orchestrator creates a tracking issue in the target repo with the
   dedupe key embedded in the body and labels like
   `devin-remediation`, `severity:high`.
6. A Devin session is created via **v3** with tags
   (`vuln:<key>`, `rule:<id>`, `severity:<x>`, `repo:<o/r>`) so subsequent
   dedupe queries are fast.
7. When Devin opens a PR, `verify-devin-pr.yml` runs the scanner against the
   PR's branch, reads the orchestrator's metadata out of the tracking issue
   body, filters scanner output down to *the specific rule/package we asked
   Devin to fix* (ignoring unrelated pre-existing findings in the target
   repo), and POSTs the outcome to `/verify/result`. On `still_vuln` the
   orchestrator calls `POST /v3/.../sessions/{id}/message` to feed the
   failing scanner output back into the same Devin session so it iterates
   instead of spawning a new one. On `clean` the issue is closed and the
   record transitions to `VERIFIED_FIXED`.

## Why this uses Devin specifically (and not just scripts)

- **Code-judgment fixes**: B324 (weak MD5) and B608 (hardcoded SQL) findings
  in Superset require reading call-sites to decide whether the hash is used
  for security, whether the SQL construction needs parametrization, or
  whether a narrowly-scoped `# nosec` with justification is correct. A script
  can't do this; a junior engineer can, and so can Devin.
- **Iterative remediation**: the orchestrator uses the Devin
  `send_message` endpoint to feed failing re-scan output back into the
  *same* running session, so Devin can revise its patch without losing
  context. Basic bots start over from scratch.
- **Programmatic control plane**: every step (create session, poll status,
  pick up the PR, feed verification back) is driven through the v3 API. The
  orchestrator is a pure orchestrator; the expertise lives in Devin.

## Observability ("how would a VP know this is working?")

- `GET /stats` — JSON metrics:
  - total findings, by severity, by status
  - active Devin sessions, PRs opened, verified fixed, verification failed
  - dedupe hit count, success rate, **median and p90 MTTR**
- `GET /dashboard` — auto-refreshing HTML rendering of `/stats` plus a live
  table of every remediation with links out to the GitHub issue, Devin
  session, and PR.
- `GET /metrics` — Prometheus exposition: counters (ingested, dispatched,
  verified), histograms (verify latency), and point-in-time gauges
  (active sessions, needs_attention, stale PRs).
- `GET /events?limit=N` — structured audit log of every state transition.
- All app logs are JSON with a `dedupe_key` + `request_id` correlation pair;
  `request_id` is minted at `/ingest` (or accepted via `X-Request-Id`) and
  flows into the Devin session tags and the tracking issue body.

**Scaling limitations (read before wiring a scrape interval):** `/stats`,
`/dashboard`, and `/metrics` each call `store.list_all()` — a full SQLite
table scan — on every hit. That's deliberately simple for a single-process
orchestrator in the low-thousands-of-records regime this system targets.
At high record counts or an aggressive (sub-15s) Prometheus scrape interval,
this will show up in CPU and request latency; the mitigation is either a
cached gauge snapshot refreshed on ingest/reconcile, or moving the store to
Postgres with indexed aggregation queries.

## Running it

### 1. Simulated (offline, no API calls)

```bash
cp .env.example .env
# Set MOCK_MODE=true in .env
docker compose up -d --build
./scripts/simulate.sh                 # POSTs the fixture findings
open http://localhost:8080/dashboard
```

In mock mode the Devin + GitHub clients are stubbed out, so you can exercise
dedupe/routing/state-transitions without spending ACUs or touching real
repos.

### 2. End-to-end (real Devin + real GitHub)

```bash
cp .env.example .env
# Set DEVIN_API_KEY (cog_...), DEVIN_ORG_ID (org-...), GITHUB_TOKEN,
# TARGET_REPO (e.g. ezraodio/superset), INGEST_SHARED_SECRET, MOCK_MODE=false
docker compose up -d --build

# Option A — fire a single fixture finding (useful for a controlled demo):
./scripts/simulate.sh sast

# Option B — turn on the real scan loop in the target repo:
#   cp scanner/security-scan.yml  ../superset/.github/workflows/
#   cp scanner/verify-devin-pr.yml ../superset/.github/workflows/
#   (set ORCHESTRATOR_URL + INGEST_SHARED_SECRET as repo Actions secrets)
#   Then trigger the workflow from the Actions tab.
```

### 3. Dashboard

<!-- The dashboard screenshot is regenerated on each demo run; see /dashboard live -->
`/dashboard` auto-refreshes every 10 seconds and shows the full remediation
queue end-to-end.

## Configuration (`.env`)

See `.env.example` for the full list. Most important knobs:

| Var | Default | What |
| --- | --- | --- |
| `MIN_SEVERITY` | `HIGH` | Drops anything strictly below this |
| `MIN_CVSS` | `7.0` | Still accepts `MEDIUM` findings if CVSS is above this |
| `TARGET_BASE_BRANCH` | `main` | Default branch on the target repo (Superset fork uses `master`) |
| `DRY_RUN` | `false` | Creates issues but does not dispatch Devin |
| `MOCK_MODE` | `false` | Stubs Devin + GitHub clients for local demos |
| `INGEST_SHARED_SECRET` | — | Required on `/ingest` and `/verify/result` |

## Repo layout

```
.
├── orchestrator/                   # FastAPI service (containerized)
│   ├── app/
│   │   ├── main.py                 # HTTP surface
│   │   ├── pipeline.py             # ingest → dedupe → route → dispatch
│   │   ├── verifier.py             # post-PR re-scan feedback loop
│   │   ├── router.py               # severity + bump-vs-Devin decision
│   │   ├── devin_client.py         # Devin v3 API client
│   │   ├── github_client.py        # issues + PR lookup
│   │   ├── db.py                   # SQLite remediation store
│   │   ├── prompts.py              # Devin prompt templates
│   │   ├── observability.py        # /stats aggregation
│   │   ├── models.py, config.py, logging_config.py
│   │   └── templates/dashboard.html
│   ├── tests/
│   ├── Dockerfile
│   └── pyproject.toml
├── scanner/                         # workflows to drop into the TARGET repo
│   ├── security-scan.yml            # daily + dispatchable scanner
│   └── verify-devin-pr.yml          # re-scans PRs opened by Devin
├── examples/                        # JSON fixture findings for simulate.sh
├── scripts/
│   └── simulate.sh                  # POST fixture findings to orchestrator
├── docker-compose.yml
└── .github/workflows/ci.yml         # lint + tests + docker build
```

## Design decisions worth calling out

- **Dedupe includes a marker inside the issue body**, not just the label —
  labels can be shared across many findings, a hash marker can't.
- **Record-before-dispatch**: the orchestrator writes the SQLite row with
  status=`DISPATCHED` *before* calling the Devin API, so a crash mid-call
  doesn't result in a session we can't locate later.
- **Auth is a shared secret on ingest** (HMAC-compare), not OAuth. The
  scanners are trusted ingesters inside our own pipeline; this keeps the
  scanner YAML ~100 lines and removes a category of deploy friction.
- **Never auto-merge**. The orchestrator opens the PR and, when verified,
  closes the tracking issue — but a human still merges.
- **Failure path feeds back, doesn't fan out**. If the re-scan says the fix
  didn't work, we `send_message` into the same session. One session per
  finding, always.

## Next steps (if this were going to production)

- Optional Dependabot webhook ingress (real-time for graph-level CVEs).
- Per-repo concurrency caps + an ACU budget guard.
- Optional direct-bump-PR path (via `gh pr create`) without dispatching Devin,
  for shops that want Dependabot-style behavior for the trivial 80%.
- Persist metrics to Postgres + Grafana instead of the SQLite + dashboard.
