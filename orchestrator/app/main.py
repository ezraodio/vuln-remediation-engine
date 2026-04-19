"""FastAPI entrypoint for the vulnerability remediation orchestrator.

Endpoints:
  POST /ingest               - scanner posts findings here
  POST /verify/result        - verification CI posts re-scan results
  POST /webhooks/github      - (PRs closed/merged) optional
  GET  /stats                - machine-readable metrics
  GET  /dashboard            - HTML dashboard
  GET  /healthz
  GET  /                     - redirects to /dashboard
"""
from __future__ import annotations

import hmac
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import Settings, get_settings
from .db import Store
from .devin_client import DevinClient
from .github_client import GitHubClient
from .logging_config import configure_logging, get_logger
from .models import IngestRequest, IngestResponse, Severity
from .observability import compute_stats
from .pipeline import RemediationPipeline
from .router import Router
from .verifier import Verifier, VerifyReport

log = get_logger("api")

app = FastAPI(title="Vulnerability Remediation Orchestrator", version="0.1.0")


def _build_state(settings: Settings) -> None:
    """Wire up components once on startup and attach to app.state."""
    configure_logging()
    store = Store(settings.db_path)
    devin = DevinClient(
        api_key=settings.devin_api_key,
        org_id=settings.devin_org_id,
        base_url=settings.devin_api_base,
        mock=settings.mock_mode,
    )
    gh = GitHubClient(
        token=settings.github_token,
        base_url=settings.github_api_base,
        mock=settings.mock_mode,
    )
    router = Router(
        min_severity=Severity(settings.min_severity),
        min_cvss=settings.min_cvss,
        bump_strategy=settings.bump_strategy,
    )
    pipeline = RemediationPipeline(
        settings=settings, store=store, devin=devin, gh=gh, router=router
    )
    verifier = Verifier(store=store, devin=devin, gh=gh)
    app.state.settings = settings
    app.state.store = store
    app.state.devin = devin
    app.state.gh = gh
    app.state.pipeline = pipeline
    app.state.verifier = verifier

    templates_dir = Path(__file__).parent / "templates"
    app.state.jinja = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )


@app.on_event("startup")
async def _startup() -> None:
    _build_state(get_settings())
    log.info(
        "orchestrator_started",
        target_repo=app.state.settings.target_repo,
        mock_mode=app.state.settings.mock_mode,
        min_severity=app.state.settings.min_severity,
    )


# -------- auth helper --------

def _authz(settings: Settings, provided: str | None) -> None:
    expected = settings.ingest_shared_secret
    if not expected:
        return
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid ingest secret")


# -------- endpoints --------

@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "ts": datetime.now(UTC).isoformat()}


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse("/dashboard")


@app.post("/ingest", response_model=IngestResponse)
async def ingest(
    req: IngestRequest,
    x_ingest_secret: str | None = Header(default=None, alias="X-Ingest-Secret"),
) -> IngestResponse:
    settings: Settings = app.state.settings
    _authz(settings, x_ingest_secret)

    pipeline: RemediationPipeline = app.state.pipeline
    results = []
    for f in req.findings:
        try:
            r = await pipeline.handle_finding(f, source=req.source)
        except Exception as e:  # noqa: BLE001
            log.exception("handle_finding_failed", rule=f.rule_id, err=str(e))
            r = None
        if r is not None:
            results.append(r)
    return IngestResponse(received=len(req.findings), results=results)


@app.post("/verify/result")
async def verify_result(
    report: VerifyReport,
    x_ingest_secret: str | None = Header(default=None, alias="X-Ingest-Secret"),
) -> dict:
    settings: Settings = app.state.settings
    _authz(settings, x_ingest_secret)
    verifier: Verifier = app.state.verifier
    await verifier.handle_report(report)
    return {"ok": True, "dedupe_key": report.dedupe_key}


@app.post("/reconcile")
async def reconcile(
    x_ingest_secret: str | None = Header(default=None, alias="X-Ingest-Secret"),
) -> dict:
    """Force a one-shot reconcile (useful for demos / cron)."""
    settings: Settings = app.state.settings
    _authz(settings, x_ingest_secret)
    pipeline: RemediationPipeline = app.state.pipeline
    store: Store = app.state.store
    updated = 0
    for rec in store.list_all():
        if rec.session_id and not rec.resolved_at:
            await pipeline.reconcile_session(rec)
            updated += 1
    return {"reconciled": updated}


@app.get("/stats")
async def stats_endpoint() -> dict:
    return compute_stats(app.state.store).model_dump()


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    store: Store = app.state.store
    settings: Settings = app.state.settings
    stats = compute_stats(store)
    records = store.list_all()
    env: Environment = app.state.jinja
    template = env.get_template("dashboard.html")
    html = template.render(
        stats=stats,
        records=records,
        target_repo=settings.target_repo,
        format_duration=_format_duration,
        age=_age,
    )
    return HTMLResponse(html)


@app.get("/events")
async def events(limit: int = 100) -> dict:
    return {"events": app.state.store.recent_events(limit)}


# -------- template helpers --------

def _format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def _age(dt: datetime) -> str:
    now = datetime.utcnow()
    delta = (now - dt).total_seconds()
    return _format_duration(delta)
