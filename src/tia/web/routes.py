"""ページと部品の経路（GET）。"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from tia import db
from tia.analysis import cases
from tia.web import queries
from tia.web.core import WebState, page, render
from tia.web.health import collectors_status


def filters_of(request: Request, state: WebState, now: datetime) -> dict:
    """URL の引数 state、day、host。形が違えば 400。"""
    tz = queries.zone(state.cfg)
    params = request.query_params
    day = queries.parse_day(params.get("day"), now, tz)
    chosen = params.get("state") or None
    if chosen and chosen not in queries.FILTERS:
        raise HTTPException(400, "state は wait、run、done、fail、skip のどれかで書く")
    host = (params.get("host") or "").strip()[:253] or None
    today = now.astimezone(tz).date() == day
    rest = urlencode({k: v for k, v in (("day", None if today else day.isoformat()), ("host", host)) if v})
    return {"day": day, "state": chosen, "host": host, "day_text": day.isoformat(), "today": today, "rest": rest}


def inbox_context(conn, request: Request, state: WebState, selected: int | None) -> dict:
    now = state.clock()
    chosen = filters_of(request, state, now)
    sections = queries.sections(conn, now, state.cfg, chosen["day"], state=chosen["state"], host=chosen["host"])
    detail = queries.detail(conn, selected, now, state.cfg, runner=state.probes) if selected else None
    if selected and detail is None:
        raise HTTPException(404, f"I-{selected:04d} はない")
    return {"filters": chosen, "sections": sections, "rail": queries.rail(conn, now, state.cfg, chosen["day"]),
            "band": queries.band(conn, now, state.cfg, chosen["day"]), "detail": detail, "selected": selected,
            "queue": queries.queue_summary(conn, now, state.cfg), "collectors": collectors_status(conn, now, state.cfg)}


def register(app: FastAPI, state: WebState) -> None:
    @app.get("/", response_class=HTMLResponse)
    def inbox(request: Request):
        with closing(db.connect(state.db_path)) as conn:
            return page(state, request, "inbox.html", **inbox_context(conn, request, state, None))

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    def incident_page(request: Request, incident_id: int):
        with closing(db.connect(state.db_path)) as conn:
            return page(state, request, "inbox.html", **inbox_context(conn, request, state, incident_id))

    @app.get("/partials/rail", response_class=HTMLResponse)
    def partial_rail(request: Request):
        now = state.clock()
        chosen = filters_of(request, state, now)
        with closing(db.connect(state.db_path)) as conn:
            return page(state, request, "partials/rail.html", filters=chosen,
                        rail=queries.rail(conn, now, state.cfg, chosen["day"]),
                        queue=queries.queue_summary(conn, now, state.cfg), with_banner=True)

    @app.get("/partials/band", response_class=HTMLResponse)
    def partial_band(request: Request):
        now = state.clock()
        chosen = filters_of(request, state, now)
        with closing(db.connect(state.db_path)) as conn:
            return page(state, request, "partials/band.html", filters=chosen,
                        band=queries.band(conn, now, state.cfg, chosen["day"]))

    @app.get("/partials/list", response_class=HTMLResponse)
    def partial_list(request: Request, selected: int | None = None):
        now = state.clock()
        chosen = filters_of(request, state, now)
        with closing(db.connect(state.db_path)) as conn:
            sections = queries.sections(conn, now, state.cfg, chosen["day"], state=chosen["state"], host=chosen["host"])
        return page(state, request, "partials/list.html", filters=chosen, sections=sections, selected=selected)

    @app.get("/partials/health", response_class=HTMLResponse)
    def partial_health(request: Request):
        now = state.clock()
        with closing(db.connect(state.db_path)) as conn:
            collectors = collectors_status(conn, now, state.cfg)
        return page(state, request, "partials/health.html", collectors=collectors)

    @app.get("/partials/incidents/{incident_id}", response_class=HTMLResponse)
    def partial_incident(request: Request, incident_id: int):
        with closing(db.connect(state.db_path)) as conn:
            detail = queries.detail(conn, incident_id, state.clock(), state.cfg, runner=state.probes)
        if detail is None:
            raise HTTPException(404, f"I-{incident_id:04d} はない")
        return page(state, request, "partials/incident.html", detail=detail)

    @app.get("/partials/incidents/{incident_id}/case-form", response_class=HTMLResponse)
    def partial_case_form(request: Request, incident_id: int):
        with closing(db.connect(state.db_path)) as conn:
            detail = queries.detail(conn, incident_id, state.clock(), state.cfg, runner=state.probes)
            if detail is None:
                raise HTTPException(404, f"I-{incident_id:04d} はない")
            draft = cases.draft(conn, incident_id, analysis_id=queries.shown_analysis_id(conn, incident_id))
        return page(state, request, "partials/case_form.html", detail=detail, draft=draft)


def check(app: FastAPI) -> tuple[str, dict, int]:
    """`tia web --check` のために、一覧を 1 回描き、`/healthz` の中身を返す。待ち受けない。"""
    from tia.web.health import healthz

    state: WebState = app.state.tia
    scope = {"type": "http", "method": "GET", "path": "/", "raw_path": b"/", "query_string": b"", "headers": [],
             "scheme": "https", "server": ("check.invalid", 443), "client": ("127.0.0.1", 0), "app": app,
             "root_path": ""}
    request = Request(scope)
    now = state.clock()
    with closing(db.connect(state.db_path)) as conn:
        html = render(state, request, "inbox.html", **inbox_context(conn, request, state, None))
        body, status = healthz(conn, state.db_path, state.cfg, now, state.monitor.snapshot(),
                               queries.queue_summary(conn, now, state.cfg))
    return html, body, status
