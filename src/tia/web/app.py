"""画面のアプリケーション。組み立て、応答の守り、誤りの表示、`/healthz`。経路は `routes*` が足す。

1 つの要求ごとに保存先へつなぎ、読み取りは `queries`、操作は `actions` に任せる。
"""
from __future__ import annotations

import json
import logging
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.exceptions import HTTPException as StarletteHTTPException

from tia import db
from tia.config import Config
from tia.web import filters, queries, security
from tia.web.core import BUSY_MESSAGE, Clock, WebState, is_busy, is_htmx, page, render, utc_now
from tia.web import routes
from tia.web import routes_actions
from tia.web import events
from tia.web.health import HealthMonitor, Probe, healthz

log = logging.getLogger("tia.web")
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(db_path: Path, cfg: Config, *, bundle_dir: Path | None = None, source_dir: Path | None = None,
               llm_probe: Probe | None = None, llm_probe_error: str | None = None,
               monitor_interval_sec: float | None = None, clock: Clock = utc_now,
               probe_runner: object | None = None) -> FastAPI:
    """アプリを組み立てる。monitor_interval_sec を与えると、稼働の確認を別のスレッドで続ける。

    llm_probe がなく llm_probe_error があれば、LLM は「接続先が未設定」の失敗として扱う。
    """
    db_path = Path(db_path)
    with closing(db.connect(db_path)):
        pass
    monitor = HealthMonitor(llm_probe, bundle_dir or Path(cfg.knowledge_bundle_dir), cfg, clock, source_dir=source_dir,
                            probe_error=llm_probe_error)
    env = Environment(loader=PackageLoader("tia.web", "templates"),
                      autoescape=select_autoescape(default=True, default_for_string=True),
                      trim_blocks=True, lstrip_blocks=True)
    filters.register(env, queries.zone(cfg))
    state = WebState(db_path, cfg, clock, monitor, env, secrets.token_bytes(32), probes=probe_runner)
    app = FastAPI(title=cfg.web_system_name, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.tia = state
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    _guard(app, state)
    _health_route(app, state)
    routes.register(app, state)
    routes_actions.register(app, state)
    events.register(app, state)
    # 経路。後のタスクがここに足す
    if monitor_interval_sec is not None:
        monitor.start(monitor_interval_sec)
    return app


def _guard(app: FastAPI, state: WebState) -> None:
    @app.middleware("http")
    async def guard(request: Request, call_next):
        security.session_of(request)
        response = await call_next(request)
        security.apply_headers(request, response, cookie_secure=state.cfg.web_cookie_secure)
        return response

    # 経路がない 404 は Starlette の例外で来るので、親の型で受ける
    @app.exception_handler(StarletteHTTPException)
    async def failed(request: Request, exc: StarletteHTTPException):
        message = str(exc.detail)
        if is_htmx(request):
            # 断った理由はトーストで見せる。HTMX は 4xx の本文を差し替えないが、HX-Trigger は読む
            trigger = json.dumps({"tia-toast": {"message": message, "ok": False}}, ensure_ascii=True)
            return HTMLResponse(render(state, request, "partials/message.html", message=message, ok=False),
                                status_code=exc.status_code, headers={"HX-Trigger": trigger})
        if request.url.path == "/healthz" or request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse({"detail": message}, status_code=exc.status_code)
        return page(state, request, "error.html", exc.status_code, message=message, status=exc.status_code)

    @app.exception_handler(ValueError)
    async def bad_value(request: Request, exc: ValueError):
        return await failed(request, HTTPException(400, str(exc)))

    @app.exception_handler(sqlite3.OperationalError)
    async def database_trouble(request: Request, exc: sqlite3.OperationalError):
        if is_busy(exc):
            return await failed(request, HTTPException(503, BUSY_MESSAGE))
        log.error("保存先の失敗: %s", type(exc).__name__)
        return await failed(request, HTTPException(500, f"保存先の失敗（{type(exc).__name__}）"))


def _health_route(app: FastAPI, state: WebState) -> None:
    @app.get("/healthz")
    def health_check():
        now = state.clock()
        with closing(db.connect(state.db_path)) as conn:
            body, status = healthz(conn, state.db_path, state.cfg, now, state.monitor.snapshot(),
                                   queries.queue_summary(conn, now, state.cfg))
        return JSONResponse(body, status_code=status)
