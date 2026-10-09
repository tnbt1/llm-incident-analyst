"""操作の経路（POST）。同じ画面から出た要求だけを受ける。

保存先を触る部分はスレッドで動かし、イベントループを止めない。
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from tia import db
from tia.web import actions, queries, security
from tia.web.core import BUSY_MESSAGE, WebState, is_busy, is_htmx, render

ACTIONS = ("read", "prioritize", "skip", "reanalyze", "feedback", "case", "probe", "reanalyze_with_probes")


def trigger_header(message: str, ok: bool) -> str:
    """HTMX に渡すトーストの指示。ヘッダーに入るので、日本語は JSON のエスケープで ASCII にする。"""
    return json.dumps({"tia-toast": {"message": message, "ok": ok}}, ensure_ascii=True)


async def _form(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "")
    if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
        data = await request.form()
        return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}
    return {}


def _perform(state: WebState, name: str, incident_id: int, now, form: dict[str, str]):
    with closing(db.connect(state.db_path)) as conn:
        outcome = actions.perform(conn, name, incident_id, now, form, runner=state.probes)
        detail = queries.detail(conn, incident_id, now, state.cfg, runner=state.probes) if outcome.status != 404 else None
    return outcome, detail


def register(app: FastAPI, state: WebState) -> None:
    async def act(request: Request, name: str, incident_id: int):
        security.check_same_origin(request)
        form = await _form(request)
        security.check_token(request, state.secret, form.get(security.TOKEN_FIELD))
        now = state.clock()
        try:
            outcome, detail = await run_in_threadpool(_perform, state, name, incident_id, now, form)
        except sqlite3.OperationalError as exc:
            if is_busy(exc):
                raise HTTPException(503, BUSY_MESSAGE) from None
            raise
        if name == "read":
            # 背景の処理。描き直しもトーストも要らない
            if not outcome.ok:
                raise HTTPException(outcome.status, outcome.message)
            return JSONResponse({"ok": True, "incident": f"I-{incident_id:04d}"})
        if is_htmx(request) and detail is not None:
            # HTMX には、いまの詳細を返して描き直させ、結果はトーストで知らせる
            body = render(state, request, "partials/incident.html", detail=detail, toast=outcome)
            return HTMLResponse(body, status_code=200, headers={"HX-Trigger": trigger_header(outcome.message, outcome.ok)})
        if not outcome.ok:
            raise HTTPException(outcome.status, outcome.message)
        return JSONResponse({"ok": True, "message": outcome.message, "incident": f"I-{incident_id:04d}"})

    for action_name in ACTIONS:
        def make(name: str):
            async def route(request: Request, incident_id: int):
                return await act(request, name, incident_id)
            route.__name__ = f"action_{name}"
            return route
        app.add_api_route(f"/incidents/{{incident_id}}/{action_name}", make(action_name), methods=["POST"])
