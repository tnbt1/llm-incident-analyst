"""アプリの状態と描画の共通部分。経路のモジュールと `app` の両方が使う。"""
from __future__ import annotations

from collections.abc import Callable
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment

from tia.config import Config
from tia.web import security
from tia.web.health import HealthMonitor

Clock = Callable[[], datetime]
BUSY_MESSAGE = "保存先が混んでいる。少し待ってやり直す"


def is_busy(exc: BaseException) -> bool:
    """SQLite の鍵待ちの失敗か。"""
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class WebState:
    db_path: Path
    cfg: Config
    clock: Clock
    monitor: HealthMonitor
    templates: Environment
    secret: bytes
    # 止める合図。司令塔か `tia web` が立てる。開いたままの SSE はこれを見て「: shutdown」で終わる
    stopping: threading.Event = field(default_factory=threading.Event)
    # 確認の実行器。None なら画面の「実行」は出ない
    probes: object | None = None


def render(state: WebState, request: Request, name: str, **context) -> str:
    """テンプレートを描く。全部のページと部品が同じ共通の値を受け取る。"""
    template = state.templates.get_template(name)
    return template.render(request=request, cfg=state.cfg, now=state.clock(), system_name=state.cfg.web_system_name,
                           snapshot=state.monitor.snapshot(),
                           csrf_token=security.token_for(state.secret, security.session_of(request)), **context)


def page(state: WebState, request: Request, name: str, status_code: int = 200, **context) -> HTMLResponse:
    return HTMLResponse(render(state, request, name, **context), status_code=status_code)


def is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"
