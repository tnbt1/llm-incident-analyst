"""ライブ更新。保存先の変化を見て、SSE で部品の名前を知らせる。中身は送らず、受けた側が部品を取り直す。"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
from collections.abc import AsyncIterator, Callable
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from tia.config import Config
from tia.web import queries
from tia.web.health import HealthMonitor

log = logging.getLogger("tia.web.events")
KEEPALIVE_SEC = 15


def open_read(path: Path) -> sqlite3.Connection:
    """読み取りだけの接続。別のスレッドから順に使うので、スレッドの確認を外す。"""
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA query_only = ON")
    return conn


def _frame(name: str, data: str = "") -> bytes:
    return f"event: {name}\ndata: {data}\n\n".encode()


def _progress_key(current: queries.Running | None) -> tuple | None:
    return None if current is None else (current.analysis_id, current.phase, current.tokens)


class Watcher:
    """1 つの接続の変化の追跡。テストからは `step()` で 1 回分を取り出せる。"""

    def __init__(self, conn: sqlite3.Connection, cfg: Config, monitor: HealthMonitor,
                 clock: Callable[[], datetime]) -> None:
        self._conn = conn
        self._cfg = cfg
        self._monitor = monitor
        self._clock = clock
        self._mark: queries.Mark | None = None
        self._progress: tuple | None = None
        self._health: datetime | None = None
        self._since_keepalive = 0.0

    def step(self, elapsed_sec: float) -> list[bytes]:
        """変化があれば、その部品の名前のイベント。なければ、たまに keep-alive のコメント。"""
        frames: list[bytes] = []
        try:
            mark = queries.mark(self._conn)
            current = queries.running(self._conn, self._clock(), self._cfg)
            changed_ids: set[int] = set()
            if self._mark is not None and mark.changed(self._mark):
                changed_ids = queries.changed_incidents(self._conn, self._mark)
                frames += [_frame("rail", mark.incidents_updated), _frame("band", mark.incidents_updated),
                           _frame("list", mark.incidents_updated)]
                for incident_id in sorted(changed_ids):
                    frames.append(_frame(f"incident-{incident_id}", str(incident_id)))
            progress = _progress_key(current)
            if progress != self._progress and progress is not None:
                # 進捗は数字だけを送る。受けた側は部品を取り直さず、文字を書き換える
                frames.append(_frame("progress", json.dumps(current.texts(self._cfg.llm_max_tokens), ensure_ascii=False)))
            self._mark, self._progress = mark, progress
        except sqlite3.Error as exc:
            # 保存先が混んでいる間は、次の回に回す。流れは切らない
            log.warning("変化の確認を飛ばした: %s", type(exc).__name__)
        checked = self._monitor.snapshot().checked_at
        if checked != self._health:
            self._health = checked
            frames.append(_frame("health", checked.isoformat() if checked else ""))
        self._since_keepalive += elapsed_sec
        if not frames and self._since_keepalive >= KEEPALIVE_SEC:
            frames.append(b": keep-alive\n\n")
        if frames:
            self._since_keepalive = 0.0
        return frames


def register(app: FastAPI, state) -> None:
    """`/events` を足す。"""
    @app.get("/events")
    async def sse(request: Request):
        generator = stream(request, state.db_path, state.cfg, state.monitor, state.clock, stopping=state.stopping)
        return StreamingResponse(generator, media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


async def stream(request: Request, db_path: Path, cfg: Config, monitor: HealthMonitor,
                 clock: Callable[[], datetime], *, stopping: threading.Event | None = None) -> AsyncIterator[bytes]:
    """SSE の本体。切断されるか、サービスが止まるまで、間隔ごとに変化を見る。

    止める合図（stopping）が立ったら「: shutdown」を送って終える。サーバーの停止がタスクを打ち切るのを待たない。
    """
    conn = await run_in_threadpool(open_read, db_path)
    watcher = Watcher(conn, cfg, monitor, clock)
    poll = float(cfg.web_sse_poll_sec)
    elapsed = 0.0
    try:
        yield b"retry: 3000\n\n"
        for frame in await run_in_threadpool(watcher.step, 0.0):
            yield frame
        # 長く開いたままの接続は閉じる。ブラウザは retry の間隔でつなぎ直す
        while elapsed < cfg.web_sse_max_sec:
            if await request.is_disconnected():
                break
            if stopping is not None and stopping.is_set():
                yield b": shutdown\n\n"
                break
            await asyncio.sleep(poll)
            elapsed += poll
            if stopping is not None and stopping.is_set():
                yield b": shutdown\n\n"
                break
            for frame in await run_in_threadpool(watcher.step, poll):
                yield frame
        else:
            yield b": reconnect\n\n"
    finally:
        # await しない。サーバーの停止で GeneratorExit が来たときも、ここは最後まで走る
        conn.close()
