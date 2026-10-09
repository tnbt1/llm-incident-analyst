"""系統ごとの前回位置と、収集の成否の記録。"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta

from tia import db
from tia.collectors.base import CREDENTIAL_KINDS, SourceError, scrub
from tia.config import Config
from tia.models import Source, from_iso, to_iso

SOURCES = (Source.ZABBIX, Source.WAZUH)
# 最後の成功からこの回数分の間隔を過ぎたら、止まっているとみなす。
STALE_INTERVALS = 3
# 読み残しのある収集が、この回数を超えて続いたら、追いついていないとみなす。
INCOMPLETE_LIMIT = 3
# 同じ位置での失敗が、この回数続いたら、その位置の応答を読めないとみなす。
STUCK_LIMIT = 3
# 応答の中身が原因の失敗。相手に届いているのに読めない。待っても直らないことがある。
CONTENT_KINDS = frozenset({"invalid_response", "partial", "too_large", "internal"})


@dataclass(frozen=True)
class SourceState:
    source: Source
    watermark: str | None = None
    last_poll_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_error: str | None = None
    last_error_kind: str | None = None
    last_error_at: datetime | None = None
    consecutive_failures: int = 0
    next_poll_at: datetime | None = None
    # 読み残しの続き。形は系統ごとに決める。
    cursor: str | None = None
    # 一覧を末尾まで読み切った回数。
    round: int = 0
    incomplete_polls: int = 0
    # 同じ位置で続けて失敗した回数。
    stuck_failures: int = 0

    @property
    def stuck(self) -> bool:
        """同じ位置の応答を読めずに、先へ進めなくなっているか。"""
        return self.stuck_failures >= STUCK_LIMIT and self.last_error_kind in CONTENT_KINDS


@dataclass(frozen=True)
class SourceHealth:
    """healthy でないとき、reason に理由が入る。"""

    state: SourceState
    seconds_since_ok: int | None
    healthy: bool
    reason: str | None = None


def interval_of(source: Source, cfg: Config) -> int:
    return cfg.wazuh_poll_interval_sec if source == Source.WAZUH else cfg.zabbix_poll_interval_sec


def _time(value: str | None) -> datetime | None:
    return from_iso(value) if value else None


def get(conn: sqlite3.Connection, source: Source) -> SourceState:
    row = conn.execute("SELECT * FROM collector_state WHERE source = ?", (source,)).fetchone()
    if row is None:
        return SourceState(source)
    return SourceState(source, row["watermark"], _time(row["last_poll_at"]), _time(row["last_ok_at"]),
                       row["last_error"], row["last_error_kind"], _time(row["last_error_at"]),
                       row["consecutive_failures"], _time(row["next_poll_at"]), row["cursor"], row["round"],
                       row["incomplete_polls"], row["stuck_failures"])


def _ensure(conn: sqlite3.Connection, source: Source) -> None:
    conn.execute("INSERT OR IGNORE INTO collector_state (source) VALUES (?)", (source,))


def set_watermark(conn: sqlite3.Connection, source: Source, watermark: str) -> None:
    """前回位置だけを進める。取り込みと同じまとまりの中で呼ぶ。"""
    with db.transaction(conn):
        _ensure(conn, source)
        conn.execute("UPDATE collector_state SET watermark = ? WHERE source = ?", (watermark, source))


def set_cursor(conn: sqlite3.Connection, source: Source, cursor: str | None) -> None:
    """読み残しの続きを保存する。取り込みと同じまとまりの中で呼ぶ。"""
    with db.transaction(conn):
        _ensure(conn, source)
        conn.execute("UPDATE collector_state SET cursor = ? WHERE source = ?", (cursor, source))


def finish_round(conn: sqlite3.Connection, source: Source) -> int:
    """一覧を末尾まで読み切った。続きを消し、回数を進めて返す。"""
    with db.transaction(conn):
        _ensure(conn, source)
        conn.execute("UPDATE collector_state SET cursor = NULL, round = round + 1 WHERE source = ?", (source,))
        return conn.execute("SELECT round FROM collector_state WHERE source = ?", (source,)).fetchone()[0]


def record_success(conn: sqlite3.Connection, source: Source, now: datetime, next_poll_at: datetime,
                   watermark: str | None = None, complete: bool = True) -> int:
    """成功を記録し、読み残しのある収集が続いた回数を返す。

    watermark が None なら前回位置は変えない。最後の失敗の内容は履歴として残す。
    """
    with db.transaction(conn):
        _ensure(conn, source)
        conn.execute("UPDATE collector_state SET last_poll_at = ?, last_ok_at = ?, consecutive_failures = 0, "
                     "next_poll_at = ?, watermark = COALESCE(?, watermark), stuck_at = NULL, stuck_failures = 0, "
                     "incomplete_polls = CASE WHEN ? THEN 0 ELSE incomplete_polls + 1 END WHERE source = ?",
                     (to_iso(now), to_iso(now), to_iso(next_poll_at), watermark, int(complete), source))
        return conn.execute("SELECT incomplete_polls FROM collector_state WHERE source = ?",
                            (source,)).fetchone()[0]


def record_failure(conn: sqlite3.Connection, source: Source, now: datetime, kind: str, message: str,
                   next_poll_at: datetime) -> int:
    """失敗を記録し、続けて失敗した回数を返す。前回位置は変えない。

    失敗したときの位置も残す。同じ位置での失敗が続いているかを見分けるため。
    """
    with db.transaction(conn):
        _ensure(conn, source)
        at = conn.execute("SELECT COALESCE(watermark, '') || '|' || COALESCE(cursor, '') FROM collector_state "
                          "WHERE source = ?", (source,)).fetchone()[0]
        conn.execute("UPDATE collector_state SET last_poll_at = ?, last_error = ?, last_error_kind = ?, "
                     "last_error_at = ?, consecutive_failures = consecutive_failures + 1, next_poll_at = ?, "
                     "stuck_failures = CASE WHEN stuck_at IS ? THEN stuck_failures + 1 ELSE 1 END, stuck_at = ? "
                     "WHERE source = ?",
                     (to_iso(now), scrub(message), scrub(kind), to_iso(now), to_iso(next_poll_at), at, at, source))
        return conn.execute("SELECT consecutive_failures FROM collector_state WHERE source = ?",
                            (source,)).fetchone()[0]


def backoff(cfg: Config, interval: int, failures: int, error: SourceError) -> timedelta:
    """次に試すまでの待ち。失敗が続くほど倍に延ばし、上限で止める。

    1 回目の失敗は通常の間隔で試し直す。認証の誤りは最初から長く待つ。
    相手が待ち時間を指定したら、それより短くはしない。
    """
    if error.kind in CREDENTIAL_KINDS:
        return timedelta(seconds=cfg.collector_auth_backoff_sec)
    limit = max(cfg.collector_backoff_max_sec, interval)
    seconds = min(interval * 2 ** min(max(failures, 1) - 1, 20), limit)
    if error.retry_after is not None:
        seconds = max(seconds, min(error.retry_after, limit))
    return timedelta(seconds=seconds)


def longest_wait(source: Source, cfg: Config) -> int:
    """収集が置く待ちのうち、最も長いもの。"""
    return max(interval_of(source, cfg), cfg.collector_backoff_max_sec, cfg.collector_auth_backoff_sec)


def too_far(state: SourceState, now: datetime, cfg: Config) -> bool:
    """保存してある次の収集の時刻が、収集が置くどの待ちよりも先か。

    時計が先へずれていた間に保存した時刻とみなす。信じると、時計が直った後も長く止まる。
    """
    ahead = state.next_poll_at is not None and (state.next_poll_at - now).total_seconds()
    return bool(ahead) and ahead > longest_wait(state.source, cfg)


def is_due(state: SourceState, now: datetime, cfg: Config) -> bool:
    return state.next_poll_at is None or now >= state.next_poll_at or too_far(state, now, cfg)


def health(conn: sqlite3.Connection, now: datetime, cfg: Config) -> tuple[SourceHealth, ...]:
    """画面のヘッダーと稼働の確認のための、系統ごとの状態。一度も収集していない系統も返す。"""
    result = []
    for source in SOURCES:
        state = get(conn, source)
        since = None if state.last_ok_at is None else int((now - state.last_ok_at).total_seconds())
        reason = _trouble(state, since, interval_of(source, cfg))
        result.append(SourceHealth(state, since, reason is None, reason))
    return tuple(result)


def _trouble(state: SourceState, since: int | None, interval: int) -> str | None:
    """健全でない理由。健全なら None。"""
    if state.consecutive_failures and state.stuck:
        return (f"同じ位置で {state.stuck_failures} 回続けて失敗している（{state.last_error_kind}）。"
                "この先のアラートを取り込めない")
    if state.consecutive_failures:
        return f"失敗が {state.consecutive_failures} 回続いている（{state.last_error_kind}）"
    if since is None:
        return "まだ一度も成功していない"
    if since < 0:
        return "最後の成功の時刻が未来になっている。時計のずれを確かめる"
    if since > STALE_INTERVALS * interval:
        return f"最後の成功から {since} 秒たっている"
    if state.incomplete_polls > INCOMPLETE_LIMIT:
        return f"読み切れない状態が {state.incomplete_polls} 回続いている"
    return None
