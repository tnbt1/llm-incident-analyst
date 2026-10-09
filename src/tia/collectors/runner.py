"""収集と整理を、決まった間隔で繰り返す。"""
from __future__ import annotations

import logging
import sqlite3
import threading
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from tia import db, grouping, queue
from tia.collectors import state
from tia.collectors.base import CREDENTIAL_KINDS, PollReport, SourceError
from tia.collectors.endpoints import Endpoints
from tia.collectors.wazuh import WazuhPoller
from tia.collectors.zabbix import ZabbixPoller
from tia.config import Config
from tia.models import Source, to_iso
from tia.type_rules import TypeRules

log = logging.getLogger("tia.collect")

# 新しく何かが起きたことを示す件数。これがあるときだけ、成功を記録に出す。
NOTABLE = ("created", "recurred", "skipped", "rejected", "resolved", "reopened")


class Poller(Protocol):
    source: Source

    def poll(self, conn: sqlite3.Connection, now: datetime, cfg: Config, rules: TypeRules,
             should_stop: Callable[[], bool]) -> PollReport: ...


@dataclass(frozen=True)
class SourceRun:
    """1 つの系統の、1 回の周期での結果。status は ok、failed、waiting、stopped。"""

    source: Source
    status: str
    report: PollReport | None = None
    error_kind: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Tidy:
    promoted: int = 0
    group_id: int | None = None
    followups: int = 0
    error: str | None = None


@dataclass(frozen=True)
class CycleReport:
    at: datetime
    runs: tuple[SourceRun, ...]
    tidy: Tidy

    @property
    def failed(self) -> bool:
        return self.tidy.error is not None or any(run.status == "failed" for run in self.runs)


def build_pollers(endpoints: Endpoints) -> list[Poller]:
    pollers: list[Poller] = []
    if endpoints.zabbix:
        pollers.append(ZabbixPoller(endpoints.zabbix))
    if endpoints.wazuh:
        pollers.append(WazuhPoller(endpoints.wazuh))
    return pollers


def _unexpected(exc: Exception) -> str:
    """想定外の失敗の表示。例外の文は出さない。送った秘密が入ることがあるため。"""
    return f"想定外の失敗（{type(exc).__name__}）"


def _frames(exc: Exception) -> str:
    return "".join(traceback.format_tb(exc.__traceback__)).rstrip()


def tidy(conn: sqlite3.Connection, now: datetime, cfg: Config) -> Tidy:
    """整理。連鎖を判定してから、待ちの明けたものを順番待ちへ移し、追跡解析を予約する。

    1 つのまとまりで行う。途中の状態を、解析の処理に見せないため。
    """
    with db.transaction(conn):
        group_id = grouping.evaluate(conn, now, cfg)
        promoted = queue.promote_held(conn, now)
        followups = queue.schedule_followups(conn, now, cfg)
    return Tidy(promoted, group_id, followups)


def _poll(conn: sqlite3.Connection, poller: Poller, now: datetime, cfg: Config, rules: TypeRules, force: bool,
          should_stop: Callable[[], bool]) -> SourceRun:
    source = poller.source
    before = state.get(conn, source)
    if not force and not state.is_due(before, now, cfg):
        return SourceRun(source, "waiting")
    if should_stop():
        return SourceRun(source, "stopped")
    interval = state.interval_of(source, cfg)
    try:
        report = poller.poll(conn, now, cfg, rules, should_stop)
    except SourceError as exc:
        _abandon(conn)
        kind, message = exc.kind, str(exc)
        wait = state.backoff(cfg, interval, before.consecutive_failures + 1, exc)
    except Exception as exc:  # noqa: BLE001  片方の想定外の失敗で、もう片方を止めない
        _abandon(conn)
        kind, message = "internal", _unexpected(exc)
        wait = state.backoff(cfg, interval, before.consecutive_failures + 1, SourceError(kind, message))
        log.error("%s の収集で%s\n%s", source, message, _frames(exc))
    else:
        behind = state.record_success(conn, source, now, now + timedelta(seconds=interval), report.watermark,
                                      report.complete)
        if before.consecutive_failures:
            log.info("%s の収集が復帰した。失敗は %d 回続いていた", source, before.consecutive_failures)
        # 追いついていない状態は、変わり目にだけ記録する。
        if behind == state.INCOMPLETE_LIMIT + 1:
            log.warning("%s を読み切れない状態が %d 回続いている。届く量が、1 回に読む上限を超えている",
                        source, behind)
        elif not behind and before.incomplete_polls > state.INCOMPLETE_LIMIT:
            log.info("%s を読み切った。読み切れない状態は %d 回続いていた", source, before.incomplete_polls)
        if any(report.counts.get(name) for name in NOTABLE) or not report.complete:
            log.info("%s を収集した: %s%s", source, _counts(report.counts),
                     "" if report.complete else "。読み切っていない")
        return SourceRun(source, "ok", report)
    failures = state.record_failure(conn, source, now, kind, message, now + wait)
    log.warning("%s の収集に失敗した（%s、%d 回目）: %s。次は %d 秒後", source, kind, failures, message,
                int(wait.total_seconds()))
    after = state.get(conn, source)
    if after.stuck and after.stuck_failures == state.STUCK_LIMIT:
        # 変わり目に 1 回だけ、強く知らせる。
        log.error("%s は同じ位置で %d 回続けて失敗した（%s）。その位置の応答を読めず、前回位置が進まない。"
                  "この先のアラートは取り込まれない", source, after.stuck_failures, kind)
    return SourceRun(source, "failed", error_kind=kind, error=message)


def _abandon(conn: sqlite3.Connection) -> None:
    """失敗した収集が開いたままにしたまとまりを捨てる。残すと、この後の記録がその中に入り、確定しない。"""
    if conn.in_transaction:
        conn.execute("ROLLBACK")


def _counts(counts) -> str:
    return " ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "0 件"


def run_cycle(conn: sqlite3.Connection, pollers: Sequence[Poller], now: datetime, cfg: Config, rules: TypeRules,
              *, force: bool = False, should_stop: Callable[[], bool] = lambda: False) -> CycleReport:
    """1 回の周期。時刻の来た系統を収集し、その後に整理する。失敗は結果に入れて返し、例外にしない。

    force は、待ちを無視して全部の系統を収集する。手で 1 回だけ動かすときに使う。
    """
    runs = []
    for poller in pollers:
        try:
            runs.append(_poll(conn, poller, now, cfg, rules, force, should_stop))
        except Exception as exc:  # noqa: BLE001  成否を保存できない場合も、次の系統へ進む
            _abandon(conn)
            log.error("%s の収集の記録で%s\n%s", poller.source, _unexpected(exc), _frames(exc))
            runs.append(SourceRun(poller.source, "failed", error_kind="internal", error=_unexpected(exc)))
    try:
        tidied = tidy(conn, now, cfg)
    except Exception as exc:  # noqa: BLE001
        _abandon(conn)
        log.error("整理で%s\n%s", _unexpected(exc), _frames(exc))
        tidied = Tidy(error=_unexpected(exc))
    return CycleReport(now, tuple(runs), tidied)


def _plan(stored: state.SourceState, now: datetime, cfg: Config) -> str:
    """起動のときに、系統ごとに記録へ出す 1 行。次にいつ収集するかと、その理由。"""
    name = stored.source.value
    if stored.next_poll_at is None:
        return f"{name} はすぐに収集する。まだ一度も収集していない"
    if state.too_far(stored, now, cfg):
        return (f"{name} はすぐに収集する。保存してある次の収集の時刻 {to_iso(stored.next_poll_at)} が先すぎる。"
                "時計がずれていた可能性がある")
    if now >= stored.next_poll_at:
        return f"{name} はすぐに収集する。収集の時刻を過ぎている"
    seconds = int((stored.next_poll_at - now).total_seconds())
    when = f"{name} の次の収集は {to_iso(stored.next_poll_at)}（{seconds} 秒後）。"
    if not stored.consecutive_failures:
        return when + "通常の間隔"
    if stored.last_error_kind in CREDENTIAL_KINDS:
        return when + (f"認証の失敗の後の待ち（{stored.last_error_kind}）。"
                       "秘密を直した場合は tia collect --once で確かめられる")
    return when + f"失敗が {stored.consecutive_failures} 回続いた後の待ち（{stored.last_error_kind}）"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def run_loop(conn: sqlite3.Connection, pollers: Sequence[Poller], cfg: Config, rules: TypeRules,
             stop: threading.Event, *, clock: Callable[[], datetime] = _utc_now,
             wait: Callable[[float], object] | None = None,
             on_cycle: Callable[[CycleReport], None] | None = None) -> int:
    """止める合図が来るまで周期を繰り返し、回した数を返す。合図の後は、いまの周期を終えてから止まる。

    始めに 1 回、前回の停止で解析中のまま残ったものを順番待ちへ戻す。
    """
    wait = stop.wait if wait is None else wait
    recovered = queue.recover_running(conn, clock())
    if recovered:
        log.info("解析中のまま残っていた %d 件を順番待ちへ戻した", recovered)
    # 待ちを引き継いだ起動は、何もしていないように見える。理由を先に出す。
    for poller in pollers:
        log.info("%s", _plan(state.get(conn, poller.source), clock(), cfg))
    cycles = 0
    while not stop.is_set():
        report = run_cycle(conn, pollers, clock(), cfg, rules, should_stop=stop.is_set)
        cycles += 1
        if on_cycle is not None:
            on_cycle(report)
        if not stop.is_set():
            wait(cfg.collector_tick_sec)
    return cycles
