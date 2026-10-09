"""稼働の確認。LLM と知識の束は別のスレッドで定期的に確かめ、画面と `/healthz` は最新の結果を読む。

推論の要求は稼働の確認に使わない。LLM の確認は `LlmClient.health()` と同じ形の関数を受け取る。
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from tia.analysis.llm import LlmHealth
from tia.collectors import state as collector_state
from tia.config import Config
from tia.knowledge.bundle import BundleError, freshness, load_bundle
from tia.models import to_iso

log = logging.getLogger("tia.web.health")

Probe = Callable[[], LlmHealth]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class LlmStatus:
    """ok が None のうちは、まだ確かめていない。kind は届かない理由の種類（LlmHealth.kind と同じ語）。

    config は、接続先そのものが設定できていない（鍵が読めない、宛先が壊れている）。
    """
    ok: bool | None
    detail: str
    checked_at: datetime | None = None
    kind: str = ""

    @property
    def label(self) -> str:
        if self.ok is None:
            return "確認中"
        return "稼働" if self.ok else "停止"

    @property
    def tunnel(self) -> str:
        """トンネルの札の文。種類で決める。文の中身では決めない。"""
        if self.ok:
            return "接続"
        if self.ok is None:
            return "確認中"
        return {"unreachable": "切断", "timeout": "切断", "auth": "鍵", "tls": "証明書", "config": "未設定"}.get(
            self.kind, "要確認")


@dataclass(frozen=True)
class KnowledgeStatus:
    loaded: bool
    detail: str
    version: str | None = None
    age_days: int | None = None
    stale: bool = False
    source_changed: bool | None = None
    sections: int = 0


@dataclass(frozen=True)
class Snapshot:
    llm: LlmStatus
    knowledge: KnowledgeStatus
    checked_at: datetime | None


class HealthMonitor:
    """LLM と知識の束の状態を持つ。`refresh()` で確かめ、`snapshot()` で読む。"""

    def __init__(self, probe: Probe | None, bundle_dir: Path, cfg: Config, clock: Clock, *,
                 source_dir: Path | None = None, probe_error: str | None = None) -> None:
        self._probe = probe
        self._probe_error = probe_error
        self._bundle_dir = bundle_dir
        self._source_dir = source_dir
        self._cfg = cfg
        self._clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        first = LlmStatus(None, "確認中") if probe is not None else self._unprobed(None)
        self._snapshot = Snapshot(first, KnowledgeStatus(False, "確認中"), None)

    def _unprobed(self, now: datetime | None) -> LlmStatus:
        """確認の関数がないときの状態。設定できなかった理由があれば失敗、なければ「確認していない」。"""
        if self._probe_error:
            return LlmStatus(False, f"接続先が未設定: {self._probe_error}", now, "config")
        return LlmStatus(None, "確認していない", now)

    def snapshot(self) -> Snapshot:
        with self._lock:
            return self._snapshot

    def refresh(self) -> Snapshot:
        now = self._clock()
        snapshot = Snapshot(self._check_llm(now), self._check_knowledge(now), now)
        with self._lock:
            self._snapshot = snapshot
        return snapshot

    def _check_llm(self, now: datetime) -> LlmStatus:
        if self._probe is None:
            return self._unprobed(now)
        try:
            result = self._probe()
        except Exception as exc:  # noqa: BLE001 - 確認の失敗で画面を止めない。種類だけを残す
            log.warning("LLM の確認で想定外の失敗: %s", type(exc).__name__)
            return LlmStatus(False, f"確認に失敗した（{type(exc).__name__}）", now, "internal")
        return LlmStatus(bool(result.ok), str(result.detail), now, str(getattr(result, "kind", "") or ""))

    def _check_knowledge(self, now: datetime) -> KnowledgeStatus:
        try:
            bundle = load_bundle(self._bundle_dir)
        except BundleError as exc:
            return KnowledgeStatus(False, f"束を読めない: {exc}")
        state = freshness(bundle, now.date(), stale_after_days=self._cfg.knowledge_stale_after_days,
                          source_dir=self._source_dir)
        detail = f"版 {bundle.version}、生成から {state.age_days} 日"
        if state.stale:
            detail += "。作り直す時期"
        if state.source_changed:
            detail += "。出典が生成の後に変わっている"
        return KnowledgeStatus(True, detail, bundle.version, state.age_days, state.stale, state.source_changed,
                               len(bundle.sections))

    def start(self, interval_sec: float) -> None:
        """別のスレッドで確かめ続ける。最初の 1 回はすぐに行う。"""
        if self._thread is not None:
            return

        def loop() -> None:
            first = True
            while not self._stop.is_set():
                try:
                    snapshot = self.refresh()
                    if first:
                        # 起動時の確認の結果。司令塔の主スレッドは待たない
                        llm = snapshot.llm
                        log.log(logging.INFO if llm.ok else logging.WARNING, "LLM の確認: %s", llm.detail)
                        log.info("知識の束の確認: %s", snapshot.knowledge.detail)
                except Exception:  # noqa: BLE001 - 確認のスレッドは止めない
                    log.exception("稼働の確認で想定外の失敗")
                first = False
                self._stop.wait(interval_sec)

        self._thread = threading.Thread(target=loop, name="tia-web-health", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


BUSY_WAIT_MS = 500


def database_status(conn: sqlite3.Connection, db_path: Path, cfg: Config) -> dict:
    """保存先に書けるか、空きがあるか。

    書き込みの確認は、短い待ちの別の接続で行う。ほかの処理が鍵を持っている間は「混んでいる」であって
    「書けない」ではないので、正常のまま理由だけを残す。
    """
    writable = True
    detail = "書ける"
    path = Path(db_path)
    if not os.access(path, os.W_OK) or not os.access(path.parent, os.W_OK):
        writable = False
        detail = "書けない（ファイルかフォルダに書く権限がない）"
    else:
        try:
            probe = sqlite3.connect(str(path), timeout=BUSY_WAIT_MS / 1000, isolation_level=None)
            try:
                probe.execute(f"PRAGMA busy_timeout = {BUSY_WAIT_MS}")
                probe.execute("BEGIN IMMEDIATE")
                probe.execute("ROLLBACK")
            finally:
                probe.close()
        except sqlite3.OperationalError as exc:
            text = str(exc).lower()
            if "locked" in text or "busy" in text:
                detail = "混んでいる（ほかの処理が書き込み中）"
            else:
                writable = False
                detail = f"書けない（{type(exc).__name__}）"
        except sqlite3.Error as exc:
            writable = False
            detail = f"書けない（{type(exc).__name__}）"
    free_mb: int | None = None
    try:
        free_mb = shutil.disk_usage(Path(db_path).resolve().parent).free // (1024 * 1024)
    except OSError:
        pass
    enough = free_mb is None or free_mb >= cfg.web_min_free_mb
    if not enough:
        detail = f"空きが {free_mb} MB しかない（{cfg.web_min_free_mb} MB 未満）"
    return {"ok": writable and enough, "writable": writable, "free_mb": free_mb, "detail": detail}


def collectors_status(conn: sqlite3.Connection, now: datetime, cfg: Config) -> dict:
    """系統ごとの収集の状態。収集の `state.health` をそのまま形にする。"""
    result = {}
    for item in collector_state.health(conn, now, cfg):
        result[str(item.state.source)] = {
            "ok": item.healthy,
            "seconds_since_ok": item.seconds_since_ok,
            "last_ok_at": to_iso(item.state.last_ok_at) if item.state.last_ok_at else None,
            "consecutive_failures": item.state.consecutive_failures,
            "detail": item.reason or "正常",
        }
    return result


def healthz(conn: sqlite3.Connection, db_path: Path, cfg: Config, now: datetime, snapshot: Snapshot,
            queue: dict) -> tuple[dict, int]:
    """監視用の JSON と、HTTP の状態コード。全部が正常なときだけ 200。"""
    database = database_status(conn, db_path, cfg)
    collectors = collectors_status(conn, now, cfg)
    llm = {"ok": snapshot.llm.ok, "detail": snapshot.llm.detail, "kind": snapshot.llm.kind,
           "checked_at": to_iso(snapshot.llm.checked_at) if snapshot.llm.checked_at else None}
    knowledge = {"ok": snapshot.knowledge.loaded, "version": snapshot.knowledge.version,
                 "age_days": snapshot.knowledge.age_days, "stale": snapshot.knowledge.stale,
                 "source_changed": snapshot.knowledge.source_changed, "detail": snapshot.knowledge.detail}
    problems = []
    if not database["ok"]:
        problems.append(f"database: {database['detail']}")
    if not knowledge["ok"]:
        problems.append(f"knowledge: {knowledge['detail']}")
    if llm["ok"] is False:
        problems.append(f"llm: {llm['detail']}")
    for name, item in collectors.items():
        if not item["ok"]:
            problems.append(f"{name}: {item['detail']}")
    if queue.get("stalled"):
        problems.append(f"queue: 最も古い待ちが {queue.get('oldest_waiting_sec')} 秒")
    body = {"status": "ok" if not problems else "degraded", "time": to_iso(now), "problems": problems,
            "database": database, "knowledge": knowledge, "llm": llm, "collectors": collectors, "queue": queue}
    return body, (200 if not problems else 503)
