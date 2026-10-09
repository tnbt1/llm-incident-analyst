"""解析の実行。待ち行列から 1 件ずつ取り、文脈を組み、LLM を呼び、検証して記録する。"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from tia import db, queue
from tia.analysis import records
from tia.analysis.context import Context, ContextError, assemble
from tia.analysis.llm import RELEASE_KINDS, LlmClient, LlmError, LlmResult
from tia.analysis.schema import response_format
from tia.analysis.validate import Problem, Validation, validate_output
from tia.config import Config
from tia.intake import add_event
from tia.knowledge.bundle import Bundle
from tia.knowledge.safety import neutralise
from tia.knowledge.tokens import TokenCounter, estimate_tokens
from tia.models import AnalysisState
from tia.probes import store as probe_store
from tia.probes.runner import ProbeResult, Runner, from_rows, store_results

log = logging.getLogger("tia.analyze")
Clock = Callable[[], datetime]
REGENERATION_NOTE = ("前の出力は検証に失敗した: {problems}。同じ資料に基づいて、決められた形の JSON だけを"
                     "もう一度返す。区切りのタグを出力に含めない。変更や破壊を伴う操作を提案しない。")
LENGTH_NOTE = ("前の出力は上限の {max_tokens} トークンに達して途中で切れた。各項目を短く、要点だけにして、"
               "決められた形の JSON だけをもう一度返す。")


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class Deps:
    """ワーカーが使う部品。テストでは偽の LLM と小さな束を渡す。"""
    client: LlmClient
    bundle: Bundle
    counter: TokenCounter = estimate_tokens
    # 確認（読み取りだけの照会）。None なら行わない
    probes: Runner | None = None


@dataclass(frozen=True)
class Outcome:
    kind: str  # idle / done / retry_wait / failed / released
    incident_id: int | None = None
    analysis_id: int | None = None
    detail: str = ""

    @property
    def release_kind(self) -> str:
        """待ちに戻した理由の種類。released 以外は空。"""
        return self.detail.split(":", 1)[0] if self.kind == "released" else ""


# 待ちに戻した理由のうち、LLM の側が原因で、次もすぐには成功しないもの。止める合図（stopped）は含めない。
BACKOFF_KINDS = frozenset({"unreachable", "server", "auth", "tls", "throttled", "invalid_response"})
# 同じ入力でやり直しても直らない失敗。作り直し 1 回で確定し、再試行の予約をしない。
NO_RETRY_KINDS = frozenset({"validation", "length"})
FAILED_OUTPUT_LIMIT = 8000


@dataclass
class Backoff:
    """LLM に届かない間の待ち。倍々で延ばし、上限で止める。成功で戻す。

    待っている間は、待ち行列に触れず、解析の行も出来事も作らない（待ち行列に滞留させる）。
    """
    min_sec: int
    max_sec: int
    auth_sec: int
    wait_sec: int = 0

    @property
    def active(self) -> bool:
        return self.wait_sec > 0

    def failed(self, kind: str) -> int:
        """失敗を 1 回数え、次に待つ秒数を返す。"""
        if kind == "auth":
            self.wait_sec = self.auth_sec
        elif self.wait_sec <= 0:
            self.wait_sec = self.min_sec
        else:
            self.wait_sec = min(self.wait_sec * 2, self.max_sec)
        return self.wait_sec

    def reset(self) -> None:
        self.wait_sec = 0


def _trigger(incident: sqlite3.Row) -> str:
    if incident["queue_reason"] == "followup":
        return "followup"
    if incident["queue_reason"] == "manual":
        return "manual"
    return "retry" if incident["attempt_count"] > 1 else "initial"


def _row(conn: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
    return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()


class _Progress:
    """受け取った断片の数を、決まった間隔で解析の行に書く。

    書けなくても推論は止めない。鍵待ちで失敗したら 1 回だけ記録に出し、続きは黙って飛ばす。
    """

    def __init__(self, conn: sqlite3.Connection, analysis_id: int, clock: Clock, every: int) -> None:
        self._conn, self._id, self._clock, self._every = conn, analysis_id, clock, every
        self._last = 0
        self._warned = False

    def __call__(self, chunks: int) -> None:
        if chunks - self._last < self._every:
            return
        self._last = chunks
        try:
            records.progress(self._conn, self._id, "inference", self._clock(), tokens_so_far=chunks)
        except (sqlite3.Error, records.RecordError) as exc:
            if not self._warned:
                self._warned = True
                log.warning("解析 %d の進捗を保存できない（%s）。推論は続ける", self._id, type(exc).__name__)


def _infer(deps: Deps, ctx: Context, cfg: Config, *, stop: threading.Event | None,
           progress: Callable[[int], None] | None) -> tuple[LlmResult, Validation, LlmResult | None]:
    """推論と検証。検証に失敗したら、temperature を下げて 1 回だけ作り直す。

    返すのは、最後の結果、その検証、最初の結果（作り直したときだけ）。
    """
    first = deps.client.complete(ctx.messages(), response_format=response_format(), stop=stop, on_progress=progress)
    validation = _validate(first, ctx, cfg)
    if validation.ok:
        return first, validation, None
    if first.finish_reason == "length":
        note = LENGTH_NOTE.format(max_tokens=cfg.llm_max_tokens)
    else:
        note = REGENERATION_NOTE.format(problems=validation.summary())
    # 前の出力は無害にしてから戻す。制御文字や特殊な印をそのまま次の要求に入れない
    retry_messages = ctx.messages() + [
        {"role": "assistant", "content": neutralise(first.content)[0]},
        {"role": "user", "content": note},
    ]
    second = deps.client.complete(retry_messages, response_format=response_format(),
                                  temperature=cfg.llm_retry_temperature, stop=stop, on_progress=progress)
    return second, _validate(second, ctx, cfg), first


def _validate(result: LlmResult, ctx: Context, cfg: Config) -> Validation:
    if result.finish_reason == "length":
        return Validation((Problem("$", f"出力が上限の {cfg.llm_max_tokens} トークンに達して途中で切れた。短く答える"),),
                          None)
    try:
        data = json.loads(result.content)
    except ValueError:
        return Validation((Problem("$", "出力が JSON として読めない"),), None)
    return validate_output(data, ctx.templates)


def analyse(conn: sqlite3.Connection, incident: sqlite3.Row, cfg: Config, deps: Deps, clock: Clock, *,
            trigger: str, stop: threading.Event | None = None, change_state: bool = True) -> Outcome:
    """1 件を解析する。change_state が偽なら（再生）、インシデントの状態と待ち行列には触れない。"""
    incident_id = incident["id"]
    analysis_id = records.begin(conn, incident_id, trigger, deps.client.endpoint.model, clock(),
                                attempt=max(1, incident["attempt_count"]))
    started = time.monotonic()
    probe_results = _probe(conn, incident, cfg, deps, clock, analysis_id, trigger, stop)
    try:
        always = frozenset(name for name, p in deps.probes.catalog.probes.items() if "always" in p.when) if deps.probes else frozenset()
        ctx = assemble(conn, incident, deps.bundle, cfg, clock(), counter=deps.counter, probes=probe_results,
                       always_probes=always)
    except ContextError as exc:
        return _failed(conn, incident_id, analysis_id, cfg, clock, "context", str(exc), change_state)
    for note in ctx.notes:
        log.info("I-%04d 文脈: %s", incident_id, note)
    records.attach_context(conn, analysis_id, clock(), context=ctx.to_json(), prompt_hash=ctx.prompt_hash,
                           knowledge_version=ctx.knowledge_version, prompt_tokens=ctx.tokens)
    progress = _Progress(conn, analysis_id, clock, cfg.worker_progress_every_chunks)
    try:
        result, validation, first = _infer(deps, ctx, cfg, stop=stop, progress=progress)
    except LlmError as exc:
        if exc.kind in RELEASE_KINDS:
            return _released(conn, incident_id, analysis_id, clock, exc.kind, str(exc), change_state)
        return _failed(conn, incident_id, analysis_id, cfg, clock, exc.kind, str(exc), change_state)
    try:
        records.progress(conn, analysis_id, "validation", clock(), tokens_so_far=result.chunks)
    except sqlite3.OperationalError as exc:
        log.warning("解析 %d の段階を保存できない（%s）。検証は続ける", analysis_id, type(exc).__name__)
    if first is not None:
        add_event(conn, incident_id, clock(), "regenerated", {"analysis_id": analysis_id})
    if not validation.ok:
        kind = "length" if result.finish_reason == "length" else "validation"
        return _failed(conn, incident_id, analysis_id, cfg, clock, kind, validation.summary(), change_state,
                       output=_failed_output(result))
    output = validation.output
    assert output is not None
    if validation.excluded:
        log.info("I-%04d 規則により除外した確認 %d 件: %s", incident_id, validation.excluded,
                 "、".join(item["reason"] for item in output["excluded_checks"]))
        add_event(conn, incident_id, clock(), "checks_excluded",
                  {"analysis_id": analysis_id, "count": validation.excluded,
                   "reasons": sorted({item["reason"] for item in output["excluded_checks"]})})
    now = clock()
    records.finish(conn, analysis_id, now, status="done", result=output,
                   prompt_tokens=result.prompt_tokens if result.prompt_tokens is not None else ctx.tokens,
                   completion_tokens=result.completion_tokens if result.completion_tokens is not None else result.chunks,
                   tokens_per_sec=result.tokens_per_sec)
    if change_state:
        queue.complete(conn, incident_id, now, urgency=output["classification"]["urgency"],
                       kind=output["classification"]["kind"], summary=output["summary"], analysis_id=analysis_id)
    log.info("I-%04d 解析完了 analysis=%d %.1f 秒 入力 %s 出力 %s", incident_id, analysis_id,
             time.monotonic() - started, result.prompt_tokens, result.completion_tokens or result.chunks)
    return Outcome("done", incident_id, analysis_id)


def _probe(conn: sqlite3.Connection, incident: sqlite3.Row, cfg: Config, deps: Deps, clock: Clock, analysis_id: int,
           trigger: str, stop: threading.Event | None) -> list[ProbeResult]:
    """段階 1 の確認。推論の前に動かし、結果を保存して出来事を残す。運用者が画面から取った結果で、まだ解析に
    添えていないものも拾う。どんな失敗でも解析は進む。"""
    if deps.probes is None or not cfg.probes_enabled:
        return []
    incident_id = incident["id"]
    try:
        pending = probe_store.unattached(conn, incident_id)
        probes = deps.probes.plan(incident)
        results = deps.probes.run(probes, incident, stop=stop) if probes else []
        with db.transaction(conn):
            store_results(conn, incident_id, analysis_id, "replay" if trigger == "replay" else "initial", results)
            if pending:
                probe_store.attach(conn, [row["id"] for row in pending], analysis_id)
            add_event(conn, incident_id, clock(), "probed",
                      {"analysis_id": analysis_id, "count": len(results) + len(pending),
                       "ok": sum(r.status == "ok" for r in results) + sum(row["status"] == "ok" for row in pending),
                       "failed": [r.name for r in results if r.status != "ok"]})
        log.info("I-%04d 確認 %d 件（成功 %d）", incident_id, len(results) + len(pending),
                 sum(r.status == "ok" for r in results))
        return from_rows(pending) + results
    except Exception as exc:  # noqa: BLE001 - 確認は解析を止めない
        log.warning("I-%04d 確認に失敗したので省く: %s: %s", incident_id, type(exc).__name__, exc)
        return []


def _failed_output(result: LlmResult) -> dict:
    """失敗した解析に残す出力。JSON として読めれば無害にした対応表、読めなければ文の先頭だけ。"""
    text = neutralise(result.content or "")[0]
    try:
        data = json.loads(text)
    except ValueError:
        return {"failed_output": text[:FAILED_OUTPUT_LIMIT]}
    return {"failed_output": data if isinstance(data, dict) else text[:FAILED_OUTPUT_LIMIT]}


def _failed(conn: sqlite3.Connection, incident_id: int, analysis_id: int, cfg: Config, clock: Clock, kind: str,
            message: str, change_state: bool, *, output: dict | None = None) -> Outcome:
    now = clock()
    records.finish(conn, analysis_id, now, status="failed", error_kind=kind, error=message, result=output)
    log.warning("I-%04d 解析失敗 analysis=%d %s: %s", incident_id, analysis_id, kind, message)
    if not change_state:
        return Outcome("failed", incident_id, analysis_id, f"{kind}: {message}")
    state = queue.fail(conn, incident_id, now, f"{kind}: {message}"[:records.ERROR_LIMIT], cfg,
                       retry=kind not in NO_RETRY_KINDS)
    return Outcome("retry_wait" if state == AnalysisState.RETRY_WAIT else "failed", incident_id, analysis_id,
                   f"{kind}: {message}")


def _released(conn: sqlite3.Connection, incident_id: int, analysis_id: int, clock: Clock, kind: str, message: str,
              change_state: bool) -> Outcome:
    now = clock()
    records.finish(conn, analysis_id, now, status="released", error_kind=kind, error=message)
    log.warning("I-%04d 解析を待ちに戻した analysis=%d %s: %s", incident_id, analysis_id, kind, message)
    if change_state:
        queue.release(conn, incident_id, now, kind)
    return Outcome("released", incident_id, analysis_id, f"{kind}: {message}")


def run_once(conn: sqlite3.Connection, cfg: Config, deps: Deps, clock: Clock = utc_now,
             stop: threading.Event | None = None) -> Outcome:
    """待ち行列の先頭の 1 件を解析する。何もなければ idle。"""
    if stop is not None and stop.is_set():
        return Outcome("idle", detail="stop")
    now = clock()
    incident = queue.next_candidate(conn, now, cfg)
    if incident is None:
        return Outcome("idle")
    queue.start(conn, incident["id"], now)
    incident = _row(conn, incident["id"])
    try:
        return analyse(conn, incident, cfg, deps, clock, trigger=_trigger(incident), stop=stop)
    except Exception as exc:  # 想定外。インシデントを running のまま残さない
        log.error("I-%04d 想定外の失敗 %s", incident["id"], type(exc).__name__, exc_info=True)
        running = records.for_incident(conn, incident["id"])
        for row in running:
            if row["status"] == "running":
                records.finish(conn, row["id"], clock(), status="failed", error_kind="internal",
                               error=f"想定外の失敗（{type(exc).__name__}）")
        if _row(conn, incident["id"])["analysis_state"] == AnalysisState.RUNNING:
            state = queue.fail(conn, incident["id"], clock(), f"internal: {type(exc).__name__}", cfg)
            return Outcome("retry_wait" if state == AnalysisState.RETRY_WAIT else "failed", incident["id"], None,
                           f"internal: {type(exc).__name__}")
        return Outcome("failed", incident["id"], None, f"internal: {type(exc).__name__}")


def replay(conn: sqlite3.Connection, incident_id: int, cfg: Config, deps: Deps, clock: Clock = utc_now,
           stop: threading.Event | None = None) -> Outcome:
    """保存済みのインシデントを、いまのプロンプトと知識で解析し直す。状態は変えず、解析の行だけを足す。"""
    incident = _row(conn, incident_id)
    if incident is None:
        raise ValueError(f"インシデント {incident_id} がない")
    return analyse(conn, incident, cfg, deps, clock, trigger="replay", stop=stop, change_state=False)


def recover(conn: sqlite3.Connection, clock: Clock = utc_now) -> tuple[int, int]:
    """起動時に呼ぶ。解析中のまま残ったインシデントと解析の行を片付け、その数を返す。"""
    now = clock()
    return queue.recover_running(conn, now), records.abandon_running(conn, now)


def run_loop(conn: sqlite3.Connection, cfg: Config, deps: Deps, stop: threading.Event, clock: Clock = utc_now, *,
             promote: bool = False) -> int:
    """止める合図まで解析を続け、解析した件数を返す。promote が真なら、待ち明けの繰り上げも行う。

    LLM に届かない間は、待ち行列に触れずに待つ。待ちは倍々で延び、上限で止まり、届くようになったら戻る。
    """
    recovered = recover(conn, clock)
    if any(recovered):
        log.info("起動時に解析中のまま残っていたものを戻した: インシデント %d 件、解析の行 %d 件", *recovered)
    backoff = Backoff(cfg.worker_backoff_min_sec, cfg.worker_backoff_max_sec, cfg.worker_auth_backoff_sec)
    count = 0
    while not stop.is_set():
        if promote:
            queue.promote_held(conn, clock())
        if backoff.active:
            # 待ち明けは、推論の要求を送る前に、届くかどうかだけを確かめる。届かなければ待ち行列に触れない
            health = deps.client.health()
            if not health.ok:
                wait = backoff.failed(health.kind)
                log.warning("LLM に届かない（%s）。%d 秒待つ", health.detail, wait)
                stop.wait(wait)
                continue
        outcome = run_once(conn, cfg, deps, clock, stop)
        if outcome.kind == "idle":
            stop.wait(cfg.worker_idle_sec)
            continue
        count += 1
        if outcome.release_kind in BACKOFF_KINDS:
            wait = backoff.failed(outcome.release_kind)
            log.warning("LLM に届かないか、断られた（%s）。%d 秒待つ", outcome.detail, wait)
            stop.wait(wait)
        elif backoff.active:
            log.info("LLM に届くようになった")
            backoff.reset()
    return count
