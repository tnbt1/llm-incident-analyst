"""解析のコマンド。`tia analyze` と `tia show`。"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from tia import db, queue
from tia.analysis import records, worker
from tia.analysis.llm import LlmClient
from tia.analysis.schema import KIND_LABELS, URGENCY_LABELS
from tia.collectors.base import SourceError
from tia.collectors.endpoints import EndpointError, load_endpoints, load_llm_endpoint
from tia.probes.setup import build_runner
from tia.config import load_config
from tia.knowledge.bundle import BundleError, load_bundle

log = logging.getLogger("tia.analyze")


def parse_incident(text: str) -> int:
    """`I-0001` でも `1` でも受け付ける。"""
    value = text.strip().upper()
    if value.startswith("I-"):
        value = value[2:]
    if not value.isdigit():
        raise ValueError(f"インシデントは I-0001 か 1 の形で書く: {text!r}")
    return int(value)


def _clock(args: argparse.Namespace):
    if not args.now:
        return worker.utc_now
    fixed = datetime.fromisoformat(args.now)
    if fixed.tzinfo is None:
        raise ValueError("--now にはタイムゾーンを付ける")
    return lambda: fixed


def _deps(args: argparse.Namespace, cfg) -> worker.Deps:
    endpoint = load_llm_endpoint(model=cfg.llm_model)
    if not endpoint.url.endswith("/openai") and not cfg.llm_allow_other_route:
        # 決めた経路は Open WebUI の中継経路。主経路（/api）は JSON スキーマを壊すので、間違いは起動時に止める
        raise EndpointError("TIA_LLM_URL は Open WebUI の中継経路（末尾が /openai）にする。"
                            "別の経路を使うなら llm.allow_other_route を true にする")
    client = LlmClient.from_endpoint(endpoint, cfg)
    bundle = load_bundle(Path(args.knowledge) if args.knowledge else Path(cfg.knowledge_bundle_dir))
    return worker.Deps(client, bundle, probes=build_runner(cfg, load_endpoints()))


def _print_outcome(outcome: worker.Outcome) -> None:
    if outcome.kind == "idle":
        print("解析するものがない")
        return
    label = f"I-{outcome.incident_id:04d}" if outcome.incident_id else "-"
    analysis = f" analysis={outcome.analysis_id}" if outcome.analysis_id else ""
    detail = f" {outcome.detail}" if outcome.detail else ""
    print(f"{label} {outcome.kind}{analysis}{detail}")


def _analyze(args: argparse.Namespace) -> int:
    """終了コードは、成功と idle が 0、解析の失敗か待ち戻しが 1、設定の誤りが 2。"""
    try:
        cfg = load_config(args.config)
        clock = _clock(args)
        deps = _deps(args, cfg)
    except (ValueError, OSError, EndpointError, BundleError, SourceError) as exc:
        print(f"設定の誤り: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # 届くかどうかを起動時に 1 回だけ記録に出す。届かなくても起動は続け、常駐なら待ちながら張り直す
    health = deps.client.health()
    log.log(logging.INFO if health.ok else logging.WARNING, "LLM の確認: %s", health.detail)
    with closing(db.connect(args.db)) as conn, _stop_on_signals() as stop:
        recovered = worker.recover(conn, clock)
        if any(recovered):
            log.info("起動時に解析中のまま残っていたものを戻した: インシデント %d 件、解析の行 %d 件", *recovered)
        try:
            if args.replay:
                try:
                    incident_id = parse_incident(args.replay)
                    outcome = worker.replay(conn, incident_id, cfg, deps, clock, stop)
                except ValueError as exc:
                    print(f"再生できない: {exc}", file=sys.stderr)
                    return 2
                _print_outcome(outcome)
                return 0 if outcome.kind == "done" else 1
            if args.once:
                # 収集が動いていなくても試せるよう、待ち明けの繰り上げだけはここで行う
                queue.promote_held(conn, clock())
                outcome = worker.run_once(conn, cfg, deps, clock, stop)
                _print_outcome(outcome)
                return 0 if outcome.kind in ("done", "idle") else 1
            count = worker.run_loop(conn, cfg, deps, stop, clock, promote=True)
        except (queue.StateError, records.RecordError) as exc:
            print(f"解析できない: {exc}", file=sys.stderr)
            return 1
        log.info("止める合図を受けて終了した。解析は %d 件", count)
    return 0


@contextmanager
def _stop_on_signals() -> Iterator[threading.Event]:
    """SIGTERM と SIGINT を止める合図に結ぶ。要求の途中でも、数秒で待ちに戻して終われる。"""
    stop = threading.Event()
    previous = {number: signal.signal(number, lambda *_: stop.set()) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield stop
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _show(args: argparse.Namespace) -> int:
    try:
        incident_id = parse_incident(args.incident)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    with closing(db.connect(args.db)) as conn:
        incident = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if incident is None:
            print(f"I-{incident_id:04d} はない", file=sys.stderr)
            return 1
        print(f"I-{incident['id']:04d} {incident['analysis_state']} {incident['problem_status']} {incident['source']} "
              f"{incident['host']} {incident['type']} {incident['source_severity']} | {incident['title']}")
        print(f"  発生 {incident['started_at']} 復旧 {incident['resolved_at'] or '-'} 回数 {incident['occurrence_count']}"
              f" 試行 {incident['attempt_count']} 理由 {incident['queue_reason']}")
        if incident["urgency"]:
            print(f"  緊急度 {URGENCY_LABELS.get(incident['urgency'], incident['urgency'])} "
                  f"種別 {KIND_LABELS.get(incident['kind'], incident['kind'])} | {incident['summary']}")
        if incident["fail_reason"] or incident["skip_reason"]:
            print(f"  理由 {incident['fail_reason'] or incident['skip_reason']}")
        print("経過:")
        for event in conn.execute("SELECT at, type, detail_json FROM events WHERE incident_id = ? ORDER BY id",
                                  (incident_id,)):
            detail = event["detail_json"] if event["detail_json"] not in ("{}", None) else ""
            print(f"  {event['at']} {event['type']} {detail}".rstrip())
        rows = records.for_incident(conn, incident_id)
        print(f"解析: {len(rows)} 件")
        for row in rows:
            duration = f"{row['duration_ms'] / 1000:.1f} 秒" if row["duration_ms"] is not None else "-"
            print(f"  #{row['id']} {row['trigger']} {row['status']} {row['phase']} {duration} 入力 {row['prompt_tokens']} "
                  f"出力 {row['completion_tokens']} 速度 {row['tokens_per_sec']} 版 {row['knowledge_version']} "
                  f"hash {row['prompt_hash']}" + (f" | {row['error_kind']}: {row['error']}" if row["error_kind"] else ""))
        for row in rows:
            if row["status"] == "failed" and records.failed_output(row) is not None:
                print(f"失敗した出力: #{row['id']}")
                print(json.dumps(records.failed_output(row), ensure_ascii=False, indent=2))
        latest = records.latest_done(conn, incident_id)
        if latest is not None:
            for item in (records.result_of(latest) or {}).get("excluded_checks") or []:
                # コマンドの文は出さない。目的と理由だけ
                print(f"  規則により除外した確認: {item.get('purpose', '')}（{item.get('reason', '')}）")
            if args.result:
                print("最新の結果:")
                print(json.dumps(records.result_of(latest), ensure_ascii=False, indent=2))
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    analyze = sub.add_parser("analyze", help="待ち行列のインシデントを LLM で解析する。接続先は環境変数で渡す")
    analyze.add_argument("--db", required=True)
    analyze.add_argument("--config", type=Path, default=None)
    analyze.add_argument("--knowledge", default=None, help="知識の束の場所。省略すると設定の knowledge.bundle_dir")
    mode = analyze.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="1 件だけ解析して終わる")
    mode.add_argument("--replay", metavar="INCIDENT", help="保存済みのインシデントを解析し直す。状態は変えない")
    analyze.add_argument("--now", default=None, help="時刻を固定する。ISO 8601、タイムゾーン付き")
    analyze.set_defaults(func=_analyze)
    show = sub.add_parser("show", help="インシデントの経過と解析を表示する")
    show.add_argument("--db", required=True)
    show.add_argument("incident", help="I-0001 か 1")
    show.add_argument("--result", action="store_true", help="最新の結果の JSON も表示する")
    show.set_defaults(func=_show)
