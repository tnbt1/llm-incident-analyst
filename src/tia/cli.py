"""コマンドの入口。採取済みのデータの取り込みと、常駐の収集。"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from collections import Counter
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from tia import db, grouping, intake, queue
from tia.analysis.cli import register as register_analysis
from tia.collectors.endpoints import load_endpoints
from tia.collectors.runner import CycleReport, build_pollers, run_cycle, run_loop
from tia.config import load_config
from tia.config_cli import register as register_config
from tia.knowledge.cli import register as register_knowledge
from tia.ops.cli import register as register_ops
from tia.normalize import NormalizationError, normalize_wazuh, normalize_zabbix
from tia.type_rules import load_type_rules
from tia.web.cli import register as register_web


def _ingest(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    rules = load_type_rules(args.type_rules)
    now = datetime.fromisoformat(args.now) if args.now else datetime.now(UTC)
    items = json.loads(Path(args.file).read_text(encoding="utf-8"))
    if not isinstance(items, list):
        print("入力は配列で書く", file=sys.stderr)
        return 2
    normalize = normalize_zabbix if args.source == "zabbix" else normalize_wazuh
    outcomes: Counter[str] = Counter()
    with closing(db.connect(args.db)) as conn:
        for item in items:
            try:
                outcomes[intake.apply(conn, normalize(item, cfg, rules), now, cfg).outcome] += 1
            except NormalizationError as exc:
                outcomes["rejected"] += 1
                print(f"読み飛ばし: {exc}", file=sys.stderr)
        if grouping.evaluate(conn, now, cfg) is not None:
            outcomes["group"] += 1
        queue.promote_held(conn, now)
    print(" ".join(f"{name}={count}" for name, count in sorted(outcomes.items())) or "取り込みなし")
    return 0


def _list(args: argparse.Namespace) -> int:
    with closing(db.connect(args.db)) as conn:
        for row in conn.execute("SELECT id, source, host, type, source_severity, analysis_state, problem_status, "
                                "occurrence_count, title FROM incidents ORDER BY id"):
            print(f"I-{row['id']:04d} {row['analysis_state']:<10} {row['problem_status']:<8} {row['source']:<6} "
                  f"{row['host']:<28} {row['type']:<9} x{row['occurrence_count']} {row['source_severity']} | "
                  f"{row['title']}")
    return 0


def _print_cycle(report: CycleReport) -> None:
    for run in report.runs:
        if run.status == "ok":
            counts = " ".join(f"{name}={count}" for name, count in sorted(run.report.counts.items()))
            note = "" if run.report.complete else " 読み切っていない"
            print(f"{run.source} ok {counts or '変化なし'}{note}")
        else:
            print(f"{run.source} {run.status} {run.error_kind} {run.error}")
    tidy = report.tidy
    if tidy.error:
        print(f"tidy failed {tidy.error}")
    else:
        print(f"tidy promoted={tidy.promoted} group={tidy.group_id or '-'} followups={tidy.followups}")


def _collect(args: argparse.Namespace) -> int:
    """終了コードは、成功が 0、収集か整理の失敗が 1、設定の誤りが 2。"""
    try:
        cfg = load_config(args.config)
        rules = load_type_rules(args.type_rules)
        pollers = build_pollers(load_endpoints())
        now = datetime.fromisoformat(args.now) if args.now else None
        if now is not None and now.tzinfo is None:
            raise ValueError("--now にはタイムゾーンを付ける")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"設定の誤り: {exc}", file=sys.stderr)
        return 2
    if not pollers:
        print("収集する系統がない。TIA_ZABBIX_URL か TIA_WAZUH_URL を設定する", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # 通信の部品は、要求のたびに 1 行を出す。収集の記録を埋めてしまうので、警告からにする。
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    with closing(db.connect(args.db)) as conn:
        if args.once:
            report = run_cycle(conn, pollers, now or datetime.now(UTC), cfg, rules, force=True)
            _print_cycle(report)
            return 1 if report.failed else 0
        stop = threading.Event()
        previous = {number: signal.signal(number, lambda *_: stop.set())
                    for number in (signal.SIGTERM, signal.SIGINT)}
        try:
            cycles = run_loop(conn, pollers, cfg, rules, stop)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
        logging.getLogger("tia.collect").info("止める合図を受けて終了した。周期は %d 回", cycles)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tia", description="Incident Analyst")
    sub = parser.add_subparsers(dest="command", required=True)
    register_knowledge(sub)
    register_analysis(sub)
    register_web(sub)
    register_ops(sub)
    register_config(sub)
    ingest = sub.add_parser("ingest", help="採取済みの JSON を取り込む")
    ingest.add_argument("--db", required=True)
    ingest.add_argument("--source", required=True, choices=["zabbix", "wazuh"])
    ingest.add_argument("--file", required=True)
    ingest.add_argument("--config", type=Path, default=None)
    ingest.add_argument("--type-rules", type=Path, default=Path("config/type-rules.yaml"))
    ingest.add_argument("--now", default=None, help="時刻を固定する。ISO 8601、タイムゾーン付き")
    ingest.set_defaults(func=_ingest)
    listing = sub.add_parser("list", help="保存済みのインシデントを表示する")
    listing.add_argument("--db", required=True)
    listing.set_defaults(func=_list)
    collect = sub.add_parser("collect", help="Zabbix と Wazuh から取り込み続ける。接続先は環境変数で渡す")
    collect.add_argument("--db", required=True)
    collect.add_argument("--config", type=Path, default=None)
    collect.add_argument("--type-rules", type=Path, default=Path("config/type-rules.yaml"))
    collect.add_argument("--once", action="store_true", help="1 回だけ収集して終わる。待ちは無視する")
    collect.add_argument("--now", default=None, help="--once の時刻を固定する。ISO 8601、タイムゾーン付き")
    collect.set_defaults(func=_collect)
    args = parser.parse_args(argv)
    if args.command == "collect" and args.now and not args.once:
        parser.error("--now は --once と一緒に使う")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
