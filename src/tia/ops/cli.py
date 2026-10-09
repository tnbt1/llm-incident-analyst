"""運用のコマンド。`tia housekeeping`、`tia backup`、`tia restore`、`tia run`。"""
from __future__ import annotations

import argparse
import logging
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from tia import db
from tia.config import load_config
from tia.ops import backup, retention


def _now(text: str | None) -> datetime:
    if not text:
        return datetime.now(UTC)
    value = datetime.fromisoformat(text)
    if value.tzinfo is None:
        raise ValueError("--now にはタイムゾーンを付ける")
    return value


def _housekeeping(args: argparse.Namespace) -> int:
    """終了コードは、成功が 0、設定の誤りが 2。"""
    try:
        cfg = load_config(args.config)
        now = _now(args.now)
        path = Path(args.db)
        if not path.is_file():
            raise ValueError(f"保存先がない: {path}")
    except (ValueError, OSError) as exc:
        print(f"設定の誤り: {exc}", file=sys.stderr)
        return 2
    with closing(db.connect(path)) as conn:
        report = retention.apply(conn, now, cfg, dry_run=args.dry_run)
    print(("乾いた実行。" if args.dry_run else "") + report.summary())
    return 0


def _backup(args: argparse.Namespace) -> int:
    """終了コードは、成功が 0、できなかったときが 1。"""
    try:
        cfg = load_config(args.config)
        result = backup.backup(args.db, args.out or cfg.backup_dir, keep=args.keep or cfg.backup_keep,
                               now=_now(args.now), config_dir=args.config_dir)
    except (ValueError, OSError, backup.BackupError) as exc:
        print(f"バックアップできない: {exc}", file=sys.stderr)
        return 1
    print(result.summary())
    return 0


def _restore(args: argparse.Namespace) -> int:
    try:
        path = backup.restore(args.source, args.db)
    except (OSError, backup.BackupError) as exc:
        print(f"復元できない: {exc}", file=sys.stderr)
        return 1
    print(f"復元した: {path}")
    return 0


def _run(args: argparse.Namespace) -> int:
    """終了コードは 0（止める合図で終えた）、2（設定の誤り）、3（部品が倒れた）、4（別の司令塔が動いている）。"""
    from tia.collectors.base import SourceError
    from tia.collectors.endpoints import EndpointError
    from tia.knowledge.bundle import BundleError
    from tia.ops import service

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("httpx", "httpcore", "uvicorn"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    try:
        plan = service.prepare(args)
    except (ValueError, OSError, KeyError, TypeError, EndpointError, BundleError, SourceError) as exc:
        print(f"設定の誤り: {exc}", file=sys.stderr)
        return service.EXIT_CONFIG
    return service.run_service(plan)


def register(sub: argparse._SubParsersAction) -> None:
    run = sub.add_parser("run", help="司令塔を動かす。収集、解析、画面を 1 つのプロセスで")
    run.add_argument("--db", required=True)
    run.add_argument("--config", type=Path, default=None)
    run.add_argument("--type-rules", type=Path, default=Path("config/type-rules.yaml"))
    run.add_argument("--knowledge", default=None, help="知識の束の場所。省略すると設定の knowledge.bundle_dir")
    run.add_argument("--host", default=None, help="画面の待受のアドレス。省略すると設定の web.host")
    run.add_argument("--port", type=int, default=None, help="画面の待受のポート。省略すると設定の web.port")
    run.add_argument("--no-analysis", action="store_true", help="解析のワーカーを動かさない。段階 2 の収集だけの運用")
    run.add_argument("--config-dir", type=Path, default=None, help="バックアップに固める設定のフォルダ。省略すると --config の場所")
    run.set_defaults(func=_run)
    housekeeping = sub.add_parser("housekeeping", help="保持期間の整理を 1 回行う")
    housekeeping.add_argument("--db", required=True)
    housekeeping.add_argument("--config", type=Path, default=None)
    housekeeping.add_argument("--now", default=None, help="時刻を固定する。ISO 8601、タイムゾーン付き")
    housekeeping.add_argument("--dry-run", action="store_true", help="消さずに数だけを出す")
    housekeeping.set_defaults(func=_housekeeping)
    take = sub.add_parser("backup", help="保存先の写しを取る。設定と知識の束も固める")
    take.add_argument("--db", required=True)
    take.add_argument("--out", default=None, help="世代を置く場所。省略すると設定の backup.dir")
    take.add_argument("--keep", type=int, default=None, help="残す世代の数。省略すると設定の backup.keep")
    take.add_argument("--config", type=Path, default=None)
    take.add_argument("--config-dir", type=Path, default=None, help="一緒に固める設定のフォルダ。secrets/ は入れない")
    take.add_argument("--now", default=None, help="時刻を固定する。ISO 8601、タイムゾーン付き")
    take.set_defaults(func=_backup)
    put_back = sub.add_parser("restore", help="写しで保存先を置き換える。司令塔を止めてから行う")
    put_back.add_argument("--from", dest="source", required=True, help="世代のフォルダの tia.sqlite")
    put_back.add_argument("--db", required=True)
    put_back.set_defaults(func=_restore)
