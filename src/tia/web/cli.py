"""画面のコマンド。`tia web` と `tia web --check`。"""
from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import threading
import time
from pathlib import Path

from tia.analysis.llm import LlmClient
from tia.collectors.base import SourceError
from tia.collectors.endpoints import EndpointError, load_llm_endpoint
from tia.config import load_config

log = logging.getLogger("tia.web")


def _probe(cfg, *, env=None):
    """LLM の稼働の確認。接続先を設定できなければ (None, 理由)。理由は `/healthz` と画面に失敗として出る。"""
    try:
        endpoint = load_llm_endpoint(model=cfg.llm_model) if env is None else load_llm_endpoint(env, model=cfg.llm_model)
        client = LlmClient.from_endpoint(endpoint, cfg)
    except (EndpointError, SourceError, OSError, ValueError) as exc:
        log.warning("LLM の接続先を設定できない: %s", exc)
        return None, str(exc)
    return client.health, None


def _check_database(path: Path) -> None:
    """保存先は、収集が作った既存のファイルだけを受ける。綴りの誤りで空の保存先を作らない。"""
    if not path.is_file():
        raise ValueError(f"保存先がない: {path}。収集（tia collect）が作ったファイルを指定する")
    try:
        probe = sqlite3.connect(str(path))
        try:
            probe.execute("PRAGMA schema_version").fetchone()
        finally:
            probe.close()
    except sqlite3.Error as exc:
        raise ValueError(f"保存先を開けない: {path}（{type(exc).__name__}: {exc}）") from None


def build(args: argparse.Namespace):
    """設定を読み、アプリを組み立てる。設定の誤りは ValueError か OSError。"""
    from tia.web.app import create_app

    cfg = load_config(args.config)
    db_path = Path(args.db)
    _check_database(db_path)
    bundle_dir = Path(args.knowledge) if args.knowledge else Path(cfg.knowledge_bundle_dir)
    source_dir = Path(cfg.knowledge_source_dir) if Path(cfg.knowledge_source_dir).is_dir() else None
    probe, probe_error = (None, None) if args.check else _probe(cfg)
    interval = None if args.check else float(cfg.web_health_interval_sec)
    return create_app(db_path, cfg, bundle_dir=bundle_dir, source_dir=source_dir, llm_probe=probe,
                      llm_probe_error=probe_error, monitor_interval_sec=interval), cfg


def _web(args: argparse.Namespace) -> int:
    """終了コードは、成功が 0、描画や起動の失敗が 1、設定の誤りが 2。"""
    try:
        app, cfg = build(args)
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(f"設定の誤り: {exc}", file=sys.stderr)
        return 2
    if args.check:
        from tia.web.routes import check

        app.state.tia.monitor.refresh()
        try:
            page, body, status = check(app)
        except Exception as exc:  # noqa: BLE001 - 描けない理由を 1 行で示して終わる
            print(f"一覧を描けない: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        print(f"一覧 {len(page):,} 文字、/healthz {status} {body['status']}"
              + (": " + "、".join(body["problems"]) if body.get("problems") else ""))
        return 0
    import uvicorn

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    host = args.host or cfg.web_host
    port = args.port or cfg.web_port
    log.info("画面を %s:%d で待ち受ける", host, port)
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning", proxy_headers=False,
                                           server_header=False, date_header=False, timeout_graceful_shutdown=5))

    def relay_stop() -> None:
        # uvicorn が合図を受けたら、開いたままの SSE に「: shutdown」を送らせる
        while not server.should_exit and not server.force_exit:
            time.sleep(0.2)
        app.state.tia.stopping.set()

    threading.Thread(target=relay_stop, name="tia-web-stop", daemon=True).start()
    try:
        server.run()
    finally:
        app.state.tia.stopping.set()
        app.state.tia.monitor.stop()
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    web = sub.add_parser("web", help="画面を動かす。認証は Caddy が行う")
    web.add_argument("--db", required=True)
    web.add_argument("--config", type=Path, default=None)
    web.add_argument("--knowledge", default=None, help="知識の束の場所。省略すると設定の knowledge.bundle_dir")
    web.add_argument("--host", default=None, help="待受のアドレス。省略すると設定の web.host")
    web.add_argument("--port", type=int, default=None, help="待受のポート。省略すると設定の web.port")
    web.add_argument("--check", action="store_true", help="一覧を 1 回描いて終わる。待ち受けない")
    web.set_defaults(func=_web)
