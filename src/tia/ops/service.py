"""司令塔 `tia run`。収集、解析のワーカー 1 つ、稼働の確認、夜間の処理、画面を 1 つのプロセスで動かす。

スレッドごとに SQLite の接続を分ける。見張りは、欠かせない処理が 1 つでも倒れたら全体を止める。
同じ保存先で 2 つ目を動かさないよう、保存先の隣の .lock を flock で握る。
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
import traceback
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from tia import db
from tia.analysis import worker
from tia.analysis.llm import LlmClient
from tia.collectors.endpoints import EndpointError, load_endpoints, load_llm_endpoint
from tia.probes.setup import build_runner
from tia.collectors.runner import build_pollers
from tia.collectors.runner import run_loop as collect_loop
from tia.config import Config, load_config
from tia.knowledge.bundle import BundleError, load_bundle, resolve_bundle_dir
from tia.ops.lock import InstanceLock, LockError, lock_path  # noqa: F401 - 公開する
from tia.ops import backup as backup_mod
from tia.ops import retention
from tia.type_rules import load_type_rules

log = logging.getLogger("tia.run")
# 終了コード。0 は止める合図で終えた、2 は設定の誤り、3 は部品が倒れた、4 は別の司令塔が動いている
EXIT_OK, EXIT_CONFIG, EXIT_COMPONENT, EXIT_LOCKED = 0, 2, 3, 4
# Compose の stop_grace_period 30 秒より短く終える
GRACE_SEC = 25
START_TIMEOUT_SEC = 15


class Supervisor:
    """スレッドの見張り。欠かせないものが 1 つでも倒れたら全体を止める。

    止める合図は stop に集める。合図の後、on_stop の処理を 1 回だけ行い、猶予の間だけスレッドを待つ。
    """

    def __init__(self, stop: threading.Event, *, grace_sec: float = GRACE_SEC) -> None:
        self.stop = stop
        self.grace_sec = grace_sec
        self.failed: str | None = None
        self._threads: list[tuple[str, threading.Thread]] = []
        self._hooks: list[Callable[[], None]] = []
        self._hooks_done = False
        self._lock = threading.Lock()

    def on_stop(self, hook: Callable[[], None]) -> None:
        self._hooks.append(hook)

    def _fail(self, name: str) -> None:
        with self._lock:
            if self.failed is None:
                self.failed = name
        self.request_stop()

    def spawn(self, name: str, target: Callable[[], object], *, essential: bool = True) -> threading.Thread:
        def run() -> None:
            try:
                target()
            except BaseException as exc:  # noqa: BLE001 - SystemExit も倒れたとして扱う
                if isinstance(exc, SystemExit) and exc.code in (0, None) and self.stop.is_set():
                    return
                log.error("%s が倒れた: %s\n%s", name, type(exc).__name__,
                          "".join(traceback.format_exception(exc)).rstrip())
                if essential:
                    self._fail(name)
                return
            if essential and not self.stop.is_set():
                log.error("%s が止める合図なしに終わった", name)
                self._fail(name)

        thread = threading.Thread(target=run, name=f"tia-{name}", daemon=True)
        self._threads.append((name, thread))
        thread.start()
        return thread

    def request_stop(self) -> None:
        self.stop.set()
        with self._lock:
            if self._hooks_done:
                return
            self._hooks_done = True
        for hook in self._hooks:
            try:
                hook()
            except Exception:  # noqa: BLE001
                log.exception("止める処理で想定外の失敗")

    def wait(self) -> int:
        while not self.stop.wait(0.5):
            pass
        self.request_stop()
        deadline = time.monotonic() + self.grace_sec
        for _, thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        alive = [name for name, thread in self._threads if thread.is_alive()]
        if alive:
            log.error("猶予の %s 秒で止まらなかった: %s", self.grace_sec, ", ".join(alive))
        return EXIT_COMPONENT if self.failed else EXIT_OK


def next_run(now: datetime, at: str, zone: ZoneInfo) -> datetime:
    """at（HH:MM、zone の時計）の次の時刻。いまを過ぎていれば翌日。"""
    hour, minute = (int(part) for part in at.split(":"))
    local = now.astimezone(zone)
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= local:
        candidate += timedelta(days=1)
    return candidate.astimezone(UTC)


class Nightly:
    """夜間の処理。バックアップと保持期間の整理を、決めた時刻に 1 回ずつ行う。失敗は記録に出すだけで止めない。"""

    def __init__(self, db_path: Path, cfg: Config, config_dir: Path | None, clock: Callable[[], datetime]) -> None:
        self.db_path, self.cfg, self.config_dir, self.clock = db_path, cfg, config_dir, clock
        self.zone = ZoneInfo(cfg.web_timezone)
        now = clock()
        self.due = {"backup": next_run(now, cfg.backup_at, self.zone),
                    "retention": next_run(now, cfg.housekeeping_retention_at, self.zone)}

    def tick(self) -> list[str]:
        done = []
        now = self.clock()
        for job in ("backup", "retention"):
            if now < self.due[job]:
                continue
            try:
                getattr(self, f"run_{job}")(now)
            except Exception as exc:  # noqa: BLE001 - 夜間の処理の失敗で司令塔を止めない
                log.error("夜間の処理 %s で失敗した: %s: %s", job, type(exc).__name__, exc)
            at = self.cfg.backup_at if job == "backup" else self.cfg.housekeeping_retention_at
            self.due[job] = next_run(now, at, self.zone)
            done.append(job)
        return done

    def run_backup(self, now: datetime) -> None:
        result = backup_mod.backup(self.db_path, self.cfg.backup_dir, keep=self.cfg.backup_keep, now=now,
                                   config_dir=self.config_dir)
        log.info(result.summary())

    def run_retention(self, now: datetime) -> None:
        with closing(db.connect(self.db_path)) as conn:
            log.info(retention.apply(conn, now, self.cfg).summary())


class BundleReloader:
    """知識の束の入れ替えを見張る。current の指す先が変わったら読み直し、ワーカーの束を差し替える。"""

    def __init__(self, deps: worker.Deps, bundle_dir: Path, every_sec: float) -> None:
        self.deps, self.bundle_dir, self.every_sec = deps, Path(bundle_dir), every_sec
        self._next = 0.0
        self._warned = False

    def tick(self) -> str | None:
        if time.monotonic() < self._next:
            return None
        self._next = time.monotonic() + self.every_sec
        try:
            target = resolve_bundle_dir(self.bundle_dir)
            if target == self.deps.bundle.path:
                self._warned = False
                return None
            bundle = load_bundle(self.bundle_dir)
        except BundleError as exc:
            if not self._warned:
                self._warned = True
                log.warning("知識の束を読み直せない。前の束 %s のまま続ける: %s", self.deps.bundle.version, exc)
            return None
        self._warned = False
        self.deps.bundle = bundle
        log.info("知識の束を %s に入れ替えた（節 %d）", bundle.version, len(bundle.sections))
        return bundle.version


def _collector(db_path: Path, pollers, cfg: Config, rules, stop: threading.Event) -> None:
    with closing(db.connect(db_path)) as conn:
        cycles = collect_loop(conn, pollers, cfg, rules, stop)
    log.info("収集を終えた。周期は %d 回", cycles)


def _worker(db_path: Path, cfg: Config, deps: worker.Deps, stop: threading.Event) -> None:
    # 繰り上げは収集の整理が行うので promote=False
    with closing(db.connect(db_path)) as conn:
        count = worker.run_loop(conn, cfg, deps, stop, promote=False)
    log.info("解析を終えた。%d 件", count)


def _housekeeping(nightly: Nightly, reloader: BundleReloader | None, stop: threading.Event, every_sec: float) -> None:
    while not stop.is_set():
        nightly.tick()
        if reloader is not None:
            reloader.tick()
        stop.wait(every_sec)


def build_deps(cfg: Config, bundle_dir: Path) -> worker.Deps:
    """LLM の接続先と知識の束。宛先は Open WebUI の中継経路に限る。"""
    endpoint = load_llm_endpoint(model=cfg.llm_model)
    if not endpoint.url.endswith("/openai") and not cfg.llm_allow_other_route:
        raise EndpointError("TIA_LLM_URL は Open WebUI の中継経路（末尾が /openai）にする。"
                            "別の経路を使うなら llm.allow_other_route を true にする")
    return worker.Deps(LlmClient.from_endpoint(endpoint, cfg), load_bundle(bundle_dir),
                       probes=build_runner(cfg, load_endpoints()))


@dataclass
class Plan:
    """起動に要るものを、設定の確認が終わった形で持つ。"""
    cfg: Config
    rules: object
    pollers: list
    db_path: Path
    bundle_dir: Path
    config_dir: Path | None
    deps: worker.Deps | None
    host: str
    port: int


def prepare(args: argparse.Namespace) -> Plan:
    """設定、接続先、束を読む。誤りは ValueError の仲間で返す。"""
    cfg = load_config(args.config)
    rules = load_type_rules(args.type_rules)
    pollers = build_pollers(load_endpoints())
    if not pollers:
        raise ValueError("収集する系統がない。TIA_ZABBIX_URL か TIA_WAZUH_URL を設定する")
    db_path = Path(args.db)
    if not db_path.parent.is_dir():
        raise ValueError(f"保存先のフォルダがない: {db_path.parent}")
    bundle_dir = Path(args.knowledge) if args.knowledge else Path(cfg.knowledge_bundle_dir)
    analysis = cfg.worker_enabled and not args.no_analysis
    deps = build_deps(cfg, bundle_dir) if analysis else None
    if args.config_dir:
        config_dir = Path(args.config_dir)
    else:
        config_dir = Path(args.config).parent if args.config else None
    return Plan(cfg, rules, pollers, db_path, bundle_dir, config_dir, deps, args.host or cfg.web_host,
                args.port or cfg.web_port)


def run_service(plan: Plan) -> int:
    """司令塔を動かし、終了コードを返す。"""
    import uvicorn

    from tia.web.app import create_app

    lock = InstanceLock(plan.db_path)
    try:
        lock.acquire()
    except LockError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_LOCKED
    stop = threading.Event()
    previous: dict[int, object] = {}
    try:
        with closing(db.connect(plan.db_path)):
            pass  # 移行を主スレッドで済ませてから、ほかのスレッドに接続させる
        # 解析を切っているときは LLM を確かめない。札は「確認していない」で、/healthz の失敗にしない
        probe = plan.deps.client.health if plan.deps else None
        app = create_app(plan.db_path, plan.cfg, bundle_dir=plan.bundle_dir, llm_probe=probe,
                         probe_runner=plan.deps.probes if plan.deps else None,
                         monitor_interval_sec=float(plan.cfg.web_health_interval_sec))
        server = uvicorn.Server(uvicorn.Config(app, host=plan.host, port=plan.port, log_level="warning",
                                               proxy_headers=False, server_header=False, date_header=False,
                                               timeout_graceful_shutdown=5, lifespan="off"))
        sup = Supervisor(stop)
        # 先に SSE へ止める合図を出す。開いたままの流れが「: shutdown」で終わってから、サーバーを閉じる
        sup.on_stop(app.state.tia.stopping.set)
        sup.on_stop(lambda: setattr(server, "should_exit", True))
        sup.on_stop(app.state.tia.monitor.stop)
        previous = {number: signal.signal(number, lambda *_: stop.set())
                    for number in (signal.SIGTERM, signal.SIGINT)}
        sup.spawn("web", server.run)
        deadline = time.monotonic() + START_TIMEOUT_SEC
        while not server.started and sup.failed is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if not server.started:
            if sup.failed is None:
                log.error("画面が起動しない（%s:%d）", plan.host, plan.port)
                sup._fail("web")
            return sup.wait()
        sup.spawn("collector", lambda: _collector(plan.db_path, plan.pollers, plan.cfg, plan.rules, stop))
        if plan.deps is not None:
            sup.spawn("worker", lambda: _worker(plan.db_path, plan.cfg, plan.deps, stop))
            # 起動時の LLM の確認は、画面の稼働の確認のスレッドが行い、初回の結果を記録に出す。主スレッドでは呼ばない
        nightly = Nightly(plan.db_path, plan.cfg, plan.config_dir, worker.utc_now)
        reloader = (BundleReloader(plan.deps, plan.bundle_dir, plan.cfg.knowledge_reload_check_sec)
                    if plan.deps else None)
        pause = min(30, plan.cfg.knowledge_reload_check_sec)
        sup.spawn("housekeeping", lambda: _housekeeping(nightly, reloader, stop, pause), essential=False)
        log.info("司令塔を起動した: 画面 %s:%d、収集 %s、解析 %s、バックアップ %s、整理 %s（%s）", plan.host, plan.port,
                 " ".join(str(poller.source) for poller in plan.pollers), "あり" if plan.deps else "なし",
                 plan.cfg.backup_at, plan.cfg.housekeeping_retention_at, plan.cfg.web_timezone)
        code = sup.wait()
        log.info("止める合図を受けて終了した（終了コード %d）", code)
        return code
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        lock.release()
