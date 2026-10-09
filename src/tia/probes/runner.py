"""確認の実行。VM には ssh で名前 1 語を渡し、Zabbix と Wazuh には読み取りの API を呼ぶ。

並列に動かし、全体の予算で打ち切る。出力は秘密を伏せ、区切りのタグを無害にし、上限で切ってから保存する。
失敗は結果の状態として残し、例外にしない（確認が解析を止めることはない）。
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import sqlite3
import subprocess
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from tia.collectors.base import SourceError, hide_secrets, read_secret
from tia.collectors.endpoints import WazuhEndpoint, ZabbixEndpoint
from tia.collectors.http import Http, tls_context
from tia.collectors.wazuh import WazuhClient
from tia.collectors.zabbix import ZabbixClient
from tia.config import Config
from tia.knowledge.safety import neutralise
from tia.knowledge.tokens import TokenCounter
from tia.normalize import clean_text
from tia.probes import store
from tia.probes.catalog import Catalog, Probe

log = logging.getLogger("tia.probes")

MAX_PARALLEL = 8
ERROR_LIMIT = 300
TRUNCATED = "\n…（切り詰めた）"
# VM 側の実行器の終了コード
EXIT_REFUSED, EXIT_TIMEOUT, EXIT_FAILED, EXIT_SSH = 2, 3, 4, 255
STATUS_LABELS = {"ok": "成功", "timeout": "時間切れ", "unreachable": "届かない", "refused": "断られた",
                 "failed": "失敗", "skipped": "省いた"}
HISTORY_POINTS = 30
HISTORY_WINDOW_SEC = 3600
WAZUH_WINDOW_SEC = 7200
WAZUH_MIN_LEVEL = 5
WAZUH_PAGE = 200
WAZUH_KEEP = 20
PROBLEMS_KEEP = 20

# 一般の秘密の形。設定の秘密は hide_secrets で値を知って消す。知らない秘密はこの形で消す
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+\S+")
# 「password is required」のような文は伏せない。値を伴う形（: か =）だけ
_ASSIGNED = re.compile(r"(?i)\b(token|passw(?:or)?d|secret|api[_-]?key)(\s*[:=]\s*)(\S+)")
_LONG_HEX = re.compile(r"\b[0-9a-f]{64}\b")
_SK_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")
_SSH_KEY_BODY = re.compile(r"\b(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+) (AAAA[A-Za-z0-9+/=]{12,})")


@dataclass(frozen=True)
class ProbeResult:
    name: str
    target: str
    status: str
    output: str
    error: str | None
    duration_ms: int
    started_at: datetime
    command: str | None = None
    trigger: str = "initial"  # initial / operator / replay。運用者が添えた結果は予算で最後に落とす

    @property
    def label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)


def hide(text: str, secrets: tuple[str, ...] = ()) -> str:
    """確認の出力から秘密を消す。設定の秘密はその値で、知らない秘密は形で。制御文字も除く。"""
    text = hide_secrets(text, secrets)
    text = _PRIVATE_KEY.sub("[伏せた: 秘密鍵]", text)
    text = _SSH_KEY_BODY.sub(r"\1 [伏せた: 鍵]", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} ***", text)
    text = _ASSIGNED.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    text = _SK_KEY.sub("***", text)
    text = _LONG_HEX.sub("***", text)
    return clean_text(text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "  "), len(text) + 1)


def tidy(text: str, cap_bytes: int, secrets: tuple[str, ...] = ()) -> str:
    """保存と文脈に入れる形にする: 伏せ字、区切りのタグの無害化、上限で切る。"""
    cleaned, _ = neutralise(hide(text, secrets))
    raw = cleaned.encode("utf-8")
    if len(raw) > cap_bytes:
        cleaned = raw[:cap_bytes].decode("utf-8", errors="ignore").rstrip() + TRUNCATED
    return cleaned.strip("\n")


class Skip(Exception):
    """この確認は行えない（アラートに項目がない、Zabbix にホストがない）。結果は skipped で理由を残す。"""


class Runner:
    """1 回の解析（または画面からの 1 回）の確認をまとめて動かす。"""

    def __init__(self, cfg: Config, catalog: Catalog, *, ssh_bin: str = "ssh", key_file: Path, known_hosts: Path,
                 zabbix: ZabbixEndpoint | None = None, wazuh: WazuhEndpoint | None = None,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC), max_parallel: int = MAX_PARALLEL,
                 tz: str = "Asia/Tokyo") -> None:
        self.cfg = cfg
        self.catalog = catalog
        self.ssh_bin = ssh_bin
        self.key_file = Path(key_file)
        self.known_hosts = Path(known_hosts)
        self.zabbix = zabbix
        self.wazuh = wazuh
        self.now = now
        self.max_parallel = max(1, max_parallel)
        self.tz = ZoneInfo(tz)

    # --- 選択 ---

    def plan(self, incident: sqlite3.Row) -> list[Probe]:
        """段階 1 で動かす確認。群には行わない（構成要素ごとに済んでいる）。"""
        if incident["source"] == "group":
            return []
        return self.catalog.for_incident(incident["host"], incident["type"], incident["source"])

    def command_for(self, probe: Probe, host: str) -> str | None:
        return self.catalog.command_for(probe, host)

    # --- 実行 ---

    def run(self, probes: list[Probe], incident: sqlite3.Row, *, stop: threading.Event | None = None
            ) -> list[ProbeResult]:
        """並列に動かし、全体の予算で打ち切る。結果はカタログの順。"""
        if not probes:
            return []
        budget = self.cfg.probes_total_budget_sec
        interrupt = threading.Event()
        secrets, zabbix, wazuh, http = self._clients(interrupt)
        processes: dict[str, subprocess.Popen] = {}
        lock = threading.Lock()
        results: dict[str, ProbeResult] = {}
        started = time.monotonic()

        def one(probe: Probe) -> None:
            if stop is not None and stop.is_set():
                results[probe.name] = self._result(probe, incident, "skipped", "", "止める合図があった")
                return
            try:
                if probe.where == "host":
                    results[probe.name] = self._host(probe, incident, secrets, processes, lock)
                elif probe.where == "zabbix":
                    results[probe.name] = self._zabbix(probe, incident, zabbix, secrets)
                else:
                    results[probe.name] = self._wazuh(probe, incident, wazuh, secrets)
            except Exception as exc:  # noqa: BLE001 - 確認の失敗は結果に残し、解析を止めない
                log.warning("確認 %s が失敗した: %s", probe.name, hide(f"{type(exc).__name__}: {exc}", secrets)[:ERROR_LIMIT])
                results[probe.name] = self._result(probe, incident, "failed", "",
                                                   hide(f"{type(exc).__name__}: {exc}", secrets)[:ERROR_LIMIT])

        try:
            with ThreadPoolExecutor(max_workers=min(self.max_parallel, len(probes)), thread_name_prefix="tia-probe") as pool:
                futures = {pool.submit(one, probe): probe for probe in probes}
                done, pending = wait(futures, timeout=budget)
                if pending:
                    interrupt.set()
                    with lock:
                        for proc in processes.values():
                            _kill(proc)
                    wait(pending, timeout=5)
        finally:
            if http is not None:
                http.close()
        elapsed_ms = int((time.monotonic() - started) * 1000)
        late = {futures[f].name for f in pending}
        ordered = []
        for probe in probes:
            result = results.get(probe.name)
            if result is None or probe.name in late:
                result = self._result(probe, incident, "timeout", "", f"全体の予算 {budget} 秒を超えた", elapsed_ms)
            ordered.append(result)
        return ordered

    def _clients(self, interrupt: threading.Event):
        """API の接続。秘密は毎回ファイルから読む（入れ替えが再起動なしで効く）。"""
        secrets: tuple[str, ...] = ()
        zabbix = wazuh = http = None
        if self.zabbix is not None or self.wazuh is not None:
            verify = tls_context(self.wazuh.ca_file) if self.wazuh is not None else True
            http = Http(self.cfg, verify, timeout_sec=self.cfg.probes_timeout_sec, interrupt=interrupt,
                        user_agent="tia-probe")
        if self.zabbix is not None:
            try:
                token = read_secret(self.zabbix.token_file, "Zabbix の API トークン", header_safe=True)
                zabbix = ZabbixClient(http, self.zabbix.url, token)
                secrets += (token,)
            except SourceError as exc:
                log.warning("Zabbix の確認を省く: %s", exc)
        if self.wazuh is not None:
            try:
                password = read_secret(self.wazuh.password_file, "インデクサーの閲覧パスワード")
                wazuh = WazuhClient(http, self.wazuh.url, self.wazuh.user, password)
                secrets += (password,)
            except SourceError as exc:
                log.warning("Wazuh の確認を省く: %s", exc)
        return secrets, zabbix, wazuh, http

    def _result(self, probe: Probe, incident: sqlite3.Row, status: str, output: str, error: str | None,
                duration_ms: int = 0, started_at: datetime | None = None, command: str | None = None) -> ProbeResult:
        target = incident["host"] if probe.where == "host" else probe.where
        if command is None and probe.where == "host":
            command = self.command_for(probe, incident["host"])
        return ProbeResult(probe.name, target, status, output, error, duration_ms, started_at or self.now(), command)

    def _timeout(self, probe: Probe) -> int:
        return min(probe.timeout_sec, self.cfg.probes_timeout_sec)

    def _cap(self, probe: Probe) -> int:
        return min(probe.cap_bytes, self.cfg.probes_output_cap_bytes)

    # --- VM ---

    def _host(self, probe: Probe, incident: sqlite3.Row, secrets: tuple[str, ...],
              processes: dict[str, subprocess.Popen], lock: threading.Lock) -> ProbeResult:
        host = incident["host"]
        entry = self.catalog.hosts[host]
        timeout = self._timeout(probe)
        argv = [self.ssh_bin, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                "-o", f"ConnectTimeout={min(timeout, 10)}", "-o", "ServerAliveInterval=5", "-o", "LogLevel=ERROR",
                "-o", "ClearAllForwardings=yes", "-i", str(self.key_file), f"{self.cfg.probes_ssh_user}@{entry.ip}",
                probe.name]
        started_at = self.now()
        clock = time.monotonic()
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                                             "LANG": "C.UTF-8", "HOME": os.environ.get("HOME", "/tmp")})
        with lock:
            processes[probe.name] = proc
        try:
            out, err = proc.communicate(timeout=timeout + 2)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            _kill(proc)
            out, err = proc.communicate()
            code = None
        duration_ms = int((time.monotonic() - clock) * 1000)
        output = tidy(out.decode("utf-8", errors="replace"), self._cap(probe), secrets)
        error_text = hide(err.decode("utf-8", errors="replace"), secrets).strip()[:ERROR_LIMIT] or None
        if code is None:
            status, error_text = "timeout", f"{timeout} 秒で打ち切った"
        elif code == 0:
            status = "ok"
        elif code == EXIT_REFUSED:
            status = "refused"
        elif code == EXIT_TIMEOUT:
            status = "timeout"
        elif code == EXIT_FAILED:
            status = "failed"
        elif code == EXIT_SSH:
            lowered = (error_text or "").lower()
            status = "refused" if ("permission denied" in lowered or "host key" in lowered
                                   or "publickey" in lowered) else "unreachable"
            error_text = error_text or "ssh が接続できなかった"
        else:
            status, error_text = "failed", error_text or f"終了コード {code}"
        return self._result(probe, incident, status, output, error_text, duration_ms, started_at)

    # --- Zabbix ---

    def _zabbix(self, probe: Probe, incident: sqlite3.Row, client: ZabbixClient | None,
                secrets: tuple[str, ...]) -> ProbeResult:
        if client is None:
            return self._result(probe, incident, "skipped", "", "Zabbix の接続先がない")
        raw = json.loads(incident["raw_json"] or "{}") if incident["source"] == "zabbix" else {}
        started_at = self.now()
        clock = time.monotonic()
        try:
            if probe.name == "zabbix_trigger":
                text = self._zabbix_trigger(client, raw)
            elif probe.name == "zabbix_history_60m":
                text = self._zabbix_history(client, raw)
            elif probe.name == "zabbix_host_problems":
                text = self._zabbix_problems(client, incident["host"])
            else:
                return self._result(probe, incident, "skipped", "", "実装のない Zabbix の確認")
        except SourceError as exc:
            status = "refused" if exc.kind == "auth" else ("timeout" if exc.kind == "timeout" else "failed")
            return self._result(probe, incident, status, "", str(exc)[:ERROR_LIMIT],
                                int((time.monotonic() - clock) * 1000), started_at)
        except Skip as exc:
            return self._result(probe, incident, "skipped", "", str(exc), int((time.monotonic() - clock) * 1000),
                                started_at)
        return self._result(probe, incident, "ok", tidy(text, self._cap(probe), secrets), None,
                            int((time.monotonic() - clock) * 1000), started_at)

    def _zabbix_trigger(self, client: ZabbixClient, raw: dict) -> str:
        trigger_id = _digits(raw.get("objectid"))
        if trigger_id is None:
            raise Skip("アラートにトリガーの番号がない")
        rows = client.call("trigger.get", {
            "output": ["triggerid", "description", "expression", "priority", "value", "lastchange", "comments"],
            "triggerids": [trigger_id], "selectHosts": ["host"],
            "selectItems": ["itemid", "key_", "name", "lastvalue", "units", "lastclock"]})
        if not rows:
            return "トリガーが見つからない（消えた、または閲覧できない）"
        lines = []
        for row in rows:
            lines.append(f"トリガー {row.get('triggerid')}: {row.get('description', '')}")
            lines.append(f"式: {row.get('expression', '')}")
            lines.append(f"状態: {'問題' if str(row.get('value')) == '1' else '正常'}、"
                         f"最終変化: {self._when(row.get('lastchange'))}、重大度: {row.get('priority')}")
            if row.get("comments"):
                lines.append(f"説明: {row['comments']}")
            for item in row.get("items") or []:
                lines.append(f"項目 {item.get('itemid')} {item.get('key_')}: 最新値 {item.get('lastvalue')}"
                             f"{item.get('units', '')}（{self._when(item.get('lastclock'))}）")
        return "\n".join(lines)

    def _zabbix_history(self, client: ZabbixClient, raw: dict) -> str:
        item_ids = [i for i in (_digits(it.get("itemid")) for it in raw.get("items") or [] if isinstance(it, dict)) if i]
        if not item_ids:
            raise Skip("アラートに項目の番号がない")
        items = client.call("item.get", {"output": ["itemid", "name", "key_", "value_type", "units"],
                                         "itemids": item_ids[:5]})
        till = int(self.now().timestamp())
        lines = []
        for item in items:
            item_id = _digits(item.get("itemid"))
            value_type = _digits(item.get("value_type")) or "0"
            if item_id is None or value_type not in ("0", "3"):
                lines.append(f"項目 {item.get('key_')}: 数値でないので履歴を省く")
                continue
            points = client.call("history.get", {
                "output": "extend", "history": int(value_type), "itemids": [item_id],
                "time_from": till - HISTORY_WINDOW_SEC, "time_till": till, "sortfield": "clock", "sortorder": "ASC",
                "limit": 3600})
            thinned = _thin(points, HISTORY_POINTS)
            lines.append(f"項目 {item.get('key_')}（{item.get('name', '')}、単位 {item.get('units', '')}）"
                         f"の 60 分の履歴 {len(points)} 点（{len(thinned)} 点に間引いた）:")
            lines.extend(f"  {self._when(p.get('clock'))} {p.get('value')}" for p in thinned)
        return "\n".join(lines)

    def _zabbix_problems(self, client: ZabbixClient, host: str) -> str:
        hosts = client.call("host.get", {"output": ["hostid", "host"], "filter": {"host": [host]}})
        host_ids = [h for h in (_digits(x.get("hostid")) for x in hosts if isinstance(x, dict)) if h]
        if not host_ids:
            raise Skip(f"Zabbix にホスト {host} がない")
        rows = client.call("problem.get", {
            "output": ["eventid", "objectid", "clock", "name", "severity", "acknowledged", "r_eventid"],
            "hostids": host_ids, "recent": False, "sortfield": ["eventid"], "sortorder": "DESC",
            "limit": PROBLEMS_KEEP})
        if not rows:
            return f"{host} の未解決の問題: なし"
        lines = [f"{host} の未解決の問題 {len(rows)} 件（新しい順、最大 {PROBLEMS_KEEP}）:"]
        lines.extend(f"  {self._when(r.get('clock'))} 重大度 {r.get('severity')} {r.get('name', '')}"
                     f"{'（確認済み）' if str(r.get('acknowledged')) == '1' else ''}" for r in rows)
        return "\n".join(lines)

    # --- Wazuh ---

    def _wazuh(self, probe: Probe, incident: sqlite3.Row, client: WazuhClient | None,
               secrets: tuple[str, ...]) -> ProbeResult:
        if client is None:
            return self._result(probe, incident, "skipped", "", "Wazuh の接続先がない")
        started_at = self.now()
        clock = time.monotonic()
        till = int(self.now().timestamp() * 1000)
        body = {
            "size": WAZUH_PAGE, "track_total_hits": False,
            "sort": [{"timestamp": {"order": "asc"}}, {self.cfg.wazuh_tiebreak_field: {"order": "asc"}}],
            "_source": ["timestamp", "rule.id", "rule.level", "rule.description", "agent.name", "data.srcip",
                        "data.dstuser", "full_log"],
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": till - WAZUH_WINDOW_SEC * 1000, "lte": till, "format": "epoch_millis"}}},
                {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}},
                {"terms": {"agent.name": [incident["host"]]}}]}}}
        try:
            hits = client.search(body)
        except SourceError as exc:
            status = "refused" if exc.kind == "auth" else ("timeout" if exc.kind == "timeout" else "failed")
            return self._result(probe, incident, status, "", str(exc)[:ERROR_LIMIT],
                                int((time.monotonic() - clock) * 1000), started_at)
        kept = hits[-WAZUH_KEEP:]
        if not kept:
            text = f"{incident['host']} の Wazuh のアラート（2 時間、level {WAZUH_MIN_LEVEL} 以上）: なし"
        else:
            lines = [f"{incident['host']} の Wazuh のアラート（2 時間、level {WAZUH_MIN_LEVEL} 以上）: "
                     f"{len(hits)} 件のうち新しい {len(kept)} 件:"]
            for hit in kept:
                src = hit.get("_source", {}) if isinstance(hit, dict) else {}
                rule = src.get("rule", {}) if isinstance(src.get("rule"), dict) else {}
                data = src.get("data", {}) if isinstance(src.get("data"), dict) else {}
                lines.append(f"  {src.get('timestamp', '')} rule {rule.get('id', '')} level {rule.get('level', '')} "
                             f"{rule.get('description', '')}"
                             + (f" src {data.get('srcip')}" if data.get("srcip") else "")
                             + (f" user {data.get('dstuser')}" if data.get("dstuser") else ""))
                if src.get("full_log"):
                    lines.append(f"    {str(src['full_log'])[:200]}")
            text = "\n".join(lines)
        return self._result(probe, incident, "ok", tidy(text, self._cap(probe), secrets), None,
                            int((time.monotonic() - clock) * 1000), started_at)

    def _when(self, clock: object) -> str:
        digits = _digits(clock)
        if digits is None:
            return "?"
        return datetime.fromtimestamp(int(digits), UTC).astimezone(self.tz).strftime("%m-%d %H:%M:%S")


def _digits(value: object) -> str | None:
    text = str(value) if value is not None else ""
    return text if text.isdigit() else None


def _thin(points: list, keep: int) -> list:
    if len(points) <= keep:
        return list(points)
    step = len(points) / keep
    return [points[min(len(points) - 1, int(i * step))] for i in range(keep)]


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


# --- 保存と文脈 ---

def store_results(conn: sqlite3.Connection, incident_id: int, analysis_id: int | None, trigger: str,
                  results: list[ProbeResult]) -> list[int]:
    return [store.insert(conn, incident_id, analysis_id, r.name, r.target, trigger, r.started_at, r.duration_ms,
                         r.status, r.output, r.error, command=r.command) for r in results]


def from_rows(rows: list[sqlite3.Row]) -> list[ProbeResult]:
    """保存した行を結果に戻す。再解析に添えるときに使う。"""
    return [ProbeResult(r["name"], r["target"], r["status"], r["output"], r["error"], r["duration_ms"],
                        datetime.fromisoformat(r["started_at"]), r["command"], r["trigger"]) for r in rows]


# 1 件の確認が文脈に占める上限。journal の出力 4 KB は約 1,600 トークンで、1 件で予算の大半を使ってしまうため
PROBE_TOKEN_CAP = 600


def _block(r: ProbeResult, zone: ZoneInfo, counter: TokenCounter, cap: int) -> str:
    head = (f"## {r.name} @ {r.target} — {r.label}（{r.duration_ms} ms、"
            f"{r.started_at.astimezone(zone).strftime('%H:%M:%S')}）")
    if r.command:
        head += f"\n$ {r.command}"
    body = r.output if r.output else (f"（{r.error}）" if r.error else "（出力なし）")
    if r.output and r.error and r.status != "ok":
        body += f"\n（{r.error}）"
    text = f"{head}\n{body}"
    if counter(text) > cap:
        lines = body.splitlines()
        while len(lines) > 1 and counter(f"{head}\n" + "\n".join(lines) + TRUNCATED) > cap:
            lines = lines[:-max(1, len(lines) // 8)]
        body = "\n".join(lines)
        while body and counter(f"{head}\n{body}{TRUNCATED}") > cap:  # 1 行が長いときは文字で切る
            body = body[: max(0, len(body) * 3 // 4)]
        text = f"{head}\n{body}{TRUNCATED}"
    return text


def render(results: list[ProbeResult], counter: TokenCounter, budget: int, *, tz: str = "Asia/Tokyo",
           always: frozenset[str] | set[str] = frozenset(), cap: int = PROBE_TOKEN_CAP) -> tuple[str, int]:
    """<probe_data> の中身と、予算のために省いた数。1 件を cap に切り詰めてから、カタログの順に並べる。
    予算を超えたら、always の確認を大きい順に落とし、次に種類に合う確認を大きい順に落とす。
    運用者が添えた結果（trigger=operator）は最後まで残す。"""
    if not results:
        return "", 0
    zone = ZoneInfo(tz)
    blocks = {i: _block(r, zone, counter, cap) for i, r in enumerate(results)}

    def rank(index: int) -> tuple[int, int]:
        r = results[index]
        tier = 2 if r.trigger == "operator" else (0 if r.name in always else 1)
        return (tier, -counter(blocks[index]))

    order = sorted(blocks, key=rank)  # 落とす順
    dropped = 0
    kept = set(blocks)
    while kept:
        note = f"（予算のため確認 {dropped} 件を省いた）\n" if dropped else ""
        text = note + "\n\n".join(blocks[i] for i in sorted(kept))
        if counter(text) <= budget:
            return text, dropped
        kept.discard(order[dropped])
        dropped += 1
    return f"（確認の結果 {dropped} 件は予算に入らず省いた）", dropped


def replace_output(result: ProbeResult, output: str) -> ProbeResult:
    return replace(result, output=output)
