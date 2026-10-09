"""設定の読み込み。知らないキーと、型や範囲の違う値は誤記とみなして失敗させる。

すべての設定は環境変数と `.env` で上書きできる。項目 `節_キー` の変数名は `TIA_節_キー` の大文字。
優先は 環境変数 > .env > analyzer.yaml > 既定。
"""
from __future__ import annotations

import logging
import os
from collections.abc import Mapping, MutableMapping
from dataclasses import Field, dataclass, fields
from pathlib import Path
from typing import Literal, NamedTuple

import re

import yaml

from tia.dotenv import read_dotenv

log = logging.getLogger("tia.config")

DEFAULT_NAMED_RULES = ("100101", "5710", "5712", "5716", "5720", "550", "553", "554", "5402", "5901", "5902")

# 整数の設定が取れる範囲。両端を含む。
INT_RANGES: dict[str, tuple[int, int]] = {
    "knowledge_card_budget_tokens": (1, 131072),
    "knowledge_section_budget_tokens": (0, 131072),
    "knowledge_max_sections": (0, 20),
    "knowledge_stale_after_days": (1, 3650),
    "zabbix_min_severity": (0, 5),
    "zabbix_hold_sec": (0, 3600),
    "zabbix_fetch_min_severity": (0, 5),
    "zabbix_poll_interval_sec": (5, 3600),
    "zabbix_page_size": (1, 1000),
    "zabbix_max_pages": (1, 100),
    "wazuh_min_level": (0, 16),
    "wazuh_hold_sec": (0, 3600),
    "wazuh_poll_interval_sec": (5, 3600),
    "wazuh_page_size": (1, 1000),
    "wazuh_max_pages": (1, 100),
    "intake_recurrence_window_sec": (1, 86400),
    "intake_followup_after_sec": (1, 604800),
    "intake_skip_resolved_after_sec": (1, 2592000),
    "grouping_storm_count": (2, 1000),
    "grouping_storm_window_sec": (1, 86400),
    "collector_tick_sec": (1, 60),
    "collector_first_lookback_sec": (0, 604800),
    "collector_overlap_sec": (10, 3600),
    "collector_connect_timeout_sec": (1, 60),
    "collector_timeout_sec": (1, 120),
    "collector_backoff_max_sec": (5, 86400),
    "collector_auth_backoff_sec": (5, 86400),
    "collector_max_response_mb": (1, 256),
    "llm_max_tokens": (1, 32768),
    # Open WebUI は上流への待ちを 300 秒で打ち切る。解析の制限時間はそれより短くする。
    "llm_timeout_sec": (1, 299),
    "llm_connect_timeout_sec": (1, 60),
    "llm_max_response_mb": (1, 64),
    "llm_context_tokens": (4096, 1048576),
    "context_input_budget_tokens": (1000, 1048576),
    "context_rules_budget_tokens": (100, 10000),
    "context_cases_budget_tokens": (0, 100000),
    "context_cases_max": (0, 10),
    "context_stats_budget_tokens": (0, 10000),
    "context_dynamic_budget_tokens": (200, 100000),
    "context_history_days": (1, 365),
    "context_history_max": (0, 100),
    "context_stats_window_days": (1, 3650),
    "context_token_margin_percent": (0, 50),
    "web_port": (1, 65535),
    "web_sse_poll_sec": (1, 30),
    "web_sse_max_sec": (2, 86400),
    "web_health_interval_sec": (5, 3600),
    "web_stall_warn_sec": (60, 86400),
    "web_max_rows": (10, 5000),
    "web_min_free_mb": (1, 1000000),
    "worker_idle_sec": (1, 60),
    "worker_backoff_min_sec": (1, 3600),
    "worker_backoff_max_sec": (1, 86400),
    "worker_auth_backoff_sec": (1, 86400),
    "worker_progress_every_chunks": (1, 1000),
    "knowledge_reload_check_sec": (5, 3600),
    "retention_incident_days": (1, 3650),
    "retention_payload_days": (1, 3650),
    "retention_skipped_days": (1, 3650),
    "backup_keep": (1, 365),
    # 確認（読み取りだけの照会）
    "probes_total_budget_sec": (5, 120),
    "probes_timeout_sec": (1, 30),
    "probes_output_cap_bytes": (512, 65536),
}
# 並べ替えの項目名に使える文字。照会の本文に入るので、形を限る。
FIELD_NAME = re.compile(r"[A-Za-z_@][A-Za-z0-9_.@]{0,63}")
RETRY_DELAY_RANGE = (1, 86400)


def _label(name: str) -> str:
    """項目名 `節_キー` を、設定ファイルでの書き方 `節.キー` に戻す。"""
    return name.replace("_", ".", 1)


KNOWLEDGE_MODES = ("selection", "full")
KNOWLEDGE_TEXTS = ("knowledge_source_dir", "knowledge_bundle_dir", "knowledge_recipe")


def _check_knowledge(cfg: "Config") -> None:
    """ナレッジの設定のうち、文字列のものを確かめる。整数は INT_RANGES で確かめる。"""
    for name in KNOWLEDGE_TEXTS:
        value = getattr(cfg, name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"設定 {_label(name)} は空でない文字列で書く: {value!r}")
    if cfg.knowledge_mode not in KNOWLEDGE_MODES:
        raise ValueError(f"設定 knowledge.mode は selection か full で書く: {cfg.knowledge_mode!r}")


LLM_TEMPERATURE_RANGE = (0.0, 2.0)
# モデルの名前に使える文字。要求の本文に入るので、形を限る。
MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


def _check_llm(cfg: "Config") -> None:
    """LLM と文脈の設定のうち、整数の範囲では確かめられないものを確かめる。"""
    if not isinstance(cfg.llm_model, str) or not MODEL_NAME.fullmatch(cfg.llm_model):
        raise ValueError(f"設定 llm.model はモデルの名前で書く: {cfg.llm_model!r}")
    low, high = LLM_TEMPERATURE_RANGE
    for name in ("llm_temperature", "llm_retry_temperature"):
        value = getattr(cfg, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
            raise ValueError(f"設定 {_label(name)} は {low} から {high} の数で書く: {value!r}")
    if not isinstance(cfg.llm_thinking, bool):
        raise ValueError(f"設定 llm.thinking は true か false で書く: {cfg.llm_thinking!r}")
    if not isinstance(cfg.llm_allow_other_route, bool):
        raise ValueError(f"設定 llm.allow_other_route は true か false で書く: {cfg.llm_allow_other_route!r}")


# 待受のアドレスに使える文字。IPv4、IPv6、ホスト名。
HOST_NAME = re.compile(r"[A-Za-z0-9.:\[\]-]{1,253}")


def _check_web(cfg: "Config") -> None:
    """画面の設定のうち、整数の範囲では確かめられないものを確かめる。"""
    if not isinstance(cfg.web_host, str) or not HOST_NAME.fullmatch(cfg.web_host):
        raise ValueError(f"設定 web.host は待受のアドレスで書く: {cfg.web_host!r}")
    if not isinstance(cfg.web_timezone, str) or not cfg.web_timezone.strip():
        raise ValueError(f"設定 web.timezone は時間帯の名前で書く: {cfg.web_timezone!r}")
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(cfg.web_timezone)
    except Exception as exc:  # noqa: BLE001 - 時間帯の名前の誤りを、設定の誤りとして示す
        raise ValueError(f"設定 web.timezone は時間帯の名前で書く: {cfg.web_timezone!r}") from exc
    if not isinstance(cfg.web_cookie_secure, bool):
        raise ValueError(f"設定 web.cookie_secure は true か false で書く: {cfg.web_cookie_secure!r}")
    name = cfg.web_system_name
    if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(c in name for c in "\r\n"):
        raise ValueError(f"設定 web.system_name は 80 文字以内の 1 行で書く: {name!r}")
def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# SSH の利用者名。コマンド行に入るので、形を限る
USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
PROBE_PATHS = ("probes_catalog", "probes_known_hosts", "probes_key_file")


def _check_probes(cfg: "Config") -> None:
    """確認の設定のうち、整数の範囲では確かめられないものを確かめる。"""
    if not isinstance(cfg.probes_enabled, bool):
        raise ValueError(f"設定 probes.enabled は true か false で書く: {cfg.probes_enabled!r}")
    if not isinstance(cfg.probes_ssh_user, str) or not USER_NAME.fullmatch(cfg.probes_ssh_user):
        raise ValueError(f"設定 probes.ssh_user は利用者名で書く: {cfg.probes_ssh_user!r}")
    for name in PROBE_PATHS:
        value = getattr(cfg, name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"設定 {_label(name)} は空でない文字列で書く: {value!r}")
    if cfg.probes_timeout_sec > cfg.probes_total_budget_sec:
        raise ValueError("設定 probes.timeout_sec は probes.total_budget_sec 以下で書く: "
                         f"{cfg.probes_timeout_sec} > {cfg.probes_total_budget_sec}")


# 夜間の処理の時刻。HH:MM の 24 時間表記。
CLOCK_TIME = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


def _check_ops(cfg: "Config") -> None:
    """常駐、保持期間、バックアップの設定のうち、整数の範囲では確かめられないものを確かめる。"""
    if not isinstance(cfg.worker_enabled, bool):
        raise ValueError(f"設定 worker.enabled は true か false で書く: {cfg.worker_enabled!r}")
    if not isinstance(cfg.backup_dir, str) or not cfg.backup_dir.strip():
        raise ValueError(f"設定 backup.dir は空でない文字列で書く: {cfg.backup_dir!r}")
    for name in ("backup_at", "housekeeping_retention_at"):
        value = getattr(cfg, name)
        if _is_int(value):
            # YAML は 04:30 を 60 進の数に読む。引用符で囲めば文字列になる
            raise ValueError(f"設定 {_label(name)} は HH:MM を引用符で囲んで書く: {value!r}")
        if not isinstance(value, str) or not CLOCK_TIME.fullmatch(value):
            raise ValueError(f"設定 {_label(name)} は HH:MM で書く: {value!r}")


@dataclass(frozen=True)
class Config:
    knowledge_source_dir: str = "examples/knowledge-source"
    knowledge_bundle_dir: str = "config/knowledge"
    knowledge_recipe: str = "config/knowledge.yaml"
    knowledge_mode: str = "selection"
    knowledge_card_budget_tokens: int = 6000
    knowledge_section_budget_tokens: int = 3000
    knowledge_max_sections: int = 3
    knowledge_stale_after_days: int = 30
    zabbix_min_severity: int = 2
    zabbix_hold_sec: int = 60
    # 書かなければ、1（Information）と zabbix.min_severity の小さい方。
    zabbix_fetch_min_severity: int | None = None
    zabbix_poll_interval_sec: int = 30
    zabbix_page_size: int = 200
    zabbix_max_pages: int = 10
    wazuh_min_level: int = 10
    wazuh_named_rules: frozenset[str] = frozenset(DEFAULT_NAMED_RULES)
    wazuh_hold_sec: int = 120
    wazuh_poll_interval_sec: int = 60
    wazuh_page_size: int = 200
    wazuh_max_pages: int = 10
    wazuh_tiebreak_field: str = "id"
    intake_recurrence_window_sec: int = 1800
    intake_followup_after_sec: int = 7200
    intake_skip_resolved_after_sec: int = 21600
    grouping_storm_count: int = 5
    grouping_storm_window_sec: int = 300
    grouping_root_host: str = "example-router01"
    queue_retry_delays_sec: tuple[int, ...] = (60, 300, 900)
    collector_tick_sec: int = 5
    collector_first_lookback_sec: int = 3600
    collector_overlap_sec: int = 120
    collector_connect_timeout_sec: int = 5
    collector_timeout_sec: int = 10
    collector_backoff_max_sec: int = 600
    collector_auth_backoff_sec: int = 900
    collector_max_response_mb: int = 16
    llm_model: str = "example/model-27b"
    llm_temperature: float = 0.2
    # 検証に失敗して作り直すときの temperature。下げて 1 回だけ作り直す。
    llm_retry_temperature: float = 0.0
    llm_max_tokens: int = 1200
    llm_timeout_sec: int = 240
    llm_connect_timeout_sec: int = 5
    llm_max_response_mb: int = 4
    llm_thinking: bool = False
    # 決めた経路は Open WebUI の中継経路（URL の末尾が /openai）。別の経路を使うときだけ真にする
    llm_allow_other_route: bool = False
    llm_context_tokens: int = 131072
    context_input_budget_tokens: int = 15600
    context_rules_budget_tokens: int = 500
    context_cases_budget_tokens: int = 900
    context_cases_max: int = 3
    context_stats_budget_tokens: int = 200
    context_dynamic_budget_tokens: int = 5000
    context_history_days: int = 7
    context_history_max: int = 10
    context_stats_window_days: int = 30
    # 見積もりの誤差の分だけ、上限より手前で止める。見積もりは節によって最大 2 割ほどずれる。
    context_token_margin_percent: int = 10
    web_host: str = "0.0.0.0"
    web_port: int = 8000
    # 画面の左上と <title> に出す名前
    web_system_name: str = "Incident Analyst"
    web_timezone: str = "Asia/Tokyo"
    web_sse_poll_sec: int = 1
    # 1 本の SSE をこの秒数で閉じ、ブラウザにつなぎ直させる。接続の滞留を防ぐ
    web_sse_max_sec: int = 600
    web_health_interval_sec: int = 30
    # 待ちがこの秒数を超えたら、画面の最上段に警告を出す。既定は 10 分
    web_stall_warn_sec: int = 600
    web_max_rows: int = 500
    web_min_free_mb: int = 200
    # Caddy が TLS を終端するので、Cookie は https でだけ送る
    web_cookie_secure: bool = True
    worker_idle_sec: int = 2
    worker_progress_every_chunks: int = 25
    # LLM に届かない、断られる、相手の誤りのときの待ち。倍々で延ばし、上限で止める。認証の誤りは長く待つ。
    worker_backoff_min_sec: int = 5
    worker_backoff_max_sec: int = 600
    worker_auth_backoff_sec: int = 900
    # 解析のワーカーを動かすか。段階 2（収集だけ）では false
    worker_enabled: bool = True
    # 知識の束の入れ替えを確かめる間隔。current の指す先が変われば読み直す
    knowledge_reload_check_sec: int = 60
    # 保持期間
    retention_incident_days: int = 180
    retention_payload_days: int = 90
    retention_skipped_days: int = 14
    # 夜間のバックアップ。世代の数と、web.timezone での時刻
    backup_dir: str = "backups"
    backup_keep: int = 7
    backup_at: str = "04:30"
    housekeeping_retention_at: str = "04:40"
    # 確認（読み取りだけの照会）。鍵とカタログがなければ起動時に無効にして警告する
    probes_enabled: bool = True
    probes_total_budget_sec: int = 30
    probes_timeout_sec: int = 10
    probes_output_cap_bytes: int = 4096
    probes_ssh_user: str = "analyst-probe"
    probes_catalog: str = "config/probes.yaml"
    probes_known_hosts: str = "config/probes_known_hosts"
    probes_key_file: str = "/run/secrets/probe_ssh_key"

    def __post_init__(self) -> None:
        _check_knowledge(self)
        _check_web(self)
        _check_llm(self)
        _check_ops(self)
        _check_probes(self)
        if self.zabbix_fetch_min_severity is None and _is_int(self.zabbix_min_severity):
            object.__setattr__(self, "zabbix_fetch_min_severity", min(1, self.zabbix_min_severity))
        for name, (low, high) in INT_RANGES.items():
            value = getattr(self, name)
            if not _is_int(value) or not low <= value <= high:
                raise ValueError(f"設定 {_label(name)} は {low} から {high} の整数で書く: {value!r}")
        rules = self.wazuh_named_rules
        if not isinstance(rules, frozenset) or not all(isinstance(r, str) and r for r in rules):
            raise ValueError(f"設定 wazuh.named_rules はルール番号の配列で書く: {rules!r}")
        host = self.grouping_root_host
        if not isinstance(host, str) or not host.strip():
            raise ValueError(f"設定 grouping.root_host は空でない文字列で書く: {host!r}")
        if self.context_input_budget_tokens + self.llm_max_tokens > self.llm_context_tokens:
            raise ValueError("設定 context.input_budget_tokens と llm.max_tokens の合計は llm.context_tokens 以下で書く: "
                             f"{self.context_input_budget_tokens} + {self.llm_max_tokens} > {self.llm_context_tokens}")
        if self.zabbix_fetch_min_severity > self.zabbix_min_severity:
            raise ValueError("設定 zabbix.fetch_min_severity は zabbix.min_severity 以下で書く: "
                             f"zabbix.fetch_min_severity = {self.zabbix_fetch_min_severity!r}、"
                             f"zabbix.min_severity = {self.zabbix_min_severity!r}")
        if self.retention_payload_days > self.retention_incident_days:
            raise ValueError("設定 retention.payload_days は retention.incident_days 以下で書く: "
                             f"{self.retention_payload_days} > {self.retention_incident_days}")
        if self.retention_skipped_days > self.retention_incident_days:
            raise ValueError("設定 retention.skipped_days は retention.incident_days 以下で書く: "
                             f"{self.retention_skipped_days} > {self.retention_incident_days}")
        field = self.wazuh_tiebreak_field
        if not isinstance(field, str) or not FIELD_NAME.fullmatch(field):
            raise ValueError(f"設定 wazuh.tiebreak_field は項目名で書く: {field!r}")
        delays = self.queue_retry_delays_sec
        low, high = RETRY_DELAY_RANGE
        if not isinstance(delays, tuple) or not all(_is_int(d) and low <= d <= high for d in delays):
            raise ValueError(f"設定 queue.retry_delays_sec は {low} から {high} の整数の配列で書く: {delays!r}")


ENV_PREFIX = "TIA_"
ENV_FILE_VAR = "TIA_ENV_FILE"
# 設定の項目ではないが TIA_ で始まる変数。接続先と秘密のファイルの場所は従来の名前のまま（collectors/endpoints.py）。
EXTERNAL_VARIABLES: tuple[tuple[str, str], ...] = (
    ("TIA_ZABBIX_URL", "Zabbix の API の URL。書かなければ Zabbix からは収集しない"),
    ("TIA_ZABBIX_TOKEN_FILE", "Zabbix の API トークンのファイル。既定 /run/secrets/zabbix_api_token"),
    ("TIA_WAZUH_URL", "Wazuh のインデクサーの URL（https）。書かなければ Wazuh からは収集しない"),
    ("TIA_WAZUH_USER", "インデクサーの利用者名。既定 analyzer_ro"),
    ("TIA_WAZUH_PASSWORD_FILE", "インデクサーのパスワードのファイル。既定 /run/secrets/wazuh_indexer_password"),
    ("TIA_WAZUH_CA_FILE", "インデクサーの証明書を確かめる CA のファイル"),
    ("TIA_LLM_URL", "LLM の URL。Open WebUI の中継経路（末尾が /openai）"),
    # TIA_LLM_MODEL は従来から llm.model の上書きで、規則どおりの名前なので設定の項目として読む
    ("TIA_LLM_API_KEY_FILE", "LLM の API 鍵のファイル。既定 /run/secrets/openwebui_api_key"),
    ("TIA_PROBE_SSH_BIN", "確認に使う ssh の実行ファイル。試験のための差し替え"),
    ("TIA_IMAGE_TAG", "Compose が起動する画像の版。この .env を Compose 自身も読む"),
    (ENV_FILE_VAR, ".env の場所。書かなければ analyzer.yaml と同じフォルダの .env"),
)
Source = Literal["default", "yaml", ".env", "env"]
TRUE_WORDS = ("true", "yes", "on", "1")
FALSE_WORDS = ("false", "no", "off", "0")
INTEGER = re.compile(r"-?\d+")


def env_name(name: str) -> str:
    """項目 `節_キー` の環境変数の名前。`TIA_節_キー` の大文字。"""
    return ENV_PREFIX + name.upper()


_SETTING_BY_VARIABLE = {env_name(f.name): f.name for f in fields(Config)}
_FIELD_BY_NAME = {f.name: f for f in fields(Config)}


def setting_name(variable: str) -> str | None:
    """環境変数の名前から項目の名前へ。設定でなければ None。"""
    return _SETTING_BY_VARIABLE.get(variable)


def _items(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _int_or_raw(raw: str) -> object:
    text = raw.strip()
    return int(text) if INTEGER.fullmatch(text) else raw


def coerce(field: Field, raw: str) -> object:
    """環境変数の文字列を項目の型に読む。読めない文字列はそのまま返し、検証に断らせる（変数名が誤りの表示に出る）。"""
    kind = str(field.type)
    if kind == "int":
        return _int_or_raw(raw)
    if kind == "int | None":
        return None if not raw.strip() else _int_or_raw(raw)
    if kind == "float":
        try:
            return float(raw.strip())
        except ValueError:
            return raw
    if kind == "bool":
        word = raw.strip().lower()
        return True if word in TRUE_WORDS else False if word in FALSE_WORDS else raw
    if kind == "tuple[int, ...]":
        return tuple(_int_or_raw(item) for item in _items(raw))
    if kind == "frozenset[str]":
        return frozenset(_items(raw))
    return raw


def format_value(value: object) -> str:
    """項目の値を、環境変数に書く形に戻す。coerce の逆。"""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, frozenset):
        return ",".join(sorted(value))
    if isinstance(value, tuple):
        return ",".join(str(item) for item in value)
    return str(value)


class Loaded(NamedTuple):
    config: Config
    sources: dict[str, Source]
    env_file: Path | None


def _yaml_values(path: Path) -> dict[str, object]:
    """YAML の `節: {キー: 値}` を `節_キー` の項目に写す。"""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("設定は対応表で書く")
    values: dict[str, object] = {}
    for section, body in data.items():
        if not isinstance(body, dict):
            raise ValueError(f"設定の節 {section!r} は対応表で書く")
        for key, value in body.items():
            name = f"{section}_{key}"
            if name not in _FIELD_BY_NAME:
                raise ValueError(f"知らない設定: {section}.{key}")
            if name == "wazuh_named_rules":
                if not isinstance(value, list) or not all(_is_int(v) or isinstance(v, str) for v in value):
                    raise ValueError(f"設定 wazuh.named_rules はルール番号の配列で書く: {value!r}")
                value = frozenset(str(v) for v in value)
            elif name == "queue_retry_delays_sec":
                if not isinstance(value, list):
                    raise ValueError(f"設定 queue.retry_delays_sec は整数の配列で書く: {value!r}")
                value = tuple(value)
            values[name] = value
    return values


def _env_file(path: Path | None, env: Mapping[str, str]) -> Path | None:
    named = env.get(ENV_FILE_VAR, "").strip()
    if named:
        candidate = Path(named)
        if not candidate.is_file():
            raise ValueError(f"{ENV_FILE_VAR} のファイルがない: {candidate}")
        return candidate
    if path is not None and (Path(path).parent / ".env").is_file():
        return Path(path).parent / ".env"
    return None


def _rename(exc: ValueError, names: Mapping[str, str]) -> ValueError:
    """検証の表示の `設定 節.キー` を、値を書いた環境変数の名前にする。"""
    message = str(exc)
    for name in names:
        message = message.replace(f"設定 {_label(name)}", env_name(name)).replace(_label(name), env_name(name))
    return ValueError(message)


def inspect_config(path: Path | None = None, env: MutableMapping[str, str] | None = None) -> Loaded:
    """4 つの層を重ねて読み、項目ごとの由来も返す。

    `.env` のうち設定でない変数（接続先と秘密のファイルの場所）は、環境変数にないときだけ env に写す。
    その後の load_endpoints が同じ名前で読むため。
    """
    env = os.environ if env is None else env
    values: dict[str, object] = {}
    sources: dict[str, Source] = {f.name: "default" for f in fields(Config)}
    if path is not None:
        for name, value in _yaml_values(Path(path)).items():
            values[name] = value
            sources[name] = "yaml"
    env_file = _env_file(path, env)
    from_env: dict[str, str] = {}
    if env_file is not None:
        for variable, raw in read_dotenv(env_file).items():
            name = setting_name(variable)
            if name is not None:
                from_env[name] = raw
                sources[name] = ".env"
            elif variable.startswith(ENV_PREFIX) and variable not in dict(EXTERNAL_VARIABLES):
                raise ValueError(f"知らない設定: {variable}（{env_file}）")
            else:
                env.setdefault(variable, raw)
    for variable in sorted(env):
        if not variable.startswith(ENV_PREFIX):
            continue
        name = setting_name(variable)
        if name is not None:
            from_env[name] = env[variable]
            sources[name] = "env"
        elif variable not in dict(EXTERNAL_VARIABLES):
            log.warning("知らない設定の環境変数を無視する: %s", variable)
    for name, raw in from_env.items():
        values[name] = coerce(_FIELD_BY_NAME[name], raw)
    try:
        return Loaded(Config(**values), sources, env_file)
    except ValueError as exc:
        raise _rename(exc, from_env) from None


def load_config(path: Path | None = None, env: MutableMapping[str, str] | None = None) -> Config:
    """path が None なら YAML は読まない。env が None なら os.environ。"""
    return inspect_config(path, env).config
