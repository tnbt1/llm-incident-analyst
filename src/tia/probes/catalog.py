"""確認のカタログ。名前と固定のコマンドの表を読んで確かめ、インシデントに合う確認を選ぶ。

コマンドは表に書いたものしか動かない。解析基盤から VM に渡るのは確認の名前 1 語だけで、
コマンドの本文は VM 側の実行器にも同じ表として焼き込まれている。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from tia.models import IncidentType

WHERE = ("host", "zabbix", "wazuh")
ROLES = ("frr", "docker")
MAX_TIMEOUT_SEC = 30
MAX_CAP_BYTES = 65536
# 確認の名前。SSH で VM に渡る唯一の文字列なので、形を限る
NAME = re.compile(r"[a-z][a-z0-9_]{0,39}")
# コマンドの文字列に入れない形。表は固定だが、見た目で読み取りだけと分かる形に保つ（置換、連結、転送）
FORBIDDEN_IN_COMMAND = re.compile(r"\$\(|`|;|&&|\|\||[<>](?!=)|\n")
PLACEHOLDERS = ("compose", "guard_table")
ALWAYS = "always"
# when に書ける条件。type: は models.IncidentType の語彙、source: は収集の系統。存在しない種類を書くと
# 一度も動かない確認になるので、読み込みで断る
TYPES = frozenset(t.value for t in IncidentType)
SOURCES = frozenset(("zabbix", "wazuh"))
CONDITION = re.compile(r"(type|source):([a-z][a-z0-9_-]{0,39})")


class CatalogError(ValueError):
    """カタログの書き方の誤り。"""


@dataclass(frozen=True)
class HostEntry:
    name: str
    ip: str
    guard_table: str
    compose: str | None
    roles: frozenset[str]


@dataclass(frozen=True)
class Probe:
    name: str
    where: str
    timeout_sec: int
    cap_bytes: int
    when: frozenset[str]
    command: str | None
    hosts: frozenset[str] | None  # None = どの VM でも（host のとき）

    def matches(self, incident_type: str, source: str) -> bool:
        """段階 1 で動かす条件に合うか。"""
        return (ALWAYS in self.when or f"type:{incident_type}" in self.when or f"source:{source}" in self.when)


@dataclass(frozen=True)
class Catalog:
    probes: dict[str, Probe]
    hosts: dict[str, HostEntry]

    @classmethod
    def load(cls, path: Path) -> Catalog:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("hosts"), dict) or not isinstance(data.get("probes"), dict):
            raise CatalogError("カタログは hosts と probes の対応表で書く")
        hosts = {str(name): _host(str(name), body) for name, body in data["hosts"].items()}
        probes = {str(name): _probe(str(name), body, hosts) for name, body in data["probes"].items()}
        if not probes:
            raise CatalogError("カタログに確認が 1 つもない")
        return cls(probes=probes, hosts=hosts)

    def for_incident(self, host: str, incident_type: str, source: str) -> list[Probe]:
        """段階 1 で動かす確認。VM の確認は目録にあるホストにだけ。カタログの順を保つ。"""
        chosen = []
        for probe in self.probes.values():
            if not probe.matches(incident_type, source):
                continue
            if probe.where == "host" and not self.runs_on(probe, host):
                continue
            chosen.append(probe)
        return chosen

    def runs_on(self, probe: Probe, host: str) -> bool:
        """その VM で動かせる確認か。API の確認はホストを問わない。"""
        if probe.where != "host":
            return True
        if host not in self.hosts:
            return False
        return probe.hosts is None or host in probe.hosts

    def command_for(self, probe: Probe, host: str) -> str | None:
        """VM で動く実際のコマンド。目録の値で穴を埋める。表示と、推奨の確認との照合に使う。"""
        if probe.command is None or host not in self.hosts:
            return None
        entry = self.hosts[host]
        return probe.command.format(compose=entry.compose or "", guard_table=entry.guard_table)


def _host(name: str, body: object) -> HostEntry:
    if not isinstance(body, dict):
        raise CatalogError(f"hosts.{name} は対応表で書く")
    ip = body.get("ip")
    if not isinstance(ip, str) or not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        raise CatalogError(f"hosts.{name}.ip は IPv4 で書く: {ip!r}")
    table = body.get("guard_table")
    if not isinstance(table, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", table):
        raise CatalogError(f"hosts.{name}.guard_table は表の名前で書く: {table!r}")
    compose = body.get("compose")
    if compose is not None and (not isinstance(compose, str) or not compose.startswith("/") or " " in compose):
        raise CatalogError(f"hosts.{name}.compose は絶対パスか null で書く: {compose!r}")
    roles = body.get("roles", [])
    if not isinstance(roles, list) or not all(r in ROLES for r in roles):
        raise CatalogError(f"hosts.{name}.roles は {'、'.join(ROLES)} の配列で書く: {roles!r}")
    unknown = set(body) - {"ip", "guard_table", "compose", "roles"}
    if unknown:
        raise CatalogError(f"hosts.{name} に知らないキー: {sorted(unknown)}")
    return HostEntry(name=name, ip=ip, guard_table=table, compose=compose, roles=frozenset(roles))


def _probe(name: str, body: object, hosts: dict[str, HostEntry]) -> Probe:
    if not NAME.fullmatch(name):
        raise CatalogError(f"確認の名前は小文字と数字と _ で書く: {name!r}")
    if not isinstance(body, dict):
        raise CatalogError(f"probes.{name} は対応表で書く")
    where = body.get("where")
    if where not in WHERE:
        raise CatalogError(f"probes.{name}.where は {'、'.join(WHERE)} のどれかで書く: {where!r}")
    timeout = body.get("timeout_sec")
    if not _is_int(timeout) or not 1 <= timeout <= MAX_TIMEOUT_SEC:
        raise CatalogError(f"probes.{name}.timeout_sec は 1 から {MAX_TIMEOUT_SEC} の整数で書く: {timeout!r}")
    cap = body.get("cap_bytes")
    if not _is_int(cap) or not 1 <= cap <= MAX_CAP_BYTES:
        raise CatalogError(f"probes.{name}.cap_bytes は 1 から {MAX_CAP_BYTES} の整数で書く: {cap!r}")
    when = body.get("when")
    if (not isinstance(when, list) or not when
            or not all(isinstance(w, str) and (w == ALWAYS or CONDITION.fullmatch(w)) for w in when)):
        raise CatalogError(f"probes.{name}.when は always、type:<種類>、source:<出所> の配列で書く: {when!r}")
    for condition in when:
        match = CONDITION.fullmatch(condition)
        if match and match.group(1) == "type" and match.group(2) not in TYPES:
            raise CatalogError(f"probes.{name}.when の種類 {match.group(2)!r} はない。使えるのは {'、'.join(sorted(TYPES))}")
        if match and match.group(1) == "source" and match.group(2) not in SOURCES:
            raise CatalogError(f"probes.{name}.when の出所 {match.group(2)!r} はない。使えるのは {'、'.join(sorted(SOURCES))}")
    command = body.get("command")
    if where == "host":
        if not isinstance(command, str) or not command.strip():
            raise CatalogError(f"probes.{name}.command は VM で動くコマンドを書く")
        # 単引用符の中（awk の式など）はシェルに解釈されないので、見ない
        if FORBIDDEN_IN_COMMAND.search(re.sub(r"'[^']*'", "''", command)):
            raise CatalogError(f"probes.{name}.command に使えない文字がある: {command!r}")
        for hole in re.findall(r"\{([^}]*)\}", command):
            if hole not in PLACEHOLDERS:
                raise CatalogError(f"probes.{name}.command の穴 {{{hole}}} は {'、'.join(PLACEHOLDERS)} のどれかで書く")
    elif command is not None:
        raise CatalogError(f"probes.{name}.command は where が host のときだけ書く")
    roles = body.get("roles")
    chosen: frozenset[str] | None = None
    if roles is not None:
        if where != "host" or not isinstance(roles, list) or not roles or not all(r in ROLES for r in roles):
            raise CatalogError(f"probes.{name}.roles は host の確認に {'、'.join(ROLES)} の配列で書く: {roles!r}")
        chosen = frozenset(h.name for h in hosts.values() if h.roles & set(roles))
        if "{compose}" in str(command) and any(hosts[h].compose is None for h in chosen):
            raise CatalogError(f"probes.{name} は compose のない VM では動かせない")
    elif where == "host" and "{compose}" in str(command):
        raise CatalogError(f"probes.{name}.command に {{compose}} があるなら roles: [docker] を書く")
    unknown = set(body) - {"where", "command", "roles", "when", "timeout_sec", "cap_bytes"}
    if unknown:
        raise CatalogError(f"probes.{name} に知らないキー: {sorted(unknown)}")
    return Probe(name=name, where=where, timeout_sec=timeout, cap_bytes=cap, when=frozenset(when),
                 command=command, hosts=chosen)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
