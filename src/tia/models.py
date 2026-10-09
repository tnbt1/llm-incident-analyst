"""取り込みから待ち行列までで共有する型。"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class Source(StrEnum):
    ZABBIX = "zabbix"
    WAZUH = "wazuh"
    GROUP = "group"


class AnalysisState(StrEnum):
    HELD = "held"
    QUEUED = "queued"
    RETRY_WAIT = "retry_wait"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    GROUPED = "grouped"


class ProblemStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    ONESHOT = "oneshot"


class IncidentType(StrEnum):
    CPU = "cpu"
    MEM = "mem"
    SWAP = "swap"
    DISK = "disk"
    IO = "io"
    NET = "net"
    CONTAINER = "container"
    SERVICE = "service"
    AUTH = "auth"
    USER = "user"
    FILE = "file"
    PKG = "pkg"
    OTHER = "other"


@dataclass(frozen=True)
class NormalizedAlert:
    source: Source
    external_id: str
    host: str
    type: IncidentType
    source_severity: str
    severity: int
    title: str
    started_at: datetime
    resolved_at: datetime | None
    problem_status: ProblemStatus
    fingerprint: str
    analyzable: bool
    availability: bool
    raw: dict


def to_iso(value: datetime) -> str:
    """UTC の秒精度の文字列。文字列のまま大小を比べられる。"""
    if value.tzinfo is None:
        raise ValueError("時刻にはタイムゾーンが必要")
    return value.astimezone(UTC).isoformat(timespec="seconds")


def from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)
