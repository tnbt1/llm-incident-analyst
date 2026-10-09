"""SQLite の接続と、番号付きの移行。"""
from __future__ import annotations

import itertools
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_savepoints = itertools.count(1)

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
CREATE TABLE incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  host TEXT NOT NULL,
  type TEXT NOT NULL,
  source_severity TEXT NOT NULL,
  severity INTEGER NOT NULL,
  title TEXT NOT NULL,
  started_at TEXT NOT NULL,
  resolved_at TEXT,
  problem_status TEXT NOT NULL,
  availability INTEGER NOT NULL DEFAULT 0,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  last_occurrence_at TEXT NOT NULL,
  group_id INTEGER REFERENCES incidents(id),
  analysis_state TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  held_until TEXT,
  next_retry_at TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  queue_reason TEXT NOT NULL DEFAULT 'initial',
  analyzed_at TEXT,
  followup_done INTEGER NOT NULL DEFAULT 0,
  skip_reason TEXT,
  fail_reason TEXT,
  urgency TEXT,
  kind TEXT,
  summary TEXT,
  latest_analysis_id INTEGER,
  read_at TEXT,
  raw_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source, external_id)
);
CREATE INDEX idx_incidents_fingerprint ON incidents (fingerprint, last_occurrence_at);
CREATE INDEX idx_incidents_state ON incidents (analysis_state, severity, started_at);
CREATE UNIQUE INDEX idx_incidents_one_running ON incidents (analysis_state) WHERE analysis_state = 'running';
CREATE TABLE alert_refs (
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  seen_at TEXT NOT NULL,
  resolved_at TEXT,
  PRIMARY KEY (source, external_id)
);
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  at TEXT NOT NULL,
  type TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_events_incident ON events (incident_id, id);
CREATE TABLE collector_state (
  source TEXT PRIMARY KEY,
  watermark TEXT,
  last_poll_at TEXT,
  last_ok_at TEXT,
  last_error TEXT
);
"""),
    (2, """
ALTER TABLE collector_state ADD COLUMN last_error_kind TEXT;
ALTER TABLE collector_state ADD COLUMN last_error_at TEXT;
ALTER TABLE collector_state ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE collector_state ADD COLUMN next_poll_at TEXT;
ALTER TABLE collector_state ADD COLUMN cursor TEXT;
ALTER TABLE collector_state ADD COLUMN round INTEGER NOT NULL DEFAULT 0;
ALTER TABLE collector_state ADD COLUMN incomplete_polls INTEGER NOT NULL DEFAULT 0;
ALTER TABLE collector_state ADD COLUMN stuck_at TEXT;
ALTER TABLE collector_state ADD COLUMN stuck_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_refs ADD COLUMN listed_round INTEGER;
ALTER TABLE alert_refs ADD COLUMN missing_rounds INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_alert_refs_open ON alert_refs (source, external_id) WHERE resolved_at IS NULL;
"""),
    (3, """
CREATE TABLE analyses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  trigger TEXT NOT NULL,
  status TEXT NOT NULL,
  phase TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 1,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  duration_ms INTEGER,
  model TEXT NOT NULL,
  quantization TEXT,
  prompt_hash TEXT,
  knowledge_version TEXT,
  context_json TEXT,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  tokens_so_far INTEGER NOT NULL DEFAULT 0,
  tokens_per_sec REAL,
  result_json TEXT,
  error_kind TEXT,
  error TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_analyses_incident ON analyses (incident_id, id);
CREATE INDEX idx_analyses_status ON analyses (status, started_at);
CREATE TABLE cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL UNIQUE REFERENCES incidents(id),
  fingerprint TEXT NOT NULL,
  host TEXT NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  symptoms TEXT NOT NULL,
  cause TEXT NOT NULL,
  confirmation TEXT NOT NULL,
  action TEXT NOT NULL,
  time_to_recover_sec INTEGER,
  occurred_on TEXT NOT NULL,
  verdict TEXT NOT NULL,
  status TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  stale_reason TEXT,
  tokens INTEGER NOT NULL
);
CREATE INDEX idx_cases_fingerprint ON cases (fingerprint, approved_at);
CREATE INDEX idx_cases_host_type ON cases (host, type, approved_at);
CREATE INDEX idx_cases_type ON cases (type, approved_at);
ALTER TABLE incidents ADD COLUMN confirmed_at TEXT;
ALTER TABLE incidents ADD COLUMN confirmed_verdict TEXT;
"""),
    (4, """
CREATE TABLE probes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  analysis_id INTEGER,
  name TEXT NOT NULL,
  target TEXT NOT NULL,
  command TEXT,
  trigger TEXT NOT NULL,
  started_at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  status TEXT NOT NULL,
  output TEXT NOT NULL,
  error TEXT
);
CREATE INDEX idx_probes_incident ON probes (incident_id, id);
CREATE INDEX idx_probes_analysis ON probes (analysis_id, id);
"""),
]


def connect(path: str | Path) -> sqlite3.Connection:
    """接続して移行を済ませる。`:memory:` も受け付ける。"""
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    # 並べ替えの一時領域をメモリに置く。ルートが読み取り専用でも動かすため。
    conn.execute("PRAGMA temp_store = MEMORY")
    if str(path) != ":memory:":
        _enable_wal(conn)
    migrate(conn)
    return conn


def _enable_wal(conn: sqlite3.Connection, *, attempts: int = 50, pause: float = 0.1) -> None:
    """WAL にする。新しいファイルを 2 つの接続が同時に開くと、片方が busy handler の効かない形で
    「database is locked」になることがあるので、短く待って試し直す。"""
    for attempt in range(attempts):
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            time.sleep(pause)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """書き込みを 1 つにまとめる。

    外側にまとまりがあれば、その中の区切りとして動く。内側の失敗は内側だけを取り消し、
    外側の失敗は内側も含めて取り消す。外側がなければ、書き込みの鍵を先に取って始める。
    """
    if conn.in_transaction:
        name = f"tia_{next(_savepoints)}"
        conn.execute(f"SAVEPOINT {name}")
        try:
            yield conn
        except BaseException:
            conn.execute(f"ROLLBACK TO {name}")
            conn.execute(f"RELEASE {name}")
            raise
        conn.execute(f"RELEASE {name}")
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def schema_version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _statements(sql: str) -> Iterator[str]:
    """移行の SQL を文ごとに分ける。executescript は途中で COMMIT してしまうので使わない。"""
    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            yield buffer.strip()
            buffer = ""
    if buffer.strip():
        yield buffer.strip()


def migrate(conn: sqlite3.Connection) -> int:
    """未適用の移行を番号順に適用し、適用後の番号を返す。

    書き込みの鍵を先に取ってから版を読み直す。同じ保存先を 2 つの接続が同時に開いても、
    後の方は前の方の移行が終わってから版を見るので、表を二重に作らない。
    """
    latest = MIGRATIONS[-1][0]
    if schema_version(conn) >= latest:
        return latest
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = schema_version(conn)
        for number, sql in MIGRATIONS:
            if number <= current:
                continue
            for statement in _statements(sql):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {number}")
            current = number
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return current
