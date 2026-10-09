"""同じ保存先に 2 つの接続が同時に始まるときの移行。

司令塔は 1 プロセスに複数の接続を持ち、バックアップや整理は別のプロセスから同じ保存先を開く。
"""
import multiprocessing
import sqlite3
from contextlib import closing

from tia import db


def test_stale_version_read_before_the_lock_does_not_recreate_the_tables(tmp_path, monkeypatch):
    """版を読んだ後に別の接続が移行を終えていても、鍵を取ってから読み直すので二重に作らない。"""
    path = tmp_path / "tia.sqlite"
    with closing(db.connect(path)):
        pass  # 別の接続が先に移行を終えた状態
    real = db.schema_version
    calls = []

    def stale_once(conn):
        calls.append(1)
        return 0 if len(calls) == 1 else real(conn)

    monkeypatch.setattr(db, "schema_version", stale_once)
    with closing(db.connect(path)) as conn:  # 旧実装は executescript が "table incidents already exists" で落ちる
        assert real(conn) == len(db.MIGRATIONS)
        assert not conn.in_transaction


def _open(args):
    path, n = args
    try:
        with closing(db.connect(path)) as conn:
            return conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    except sqlite3.Error as exc:
        import traceback
        return f"{type(exc).__name__}: {exc} @ {traceback.extract_tb(exc.__traceback__)[-1].lineno}"


def test_processes_opening_a_new_database_at_once_all_succeed(tmp_path):
    results = []
    with multiprocessing.get_context("spawn").Pool(4) as pool:
        for round_ in range(6):
            path = tmp_path / f"race-{round_}.sqlite"
            results.extend(pool.map(_open, [(path, n) for n in range(4)]))
    assert results == [0] * 24, results
