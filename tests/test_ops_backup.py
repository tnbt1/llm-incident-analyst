"""バックアップと復元。書き込み中の一貫性、世代、残骸、使用中の拒否。"""
import json
import os
import sqlite3
import tarfile
import threading
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from builders import zabbix_problem

from tia import db, intake
from tia.config import Config
from tia.normalize import normalize_zabbix
from tia.ops import backup
from tia.type_rules import load_type_rules

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 6, 19, 30, tzinfo=UTC)


def seed(path, count=20, start=50000):
    cfg, rules = Config(), load_type_rules(ROOT / "config" / "type-rules.yaml")
    with closing(db.connect(path)) as conn:
        for n in range(count):
            alert = normalize_zabbix(zabbix_problem(event_id=str(start + n), trigger_id=str(start + 10000 + n),
                                                    clock=1790661000 + n), cfg, rules)
            intake.apply(conn, alert, NOW, cfg)


def test_backup_makes_a_self_contained_copy_with_a_manifest(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path)
    result = backup.backup(path, tmp_path / "backups", keep=7, now=NOW)
    assert result.directory == tmp_path / "backups" / "20261006T193000Z"
    assert result.check == "ok" and result.size_bytes > 0 and len(result.sha256) == 64
    manifest = json.loads((result.directory / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["database"]["counts"]["incidents"] == 20 and manifest["database"]["quick_check"] == "ok"
    assert manifest["database"]["sha256"] == result.sha256
    with closing(sqlite3.connect(result.database)) as copy:
        assert copy.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert copy.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 20
    assert not (result.directory / "tia.sqlite-wal").exists()
    assert "20261006T193000Z" in result.summary()


def test_backup_taken_during_writes_is_consistent(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path, 5)
    stop = threading.Event()

    def writer():
        cfg, rules = Config(), load_type_rules(ROOT / "config" / "type-rules.yaml")
        with closing(db.connect(path)) as conn:
            n = 0
            while not stop.is_set():
                alert = normalize_zabbix(zabbix_problem(event_id=str(70000 + n), trigger_id=str(80000 + n),
                                                        clock=1790661000 + n), cfg, rules)
                intake.apply(conn, alert, NOW, cfg)
                n += 1

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        time.sleep(0.2)
        results = [backup.backup(path, tmp_path / "backups", keep=7, now=NOW + timedelta(seconds=i)) for i in range(3)]
    finally:
        stop.set()
        thread.join()
    for result in results:
        assert result.check == "ok"
        with closing(sqlite3.connect(result.database)) as copy:
            incidents = copy.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            # 取り込みはインシデントと経過を 1 つのまとまりで書く。半端な写しなら経過が足りない
            with_event = copy.execute("SELECT COUNT(DISTINCT incident_id) FROM events").fetchone()[0]
            assert incidents == with_event >= 5


def test_config_and_bundle_are_archived_without_secrets(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path, 1)
    config = tmp_path / "config"
    (config / "knowledge" / "20261001-abc").mkdir(parents=True)
    (config / "analyzer.yaml").write_text("zabbix:\n  min_severity: 2\n", encoding="utf-8")
    (config / "knowledge" / "current").write_text("20261001-abc\n", encoding="utf-8")
    (config / "secrets").mkdir()
    (config / "secrets" / "zabbix_api_token").write_text("fake-token-for-local-test\n", encoding="utf-8")
    result = backup.backup(path, tmp_path / "backups", keep=7, now=NOW, config_dir=config)
    with tarfile.open(result.config_archive) as archive:
        names = archive.getnames()
    assert "config/analyzer.yaml" in names and "config/knowledge/current" in names
    assert not any("secrets" in name for name in names)
    assert b"fake-token-for-local-test" not in result.config_archive.read_bytes()


def test_old_generations_are_pruned_to_keep(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path, 1)
    out = tmp_path / "backups"
    removed = []
    for i in range(5):
        removed.extend(backup.backup(path, out, keep=3, now=NOW + timedelta(minutes=i)).removed)
    kept = sorted(p.name for p in out.iterdir())
    assert kept == ["20261006T193200Z", "20261006T193300Z", "20261006T193400Z"]
    assert removed == ["20261006T193000Z", "20261006T193100Z"]  # 世代が 4 つ目、5 つ目になった回に 1 つずつ


def test_partial_backup_is_not_counted_and_is_removed(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path, 1)
    out = tmp_path / "backups"
    out.mkdir()
    stale = out / ".20261001T000000Z.partial"
    stale.mkdir()
    (stale / "tia.sqlite").write_bytes(b"half")
    old = time.time() - 2 * 86400
    os.utime(stale, (old, old))
    result = backup.backup(path, out, keep=1, now=NOW)
    assert not stale.exists() and result.directory.exists()
    assert sorted(p.name for p in out.iterdir()) == ["20261006T193000Z"]


def test_same_generation_twice_is_refused(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path, 1)
    backup.backup(path, tmp_path / "backups", keep=7, now=NOW)
    with pytest.raises(backup.BackupError, match="同じ時刻"):
        backup.backup(path, tmp_path / "backups", keep=7, now=NOW)


def test_restore_replaces_the_database_after_checking_it(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path, 3)
    result = backup.backup(path, tmp_path / "backups", keep=7, now=NOW)
    with closing(db.connect(path)) as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM alert_refs")
        conn.execute("DELETE FROM incidents")
    restored = backup.restore(result.database, path)
    assert restored == path
    with closing(db.connect(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 3
    assert not Path(str(path) + ".restoring").exists()


def test_restore_refuses_a_database_that_is_in_use(tmp_path):
    from tia.ops.service import InstanceLock

    path = tmp_path / "tia.sqlite"
    seed(path, 1)
    result = backup.backup(path, tmp_path / "backups", keep=7, now=NOW)
    lock = InstanceLock(path)
    lock.acquire()
    try:
        with pytest.raises(backup.BackupError, match="動いている"):
            backup.restore(result.database, path)
    finally:
        lock.release()


def test_restore_refuses_a_broken_copy(tmp_path):
    path = tmp_path / "tia.sqlite"
    seed(path, 1)
    broken = tmp_path / "broken.sqlite"
    broken.write_bytes(b"not a database at all")
    with pytest.raises(backup.BackupError, match="読めない"):
        backup.restore(broken, path)
    with closing(db.connect(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


def test_backup_of_a_missing_database_is_refused(tmp_path):
    with pytest.raises(backup.BackupError, match="保存先がない"):
        backup.backup(tmp_path / "none.sqlite", tmp_path / "backups", keep=7, now=NOW)
