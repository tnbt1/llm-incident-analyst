"""バックアップと復元。SQLite のオンラインバックアップで、書き込み中でも一貫した写しを取る。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tarfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from tia.ops.lock import InstanceLock

STAMP = "%Y%m%dT%H%M%SZ"
GENERATION = re.compile(r"\d{8}T\d{6}Z")
PARTIAL_MAX_AGE_SEC = 86400
COUNTED_TABLES = ("incidents", "events", "alert_refs", "analyses", "cases")


class BackupError(RuntimeError):
    """バックアップか復元ができない。"""


@dataclass(frozen=True)
class BackupResult:
    directory: Path
    database: Path
    size_bytes: int
    sha256: str
    check: str
    config_archive: Path | None
    removed: tuple[str, ...]

    def summary(self) -> str:
        extra = f"、設定 {self.config_archive.name}" if self.config_archive else ""
        return (f"バックアップ: {self.directory.name}（{self.size_bytes:,} バイト、確認 {self.check}{extra}）。"
                f"消した世代: {', '.join(self.removed) or 'なし'}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _copy_database(source: Path, target: Path) -> str:
    """オンラインバックアップで写し、1 ファイルで完結する形にし、quick_check の結果を返す。"""
    src = sqlite3.connect(str(source), timeout=30)
    try:
        src.execute("PRAGMA busy_timeout = 30000")
        dst = sqlite3.connect(str(target))
        try:
            # 1 回で全部を写す。少しずつ写すと、書き込みが続く間はやり直し続けて終わらない。
            # WAL なので、写している間も書き込みは止まらない
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    copy = sqlite3.connect(str(target))
    try:
        copy.execute("PRAGMA journal_mode = DELETE")
        check = copy.execute("PRAGMA quick_check").fetchone()[0]
    finally:
        copy.close()
    return str(check)


def _counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in COUNTED_TABLES if table in tables}
    finally:
        conn.close()


def _archive_config(config_dir: Path, target: Path) -> None:
    """設定と知識の束を固める。secrets/ は入れない。"""
    def keep(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        return None if "secrets" in Path(info.name).parts else info

    with tarfile.open(target, "w:gz") as archive:
        archive.add(config_dir, arcname="config", filter=keep)


def _prune(out_dir: Path, keep: int) -> tuple[str, ...]:
    generations = sorted(p for p in out_dir.iterdir() if p.is_dir() and GENERATION.fullmatch(p.name))
    removed = []
    for old in generations[:-keep]:
        shutil.rmtree(old)
        removed.append(old.name)
    now = time.time()
    for leftover in out_dir.glob(".*.partial"):
        if leftover.is_dir() and now - leftover.stat().st_mtime > PARTIAL_MAX_AGE_SEC:
            shutil.rmtree(leftover, ignore_errors=True)
    return tuple(removed)


def backup(db_path: Path | str, out_dir: Path | str, *, keep: int, now: datetime,
           config_dir: Path | str | None = None) -> BackupResult:
    """1 世代を取る。書きかけは .<時刻>.partial に作り、終わってから名前を変える。古い世代は keep まで消す。"""
    db_path, out_dir = Path(db_path), Path(out_dir)
    if not db_path.is_file():
        raise BackupError(f"保存先がない: {db_path}")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = now.astimezone(UTC).strftime(STAMP)
    final = out_dir / stamp
    if final.exists():
        raise BackupError(f"同じ時刻の世代がある: {final}")
    partial = out_dir / f".{stamp}.partial"
    shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir()
    try:
        database = partial / "tia.sqlite"
        check = _copy_database(db_path, database)
        if check != "ok":
            raise BackupError(f"写しの確認に失敗した: {check}")
        archive = None
        if config_dir is not None and Path(config_dir).is_dir():
            archive = partial / "config.tar.gz"
            _archive_config(Path(config_dir), archive)
        digest = _sha256(database)
        manifest = {"taken_at": now.astimezone(UTC).isoformat(timespec="seconds"), "source": str(db_path),
                    "database": {"file": "tia.sqlite", "size": database.stat().st_size, "sha256": digest,
                                 "quick_check": check, "counts": _counts(database)},
                    "config_archive": archive.name if archive else None}
        (partial / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n",
                                               encoding="utf-8")
        os.replace(partial, final)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    removed = _prune(out_dir, keep)
    final_db = final / "tia.sqlite"
    return BackupResult(final, final_db, final_db.stat().st_size, digest, check,
                        (final / "config.tar.gz") if archive else None, removed)


def restore(source: Path | str, db_path: Path | str) -> Path:
    """写しで保存先を置き換える。動いている保存先には行わない。写しは先に確かめる。"""
    source, db_path = Path(source), Path(db_path)
    if not source.is_file():
        raise BackupError(f"写しがない: {source}")
    if InstanceLock.is_held(db_path):
        raise BackupError(f"保存先を使っている司令塔が動いている: {db_path}。止めてから復元する")
    try:
        probe = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        try:
            check = probe.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            probe.close()
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"写しが読めない: {source}（{type(exc).__name__}）") from None
    if check != "ok":
        raise BackupError(f"写しの確認に失敗した: {check}")
    staging = db_path.with_name(db_path.name + ".restoring")
    shutil.copyfile(source, staging)
    for suffix in ("-wal", "-shm"):
        side = Path(str(db_path) + suffix)
        if side.exists():
            side.unlink()
    os.replace(staging, db_path)
    return db_path
