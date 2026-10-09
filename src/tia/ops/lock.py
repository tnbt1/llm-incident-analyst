"""同じ保存先で 2 つの司令塔を動かさないためのロック。"""
from __future__ import annotations

import fcntl
import os
from datetime import UTC, datetime
from pathlib import Path

from tia.models import to_iso


class LockError(RuntimeError):
    """別の司令塔が同じ保存先を使っている。"""


def lock_path(db_path: Path | str) -> Path:
    return Path(str(db_path) + ".lock")


class InstanceLock:
    """保存先の隣の .lock を flock で握る。プロセスが倒れても鍵は自動で外れる。"""

    def __init__(self, db_path: Path | str) -> None:
        self.path = lock_path(db_path)
        self._file = None

    def acquire(self) -> None:
        handle = open(self.path, "a+", encoding="utf-8")  # noqa: SIM115 - 握っている間は開いたままにする
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.seek(0)
            holder = handle.read().strip()
            handle.close()
            raise LockError(f"別の司令塔が動いている（{self.path}、{holder or '持ち主は不明'}）") from None
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid {os.getpid()} since {to_iso(datetime.now(UTC))}\n")
        handle.flush()
        self._file = handle

    def release(self) -> None:
        if self._file is None:
            return
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()
        self._file = None

    @staticmethod
    def is_held(db_path: Path | str) -> bool:
        path = lock_path(db_path)
        if not path.exists():
            return False
        with open(path, "a+", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return False
