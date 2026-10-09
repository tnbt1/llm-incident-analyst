"""起動時に確認の実行器を組む。鍵、カタログ、ホスト鍵、ssh のどれかがなければ警告して無効にする。"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

from tia.collectors.endpoints import Endpoints
from tia.config import Config
from tia.probes.catalog import Catalog, CatalogError
from tia.probes.runner import Runner

log = logging.getLogger("tia.probes")


# 試験のための差し替え。ssh の実行ファイルの場所。実環境では設定しない
SSH_BIN_ENV = "TIA_PROBE_SSH_BIN"


def build_runner(cfg: Config, endpoints: Endpoints | None, *, ssh_bin: str | None = None) -> Runner | None:
    """設定どおりに Runner を作る。作れない理由は 1 行で警告し、None を返す（確認なしで解析は動く）。"""
    ssh_bin = ssh_bin or os.environ.get(SSH_BIN_ENV, "").strip() or "ssh"
    if not cfg.probes_enabled:
        log.info("確認は設定で無効（probes.enabled: false）")
        return None
    key = Path(cfg.probes_key_file)
    known_hosts = Path(cfg.probes_known_hosts)
    catalog_path = Path(cfg.probes_catalog)
    missing = [str(p) for p in (key, known_hosts, catalog_path) if not p.is_file()]
    if missing:
        log.warning("確認を無効にする。ファイルがない: %s", "、".join(missing))
        return None
    ssh = shutil.which(ssh_bin)
    if ssh is None:
        log.warning("確認を無効にする。ssh の実行ファイルがない: %s", ssh_bin)
        return None
    try:
        catalog = Catalog.load(catalog_path)
    except (CatalogError, OSError, ValueError) as exc:
        log.warning("確認を無効にする。カタログを読めない: %s", exc)
        return None
    zabbix = endpoints.zabbix if endpoints is not None else None
    wazuh = endpoints.wazuh if endpoints is not None else None
    log.info("確認を有効にした: VM %d 台、確認 %d 種、利用者 %s", len(catalog.hosts), len(catalog.probes), cfg.probes_ssh_user)
    return Runner(cfg, catalog, ssh_bin=ssh, key_file=key, known_hosts=known_hosts, zabbix=zabbix, wazuh=wazuh,
                  tz=cfg.web_timezone)
