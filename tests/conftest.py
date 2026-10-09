from datetime import UTC, datetime

import pytest

from tia.config import Config


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 9, 29, 5, 57, 0, tzinfo=UTC)


@pytest.fixture
def conn():
    from tia import db

    connection = db.connect(":memory:")
    yield connection
    connection.close()


@pytest.fixture
def rules():
    from pathlib import Path

    from tia.type_rules import load_type_rules

    return load_type_rules(Path(__file__).resolve().parents[1] / "config" / "type-rules.yaml")


@pytest.fixture(scope="session")
def ca():
    """テストの間だけ使う認証局。"""
    import trustme

    return trustme.CA()


@pytest.fixture(scope="session")
def server_tls(ca):
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("localhost", "127.0.0.1").configure_cert(context)
    return context


@pytest.fixture
def ca_file(ca, tmp_path):
    path = tmp_path / "root-ca.pem"
    ca.cert_pem.write_to_path(path)
    return path


@pytest.fixture
def fast(cfg):
    """待ち時間を最短にした設定。時間切れのテストを 1 秒で終わらせる。"""
    from dataclasses import replace

    return replace(cfg, collector_timeout_sec=1, collector_connect_timeout_sec=1)
