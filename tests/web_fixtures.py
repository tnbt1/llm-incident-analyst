"""画面のテストの pytest の部品。状態のそろった保存先、アプリ、テスト用のクライアント、本物のサーバー。"""
from __future__ import annotations

import contextlib
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient
from knowledge_helpers import build_fixture
from web_helpers import HOSTILE, NOW, Clock, collector_rows, make_db  # noqa: F401 - テストが一緒に import する

from tia import db
from tia.analysis.llm import LlmHealth
from tia.config import Config
from tia.web.app import create_app

BASE_URL = "https://testserver"


class Probe:
    """LLM の稼働の確認の代わり。結果を差し替えられる。"""

    def __init__(self) -> None:
        self.result = LlmHealth(True, "モデル example/model-27b に届く")
        self.calls = 0

    def __call__(self) -> LlmHealth:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def web_db(tmp_path):
    path = tmp_path / "web.sqlite"
    ids = make_db(path)
    conn = db.connect(path)
    collector_rows(conn)
    conn.close()
    return path, ids


@pytest.fixture
def web_clock():
    return Clock(NOW)


@pytest.fixture
def probe():
    return Probe()


@pytest.fixture
def bundle_dir(tmp_path):
    return build_fixture(tmp_path / "kb").path.parent


@pytest.fixture
def web_app(web_db, web_clock, probe, bundle_dir, request):
    """確認の実行器は、テストの側に probe_runner の fixture があればそれを使う。なければなし。"""
    try:
        probe_runner = request.getfixturevalue("probe_runner")
    except pytest.FixtureLookupError:
        probe_runner = None
    cfg = Config()
    app = create_app(web_db[0], cfg, bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock, probe_runner=probe_runner)
    app.state.tia.monitor.refresh()
    return app


@pytest.fixture
def client(web_app):
    with TestClient(web_app, base_url=BASE_URL) as test_client:
        yield test_client


@pytest.fixture
def ids(web_db):
    return web_db[1]


def token_of(client: TestClient) -> str:
    """一覧を 1 回読み、画面の印（CSRF トークン）を取り出す。Cookie は client に残る。"""
    page = client.get("/")
    assert page.status_code == 200
    start = page.text.index('name="tia-token" content="') + len('name="tia-token" content="')
    return page.text[start:page.text.index('"', start)]


def post(client: TestClient, path: str, token: str | None, data: dict | None = None, *, htmx: bool = True,
         origin: str | None = BASE_URL, **headers):
    """操作を送る。既定では同じ画面からの HTMX の要求として送る。"""
    form = dict(data or {})
    if token is not None:
        form["_token"] = token
    sent = {}
    if htmx:
        sent["HX-Request"] = "true"
    if origin:
        sent["Origin"] = origin
        sent["Sec-Fetch-Site"] = "same-origin"
    sent.update(headers)
    return client.post(path, data=form, headers=sent)


@contextlib.contextmanager
def serve(app):
    """本物の uvicorn で 127.0.0.1 の空きポートに待ち受ける。SSE のように終わらない応答を試すため。"""
    import uvicorn

    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "uvicorn が起動しない"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
