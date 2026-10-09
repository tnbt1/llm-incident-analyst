"""HTTP の層の、行ごとの受信と、止める合図。"""
import threading
import time

import pytest
from fakes import FakeServer, Reply

from tia.collectors.base import SourceError
from tia.collectors.http import Http


def _lines(cfg, server, **kwargs):
    with Http(cfg, **kwargs) as http:
        return list(http.stream_lines(server.url + "/stream", {"q": 1}))


def test_lines_arrive_in_order_and_the_request_is_a_post(cfg):
    with FakeServer(lambda request: Reply(body="data: 1\n\ndata: 2\n\ndata: [DONE]\n\n")) as server:
        lines = _lines(cfg, server)
        assert server.requests[0].method == "POST" and server.requests[0].json() == {"q": 1}
    assert [line for line in lines if line] == ["data: 1", "data: 2", "data: [DONE]"]


def test_refusal_keeps_the_kind_of_the_status(cfg):
    with FakeServer(lambda request: Reply(status=503, body={"detail": "x"})) as server:
        with pytest.raises(SourceError) as info:
            _lines(cfg, server)
    assert info.value.kind == "server"


def test_stream_larger_than_the_limit_is_cut(cfg):
    with FakeServer(lambda request: Reply(body=("data: " + "x" * 5000 + "\n\n") * 300)) as server:
        with pytest.raises(SourceError) as info:
            _lines(cfg, server, max_response_mb=1)
    assert info.value.kind == "too_large"


def test_dripping_stream_is_cut_at_the_overall_deadline(cfg):
    body = "".join(f"data: {n}\n\n" for n in range(40))
    with FakeServer(lambda request: Reply(body=body, drip=(8, 0.3))) as server:
        started = time.monotonic()
        with pytest.raises(SourceError) as info:
            _lines(cfg, server, timeout_sec=2)
        elapsed = time.monotonic() - started
    assert info.value.kind == "timeout"
    assert elapsed < 5


def test_interrupt_stops_a_waiting_read_within_a_second_or_two(cfg):
    stop = threading.Event()
    threading.Timer(0.5, stop.set).start()
    with FakeServer(lambda request: Reply(body="data: late\n\n", delay=10)) as server:
        started = time.monotonic()
        with pytest.raises(SourceError) as info:
            _lines(cfg, server, timeout_sec=30, interrupt=stop)
        elapsed = time.monotonic() - started
    assert info.value.kind == "stopped"
    assert elapsed < 4


def test_sliced_reads_do_not_change_a_normal_slow_answer(cfg):
    """1 回の待ちを刻んでも、2 秒以上黙ってから答える相手の応答は普通に読める。"""
    with FakeServer(lambda request: Reply(body={"ok": True}, delay=2.5)) as server:
        with Http(cfg, timeout_sec=10) as http:
            assert http.get_json(server.url + "/x") == {"ok": True}


def test_body_without_line_breaks_is_cut_quickly_at_the_limit(cfg):
    """M-6: 改行のない本文にも大きさの上限が効く。期限まで溜め込まない。"""
    # 40 MiB を 8 秒かけて送る相手。生のバイト数で数えれば 1 MiB で止まる。行で数えると最後まで待つ
    body = "x" * (40 * 1024 * 1024)
    with FakeServer(lambda request: Reply(body=body, drip=(256 * 1024, 0.05))) as server:
        started = time.monotonic()
        with pytest.raises(SourceError) as info:
            _lines(cfg, server, max_response_mb=1, timeout_sec=30)
        elapsed = time.monotonic() - started
    assert info.value.kind == "too_large"
    assert elapsed < 4


def test_lines_split_across_reads_and_crlf_arrive_whole(cfg):
    body = "data: " + "y" * 20000 + "\r\n\r\ndata: [DONE]\r\n\r\n"
    with FakeServer(lambda request: Reply(body=body, drip=(7, 0.0))) as server:
        lines = [line for line in _lines(cfg, server) if line]
    assert lines == ["data: " + "y" * 20000, "data: [DONE]"]
