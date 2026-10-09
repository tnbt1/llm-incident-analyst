"""LLM の呼び出し。偽の Open WebUI に対して、本文、認証、ストリーミング、失敗の種類、期限、停止を確かめる。"""
import json
import logging
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from fakes import FakeLlm, FakeServer, unused_port

from tia.analysis.llm import ATTEMPT_KINDS, RELEASE_KINDS, LlmClient, LlmError
from tia.analysis.schema import response_format
from tia.collectors.base import SourceError
from tia.collectors.endpoints import LlmEndpoint

MESSAGES = [{"role": "system", "content": "規則"}, {"role": "user", "content": "資料と質問"}]


@pytest.fixture
def fake():
    return FakeLlm()


@pytest.fixture
def quick(cfg):
    """期限を短くした設定。時間切れのテストを数秒で終わらせる。"""
    return replace(cfg, llm_timeout_sec=2, llm_connect_timeout_sec=1)


def _client(server, fake, cfg, key_file=None):
    endpoint = LlmEndpoint(server.url + "/openai", key_file or Path("/nonexistent"), fake.model)
    return LlmClient(endpoint, cfg, api_key=fake.key)


def test_request_body_carries_the_decided_settings(fake, cfg):
    with FakeServer(fake.handle) as server:
        result = _client(server, fake, cfg).complete(MESSAGES, response_format=response_format())
    body = fake.requests[0]
    assert body["model"] == "example/model-27b"
    assert body["messages"] == MESSAGES
    assert (body["temperature"], body["max_tokens"], body["stream"], body["cache_prompt"]) == (0.2, 1200, True, True)
    assert body["response_format"]["json_schema"]["name"] == "analysis"
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert fake.paths == ["/openai/chat/completions"]
    assert json.loads(result.content)["summary"].startswith("example-router01")
    assert result.finish_reason == "stop"
    assert (result.prompt_tokens, result.completion_tokens) == (1234, result.chunks)
    assert result.tokens_per_sec == 7.0


def test_thinking_and_temperature_follow_the_settings(fake, cfg):
    with FakeServer(fake.handle) as server:
        client = _client(server, fake, replace(cfg, llm_thinking=True))
        client.complete(MESSAGES, response_format=response_format(), temperature=0.0, max_tokens=300)
    body = fake.requests[0]
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert (body["temperature"], body["max_tokens"]) == (0.0, 300)


def test_bearer_key_is_sent_and_progress_counts_the_chunks(fake, cfg):
    seen: list[int] = []
    with FakeServer(fake.handle) as server:
        client = _client(server, fake, cfg)
        result = client.complete(MESSAGES, response_format=response_format(), on_progress=seen.append)
    assert server.requests[0].headers["authorization"] == f"Bearer {fake.key}"
    assert seen == list(range(1, result.chunks + 1))
    assert result.chunks > 10


def test_wrong_key_is_an_auth_failure_that_releases(fake, cfg):
    with FakeServer(fake.handle) as server:
        client = LlmClient(LlmEndpoint(server.url + "/openai", Path("/x"), fake.model), cfg, api_key="wrong-key-123456")
        with pytest.raises(LlmError) as info:
            client.complete(MESSAGES, response_format=response_format())
    assert info.value.kind == "auth" and info.value.kind in RELEASE_KINDS
    assert "wrong-key" not in str(info.value)


@pytest.mark.parametrize("mode, kind", [
    ("http_500", "server"), ("non_json", "invalid_response"), ("invalid_json", None), ("truncated", "truncated"),
    ("error_json_200", "invalid_response"), ("error_in_stream", "invalid_response"),
])
def test_bad_answers_have_the_right_kind(fake, cfg, mode, kind):
    fake.modes = [mode]
    with FakeServer(fake.handle) as server:
        client = _client(server, fake, cfg)
        if kind is None:
            # 本文が JSON でない応答は、呼び出しとしては成功。検証の段階で落ちる
            assert client.complete(MESSAGES, response_format=response_format()).content == "これは JSON ではない"
            return
        with pytest.raises(LlmError) as info:
            client.complete(MESSAGES, response_format=response_format())
    assert info.value.kind == kind
    assert (kind in RELEASE_KINDS) == (mode in ("http_500", "non_json", "error_json_200", "error_in_stream"))


def test_wrong_route_answers_are_named_with_status_and_content_type(fake, cfg):
    """I-5: 経路違いの HTML や誤りの JSON は「途中で切れた」ではなく、何が返ったかを言う。試行は使わない。"""
    fake.modes = ["non_json", "error_json_200", "error_in_stream"]
    with FakeServer(fake.handle) as server:
        client = _client(server, fake, cfg)
        with pytest.raises(LlmError) as html:
            client.complete(MESSAGES, response_format=response_format())
        with pytest.raises(LlmError) as error_json:
            client.complete(MESSAGES, response_format=response_format())
        with pytest.raises(LlmError) as in_stream:
            client.complete(MESSAGES, response_format=response_format())
    assert html.value.kind == "invalid_response" and "text/html" in str(html.value) and "200" in str(html.value)
    assert "途中で切れた" not in str(html.value)
    assert error_json.value.kind == "invalid_response" and "model loading" in str(error_json.value)
    assert in_stream.value.kind == "invalid_response" and "context shift" in str(in_stream.value)
    assert "invalid_response" in RELEASE_KINDS


def test_finish_reason_ends_the_stream_even_without_done(fake, cfg):
    fake.modes = ["no_done"]
    with FakeServer(fake.handle) as server:
        result = _client(server, fake, cfg).complete(MESSAGES, response_format=response_format())
    assert result.finish_reason == "stop" and json.loads(result.content)


def test_length_is_returned_as_a_result_not_an_error(fake, cfg):
    fake.modes = ["length"]
    with FakeServer(fake.handle) as server:
        result = _client(server, fake, cfg).complete(MESSAGES, response_format=response_format())
    assert result.finish_reason == "length"


def test_token_counts_come_from_timings_then_usage_then_nothing(fake, cfg):
    with FakeServer(fake.handle) as server:
        client = _client(server, fake, cfg)
        from_timings = client.complete(MESSAGES, response_format=response_format())
        fake.modes = ["usage_only"]
        from_usage = client.complete(MESSAGES, response_format=response_format())
        fake.modes = ["no_counts"]
        from_nothing = client.complete(MESSAGES, response_format=response_format())
    assert (from_timings.prompt_tokens, from_timings.completion_tokens) == (1234, from_timings.chunks)
    assert (from_usage.prompt_tokens, from_usage.completion_tokens) == (1234, from_usage.chunks)
    assert (from_nothing.prompt_tokens, from_nothing.completion_tokens) == (None, None)
    assert from_timings.tokens_per_sec == 7.0


def test_fake_streams_like_the_real_server(fake, cfg):
    """偽の LLM は本物と同じ形で返す。text/event-stream、最後の断片に finish_reason と timings、usage はない。"""
    import httpx
    with FakeServer(fake.handle) as server:
        with httpx.Client() as http:
            with http.stream("POST", server.url + "/openai/chat/completions", json={"messages": MESSAGES},
                             headers={"Authorization": f"Bearer {fake.key}"}) as response:
                lines = [line for line in response.iter_lines() if line.startswith("data:")]
    assert response.headers["content-type"].startswith("text/event-stream")
    assert lines[-1] == "data: [DONE]"
    last = json.loads(lines[-2][5:])
    assert last["choices"][0]["finish_reason"] == "stop" and "timings" in last and "usage" not in last
    assert {"prompt_n", "predicted_n", "predicted_per_second"} <= set(last["timings"])


def test_refused_connection_is_unreachable(fake, cfg):
    endpoint = LlmEndpoint(f"http://127.0.0.1:{unused_port()}/openai", Path("/x"), fake.model)
    with pytest.raises(LlmError) as info:
        LlmClient(endpoint, replace(cfg, llm_connect_timeout_sec=1), api_key=fake.key).complete(
            MESSAGES, response_format=response_format())
    assert info.value.kind == "unreachable"


def test_slow_answer_is_cut_at_the_deadline(fake, quick):
    fake.modes = ["slow"]
    fake.slow_pause = 0.5
    with FakeServer(fake.handle) as server:
        started = time.monotonic()
        with pytest.raises(LlmError) as info:
            _client(server, fake, quick).complete(MESSAGES, response_format=response_format())
        elapsed = time.monotonic() - started
    assert info.value.kind == "timeout" and "timeout" in ATTEMPT_KINDS
    assert elapsed < 6


def test_silent_server_is_cut_at_the_deadline_before_the_first_byte(fake, quick):
    fake.modes = ["delay"]
    fake.delay = 10
    with FakeServer(fake.handle) as server:
        started = time.monotonic()
        with pytest.raises(LlmError) as info:
            _client(server, fake, quick).complete(MESSAGES, response_format=response_format())
        elapsed = time.monotonic() - started
    assert info.value.kind == "timeout"
    assert elapsed < 6


def test_stop_signal_interrupts_a_request_that_is_waiting(fake, cfg):
    fake.modes = ["delay"]
    fake.delay = 10
    stop = threading.Event()
    threading.Timer(0.5, stop.set).start()
    with FakeServer(fake.handle) as server:
        started = time.monotonic()
        with pytest.raises(LlmError) as info:
            _client(server, fake, replace(cfg, llm_timeout_sec=30)).complete(
                MESSAGES, response_format=response_format(), stop=stop)
        elapsed = time.monotonic() - started
    assert info.value.kind == "stopped" and "stopped" in RELEASE_KINDS
    assert elapsed < 4


def test_stop_signal_interrupts_a_stream_in_progress(fake, cfg):
    fake.modes = ["slow"]
    fake.slow_pause = 0.3
    stop = threading.Event()
    threading.Timer(0.8, stop.set).start()
    with FakeServer(fake.handle) as server:
        started = time.monotonic()
        with pytest.raises(LlmError) as info:
            _client(server, fake, replace(cfg, llm_timeout_sec=30)).complete(
                MESSAGES, response_format=response_format(), stop=stop)
        elapsed = time.monotonic() - started
    assert info.value.kind == "stopped"
    assert elapsed < 4


def test_key_echoed_by_the_peer_never_reaches_the_error_or_the_log(fake, cfg, caplog):
    fake.modes = ["echo_key"]
    with FakeServer(fake.handle) as server, caplog.at_level(logging.DEBUG):
        with pytest.raises(LlmError) as info:
            _client(server, fake, cfg).complete(MESSAGES, response_format=response_format())
    assert info.value.kind == "client"
    assert fake.key not in str(info.value) and fake.key[:12] not in str(info.value)
    assert fake.key not in caplog.text


def test_key_is_read_from_a_file_and_a_missing_file_is_a_configuration_error(fake, cfg, tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text(fake.key + "\n")
    with FakeServer(fake.handle) as server:
        endpoint = LlmEndpoint(server.url + "/openai", key_file, fake.model)
        client = LlmClient.from_endpoint(endpoint, cfg)
        assert client.complete(MESSAGES, response_format=response_format()).chunks > 0
        with pytest.raises(SourceError) as info:
            LlmClient.from_endpoint(LlmEndpoint(server.url + "/openai", tmp_path / "none", fake.model), cfg)
    assert info.value.kind == "credential"


def test_health_checks_the_root_and_the_model_list(fake, cfg):
    with FakeServer(fake.handle) as server:
        health = _client(server, fake, cfg).health()
        assert health.ok and "example/model-27b" in health.detail
        other = LlmClient(LlmEndpoint(server.url + "/openai", Path("/x"), "other/model"), cfg, api_key=fake.key)
        assert not other.health().ok and "一覧にない" in other.health().detail
        wrong = LlmClient(LlmEndpoint(server.url + "/openai", Path("/x"), fake.model), cfg, api_key="wrong-key-123456")
        assert not wrong.health().ok and wrong.health().detail.startswith("auth")
    assert fake.paths[:2] == ["/health", "/openai/models"]


def test_health_of_an_unreachable_server_says_so(fake, cfg):
    endpoint = LlmEndpoint(f"http://127.0.0.1:{unused_port()}/openai", Path("/x"), fake.model)
    health = LlmClient(endpoint, replace(cfg, llm_connect_timeout_sec=1), api_key=fake.key).health()
    assert not health.ok and health.detail.startswith("unreachable")
