"""LLM の呼び出し。Open WebUI の中継経路に JSON スキーマ付きの要求を送り、応答を少しずつ受け取る。"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tia.collectors.base import SourceError, read_secret, scrub
from tia.collectors.endpoints import LlmEndpoint
from tia.collectors.http import Http
from tia.config import Config

# 要求を失敗にする種類と、待ちに戻す種類。timeout と truncated は試行に数える。
# invalid_response（経路違いや相手の誤りの応答）は設定か相手の問題なので、試行を使わずに待ちに戻す。
RELEASE_KINDS = frozenset({"unreachable", "server", "auth", "tls", "throttled", "stopped", "invalid_response"})
ATTEMPT_KINDS = frozenset({"timeout", "truncated", "too_large", "client"})
# 稼働の確認の制限時間（秒）。推論の制限時間とは別
HEALTH_TIMEOUT_SEC = 10.0
MAX_LINE = 1_000_000
EXCERPT = 160


class LlmError(Exception):
    """LLM の呼び出しの失敗。kind は RELEASE_KINDS か ATTEMPT_KINDS のどれか。"""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class LlmResult:
    content: str
    chunks: int
    elapsed_sec: float
    finish_reason: str | None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    timings: dict = field(default_factory=dict)

    @property
    def tokens_per_sec(self) -> float | None:
        value = self.timings.get("predicted_per_second")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if self.elapsed_sec > 0 and self.chunks:
            return round(self.chunks / self.elapsed_sec, 2)
        return None


@dataclass(frozen=True)
class LlmHealth:
    ok: bool
    detail: str
    # 届かない理由の種類。SourceError の kind か、応答の中身が原因なら server。正常なら空。
    kind: str = ""


Progress = Callable[[int], None]


class LlmClient:
    """1 つの接続先に対する呼び出し。秘密は鍵のファイルから読み、表示にも記録にも出さない。"""

    def __init__(self, endpoint: LlmEndpoint, cfg: Config, *, api_key: str) -> None:
        self.endpoint = endpoint
        self._cfg = cfg
        self._key = api_key

    @classmethod
    def from_endpoint(cls, endpoint: LlmEndpoint, cfg: Config) -> LlmClient:
        """鍵のファイルを読む。読めなければ SourceError（credential）。起動時の設定の誤りとして扱う。"""
        return cls(endpoint, cfg, api_key=read_secret(endpoint.api_key_file, "LLM の API キー", header_safe=True))

    def _http(self, stop: threading.Event | None = None, *, timeout_sec: float | None = None) -> Http:
        return Http(self._cfg, timeout_sec=self._cfg.llm_timeout_sec if timeout_sec is None else timeout_sec,
                    connect_timeout_sec=self._cfg.llm_connect_timeout_sec,
                    max_response_mb=self._cfg.llm_max_response_mb, interrupt=stop, user_agent="tia-analyzer")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}"}

    def request_body(self, messages: list[dict], *, response_format: dict, temperature: float | None = None,
                     max_tokens: int | None = None) -> dict:
        """送る本文。思考は要求ごとに止める。prompt cache は先頭一致で効く。"""
        return {
            "model": self.endpoint.model,
            "messages": messages,
            "temperature": self._cfg.llm_temperature if temperature is None else temperature,
            "max_tokens": self._cfg.llm_max_tokens if max_tokens is None else max_tokens,
            "stream": True,
            "cache_prompt": True,
            "response_format": response_format,
            "chat_template_kwargs": {"enable_thinking": self._cfg.llm_thinking},
        }

    def complete(self, messages: list[dict], *, response_format: dict, temperature: float | None = None,
                 max_tokens: int | None = None, stop: threading.Event | None = None,
                 on_progress: Progress | None = None) -> LlmResult:
        """1 回の要求。応答の断片を数えて進捗を知らせ、最後に全文を返す。"""
        body = self.request_body(messages, response_format=response_format, temperature=temperature,
                                 max_tokens=max_tokens)
        started = time.monotonic()
        pieces: list[str] = []
        finish_reason: str | None = None
        usage: dict = {}
        timings: dict = {}
        done = False
        try:
            with self._http(stop) as http:
                for line in http.stream_lines(self.endpoint.chat_url, body, headers=self._headers(),
                                              secrets=(self._key,), expect_content_type="text/event-stream"):
                    if len(line) > MAX_LINE:
                        raise LlmError("invalid_response", "応答の 1 行が長すぎる")
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        done = True
                        break
                    chunk = self._chunk(payload)
                    if "error" in chunk and not chunk.get("choices"):
                        raise LlmError("invalid_response", "相手が誤りを返した: " + self._error_text(chunk["error"]))
                    choices = chunk.get("choices") or []
                    if choices and isinstance(choices[0], dict):
                        delta = choices[0].get("delta") or {}
                        text = delta.get("content") if isinstance(delta, dict) else None
                        if isinstance(text, str) and text:
                            pieces.append(text)
                            if on_progress is not None:
                                on_progress(len(pieces))
                        reason = choices[0].get("finish_reason")
                        if isinstance(reason, str):
                            finish_reason = reason
                    if isinstance(chunk.get("usage"), dict):
                        usage = chunk["usage"]
                    if isinstance(chunk.get("timings"), dict):
                        timings = chunk["timings"]
        except SourceError as exc:
            raise LlmError(exc.kind, scrub(str(exc), (self._key,))) from None
        elapsed = time.monotonic() - started
        # finish_reason が届いていれば、[DONE] がなくても終わりとみなす。llama.cpp と Open WebUI は両方を送る
        if not done and finish_reason is None:
            raise LlmError("truncated", f"応答が終わる前に切れた（断片 {len(pieces)} 個、{elapsed:.0f} 秒）")
        # トークン数は timings（llama-server）、なければ usage、どちらもなければ呼ぶ側が見積もりと断片の数で代える
        prompt_tokens = _count(timings.get("prompt_n"))
        completion_tokens = _count(timings.get("predicted_n"))
        if prompt_tokens is None:
            prompt_tokens = _count(usage.get("prompt_tokens"))
        if completion_tokens is None:
            completion_tokens = _count(usage.get("completion_tokens"))
        return LlmResult(content="".join(pieces), chunks=len(pieces), elapsed_sec=elapsed, finish_reason=finish_reason,
                         prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, timings=timings)

    @staticmethod
    def _error_text(error: object) -> str:
        if isinstance(error, dict):
            message = error.get("message") or error.get("reason") or error.get("detail")
            text = message if isinstance(message, str) else json.dumps(error, ensure_ascii=False)
        else:
            text = str(error)
        return " ".join(text.split())[:EXCERPT]

    @staticmethod
    def _chunk(payload: str) -> dict:
        try:
            chunk = json.loads(payload)
        except ValueError:
            raise LlmError("invalid_response", "応答の断片が JSON でない") from None
        if not isinstance(chunk, dict):
            raise LlmError("invalid_response", "応答の断片が対応表でない")
        return chunk

    def health(self, *, timeout_sec: float = HEALTH_TIMEOUT_SEC) -> LlmHealth:
        """Open WebUI の /health と、鍵で見たモデルの一覧。推論の要求は送らない。

        制限時間は推論の 240 秒ではなく短い値。応答のない待受に当たっても、確認のスレッドを長く塞がない。
        """
        try:
            with self._http(timeout_sec=min(timeout_sec, float(self._cfg.llm_timeout_sec))) as http:
                status = http.get_json(self.endpoint.health_url)
                if not (isinstance(status, dict) and status.get("status") in (True, "ok")):
                    return LlmHealth(False, "Open WebUI の /health が正常を返さない", "server")
                models = http.get_json(self.endpoint.models_url, headers=self._headers(), secrets=(self._key,))
        except SourceError as exc:
            return LlmHealth(False, f"{exc.kind}: {scrub(str(exc), (self._key,))}", exc.kind)
        names = [m.get("id") for m in (models.get("data") or []) if isinstance(m, dict)] \
            if isinstance(models, dict) else []
        if self.endpoint.model not in names:
            return LlmHealth(False, f"モデル {self.endpoint.model} が一覧にない", "server")
        return LlmHealth(True, f"モデル {self.endpoint.model} に届く")


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
