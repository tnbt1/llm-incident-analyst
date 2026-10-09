"""収集に共通の HTTP の呼び出し。失敗を種類に分け、応答の大きさと時間に上限を置く。"""
from __future__ import annotations

import json
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpcore
import httpx

from tia.collectors.base import SourceError, scrub
from tia.config import Config

BODY_SNIPPET = 2000
# 1 回の読み取りの待ちをこの長さに刻む。止める合図と期限を、待ちの途中でも確かめるため。
READ_SLICE = 1.0
# これより桁の多い整数は読まない。Python は 4,300 桁を超える整数を読めず、応答の全体が読めなくなる。
MAX_DIGITS = 30


def _bounded_int(text: str) -> int | None:
    """桁の多すぎる整数を None にする。1 つの値のために、応答の全体を捨てないため。"""
    return int(text) if len(text) <= MAX_DIGITS else None


def tls_context(ca_file: Path | None) -> ssl.SSLContext:
    """相手の証明書を検証する設定。CA のファイルがなければ、OS が信頼する CA で検証する。検証は切れない。"""
    try:
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        if ca_file:
            # Wazuh の自前の認証局には keyUsage 拡張がなく、Python 3.13 の厳格な検証（VERIFY_X509_STRICT）が拒む。
            # 運用者が CA を明示したときは厳格な検査だけを外す。CA の照合とホスト名の検査は残る
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        return context
    except (OSError, ssl.SSLError) as exc:
        raise SourceError("tls", f"CA のファイルを読めない（{type(exc).__name__}）: {ca_file}") from None


def _caused_by_tls(exc: BaseException) -> bool:
    seen = 0
    while exc is not None and seen < 10:
        if isinstance(exc, ssl.SSLError):
            return True
        exc, seen = exc.__cause__ or exc.__context__, seen + 1
    return False


def _retry_after(response: httpx.Response) -> int | None:
    value = response.headers.get("retry-after", "").strip()
    return int(value) if value.isdigit() and len(value) <= 6 else None


class _Deadline:
    """1 回の要求の期限。接続、TLS、ヘッダー、本文のどの段階でも、同じ期限まで待つ。

    interrupt が立つと、次の読み書きの前に打ち切る。
    """

    def __init__(self, interrupt: threading.Event | None = None) -> None:
        self._at: float | None = None
        self._interrupt = interrupt

    @property
    def interrupted(self) -> bool:
        return self._interrupt is not None and self._interrupt.is_set()

    def start(self, seconds: float) -> None:
        self._at = time.monotonic() + seconds

    def stop(self) -> None:
        self._at = None

    def limit(self, timeout: float | None, error: type[Exception]) -> float | None:
        """この 1 回の待ちに使える時間。期限を過ぎていたら、待たずに時間切れにする。"""
        if self.interrupted:
            raise error("止める合図を受けた")
        if self._at is None:
            return timeout
        left = self._at - time.monotonic()
        if left <= 0:
            raise error("要求の期限を過ぎた")
        return left if timeout is None else min(timeout, left)


class _BoundedStream(httpcore.NetworkStream):
    def __init__(self, inner: httpcore.NetworkStream, deadline: _Deadline) -> None:
        self._inner = inner
        self._deadline = deadline

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        """期限まで読む。待ちは READ_SLICE ごとに刻み、合間に止める合図と期限を確かめる。

        相手が黙っている間の受信の待ち時間切れは、接続を壊さない。刻んだ 1 回が切れても、
        期限と合図を確かめてから読み直せる。
        """
        while True:
            limit = self._deadline.limit(timeout, httpcore.ReadTimeout)
            piece = READ_SLICE if limit is None else min(limit, READ_SLICE)
            try:
                return self._inner.read(max_bytes, piece)
            except httpcore.ReadTimeout:
                if limit is not None and limit <= READ_SLICE:
                    raise

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, self._deadline.limit(timeout, httpcore.WriteTimeout))

    def close(self) -> None:
        self._inner.close()

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                  timeout: float | None = None) -> httpcore.NetworkStream:
        limit = self._deadline.limit(timeout, httpcore.ConnectTimeout)
        return _BoundedStream(self._inner.start_tls(ssl_context, server_hostname, limit), self._deadline)

    def get_extra_info(self, info: str) -> object:
        return self._inner.get_extra_info(info)


class _BoundedBackend(httpcore.NetworkBackend):
    """通信の 1 回ごとの待ちを、要求の期限までに切り詰める。

    通信の部品の制限時間は、1 回の読み書きごとに数える。少しずつ送る相手には、それだけでは効かない。
    """

    def __init__(self, deadline: _Deadline) -> None:
        self._inner = httpcore.SyncBackend()
        self._deadline = deadline

    def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,
                    socket_options: object = None) -> httpcore.NetworkStream:
        limit = self._deadline.limit(timeout, httpcore.ConnectTimeout)
        stream = self._inner.connect_tcp(host, port, timeout=limit, local_address=local_address,
                                         socket_options=socket_options)
        return _BoundedStream(stream, self._deadline)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def _transport(verify: ssl.SSLContext | bool, deadline: _Deadline) -> httpx.HTTPTransport:
    context = verify if isinstance(verify, ssl.SSLContext) else httpx.create_ssl_context(verify=verify,
                                                                                         trust_env=False)
    transport = httpx.HTTPTransport(verify=context, trust_env=False)
    if not hasattr(transport, "_pool"):
        raise RuntimeError("通信の部品の作りが変わり、要求の期限を置けない")
    # 期限を見る部品に差し替える。通信の部品は、外から渡す口を持たない。
    transport._pool = httpcore.ConnectionPool(ssl_context=context, max_connections=4,
                                              max_keepalive_connections=2, keepalive_expiry=5.0,
                                              network_backend=_BoundedBackend(deadline))
    return transport


class Http:
    """1 回の収集、または 1 回の解析の間だけ使う接続。環境変数の代理の設定は読まない。転送には従わない。

    期限と大きさの上限は、既定では収集の設定を使う。LLM の呼び出しは、引数で長い期限を渡す。
    interrupt を渡すと、止める合図で読みかけの要求を打ち切れる。
    """

    def __init__(self, cfg: Config, verify: ssl.SSLContext | bool = True, *, timeout_sec: int | None = None,
                 connect_timeout_sec: int | None = None, max_response_mb: int | None = None,
                 interrupt: threading.Event | None = None, user_agent: str = "tia-collector") -> None:
        self._seconds = cfg.collector_timeout_sec if timeout_sec is None else timeout_sec
        self._megabytes = cfg.collector_max_response_mb if max_response_mb is None else max_response_mb
        connect = cfg.collector_connect_timeout_sec if connect_timeout_sec is None else connect_timeout_sec
        self._deadline = _Deadline(interrupt)
        self._client = httpx.Client(
            timeout=httpx.Timeout(self._seconds, connect=connect),
            transport=_transport(verify, self._deadline), follow_redirects=False, trust_env=False,
            headers={"User-Agent": user_agent})

    def __enter__(self) -> Http:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def post_json(self, url: str, body: object, *, content_type: str = "application/json",
                  headers: dict[str, str] | None = None, auth: tuple[str, str] | None = None,
                  secrets: tuple[str, ...] = ()) -> object:
        """JSON を送り、JSON を受け取る。失敗は SourceError にする。表示に秘密は出さない。"""
        payload = json.dumps(body, ensure_ascii=False).encode()
        return self._json("POST", url, payload, {"Content-Type": content_type, **(headers or {})}, auth, secrets)

    def get_json(self, url: str, *, headers: dict[str, str] | None = None,
                 secrets: tuple[str, ...] = ()) -> object:
        """JSON を受け取る。post_json と同じ上限と失敗の種類。"""
        return self._json("GET", url, None, dict(headers or {}), None, secrets)

    def _json(self, method: str, url: str, payload: bytes | None, headers: dict[str, str],
              auth: tuple[str, str] | None, secrets: tuple[str, ...]) -> object:
        deadline = time.monotonic() + self._seconds
        self._deadline.start(self._seconds)
        chunks: list[bytes] = []
        try:
            with self._client.stream(method, url, content=payload, auth=auth, headers=headers) as response:
                if response.status_code != 200:
                    raise self._refused(response, self._reason(response), secrets)
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > self._megabytes * 1024 * 1024:
                        raise SourceError("too_large", f"応答が上限の {self._megabytes} MiB を超えた")
                    if time.monotonic() > deadline:
                        raise SourceError("timeout", f"{self._seconds} 秒以内に応答が終わらない")
                    chunks.append(chunk)
        except SourceError:
            raise
        except httpx.HTTPError as exc:
            raise self._translate(exc) from None
        finally:
            self._deadline.stop()
        try:
            return json.loads(b"".join(chunks), parse_int=_bounded_int)
        except (ValueError, RecursionError):
            raise SourceError("invalid_response", "応答が JSON でない") from None

    def stream_lines(self, url: str, body: object, *, headers: dict[str, str] | None = None,
                     secrets: tuple[str, ...] = (), expect_content_type: str | None = None) -> Iterator[str]:
        """JSON を送り、応答を行ごとに返す。Server-Sent Events の受信に使う。

        1 つの期限が全体にかかる。大きさの上限を超えたら打ち切る。失敗は SourceError にする。
        expect_content_type を渡すと、応答の形が違うときは invalid_response にして、状態、形、本文の抜粋を文に出す。
        """
        payload = json.dumps(body, ensure_ascii=False).encode()
        self._deadline.start(self._seconds)
        try:
            with self._client.stream("POST", url, content=payload,
                                     headers={"Content-Type": "application/json", **(headers or {})}) as response:
                if response.status_code != 200:
                    raise self._refused(response, self._reason(response), secrets)
                content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
                if expect_content_type is not None and content_type != expect_content_type:
                    excerpt = scrub(Http._excerpt(self._reason(response, always=True)), secrets)
                    excerpt = " ".join(excerpt.split())[:BODY_SNIPPET // 4]
                    raise SourceError("invalid_response", f"応答の形が違う（HTTP {response.status_code}、"
                                                          f"{content_type or '形の表示なし'}）: {excerpt}")
                yield from self._lines_within_limit(response)
        except SourceError:
            raise
        except httpx.HTTPError as exc:
            raise self._translate(exc) from None
        finally:
            self._deadline.stop()

    def _translate(self, exc: httpx.HTTPError) -> SourceError:
        """通信の部品の失敗を、種類の付いた失敗にする。表示に秘密は出さない。"""
        if isinstance(exc, httpx.TimeoutException):
            if self._deadline.interrupted:
                return SourceError("stopped", "止める合図を受けて要求を打ち切った")
            return SourceError("timeout", f"{self._seconds} 秒以内に応答がない")
        if isinstance(exc, httpx.LocalProtocolError):
            return SourceError("client", f"要求を送れない（{type(exc).__name__}）")
        if isinstance(exc, httpx.TransportError):
            if _caused_by_tls(exc):
                return SourceError("tls", "相手の証明書を検証できない")
            if isinstance(exc, httpx.ConnectError):
                return SourceError("unreachable", "接続できない")
            if self._deadline.interrupted:
                return SourceError("stopped", "止める合図を受けて要求を打ち切った")
            return SourceError("unreachable", f"通信が途中で切れた（{type(exc).__name__}）")
        return SourceError("client", f"要求を送れない（{type(exc).__name__}）")

    def _lines_within_limit(self, response: httpx.Response) -> Iterator[str]:
        """本文を行に分けて返す。大きさは生のバイト数で数えるので、改行のない本文にも上限が効く。"""
        limit = self._megabytes * 1024 * 1024
        size = 0
        rest = b""
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > limit:
                raise SourceError("too_large", f"応答が上限の {self._megabytes} MiB を超えた")
            rest += chunk
            while True:
                position = rest.find(b"\n")
                if position == -1:
                    break
                line, rest = rest[:position], rest[position + 1:]
                yield line.rstrip(b"\r").decode("utf-8", "replace")
        if rest:
            yield rest.rstrip(b"\r").decode("utf-8", "replace")

    @staticmethod
    def _reason(response: httpx.Response, *, always: bool = False) -> bytes:
        """断られた理由の先頭。失敗の種類は状態コードで決まるので、読めた分だけを使い、待たない。

        理由を表示に使わない状態コードでは、本文を読まない。always が真なら読む。
        """
        if not always and (response.status_code in (401, 403, 429) or response.status_code >= 500):
            return b""
        chunks: list[bytes] = []
        size = 0
        try:
            for chunk in response.iter_bytes():
                chunks.append(chunk[:BODY_SNIPPET - size])
                size += len(chunks[-1])
                if size >= BODY_SNIPPET:
                    break
        except httpx.HTTPError:
            pass
        return b"".join(chunks)

    @staticmethod
    def _excerpt(body: bytes) -> str:
        """断られた理由の抜粋。JSON で理由が書いてあれば、その文だけを使う。"""
        text = body.decode("utf-8", "replace")
        try:
            data = json.loads(text, parse_int=_bounded_int)
        except (ValueError, RecursionError):
            return text
        error = data.get("error") if isinstance(data, dict) else None
        if isinstance(error, str):
            return error
        if isinstance(error, dict) and isinstance(error.get("reason"), str):
            kind = error.get("type")
            return f"{kind}: {error['reason']}" if isinstance(kind, str) else error["reason"]
        return text

    @staticmethod
    def _refused(response: httpx.Response, body: bytes, secrets: tuple[str, ...]) -> SourceError:
        status = response.status_code
        detail = scrub(Http._excerpt(body), secrets)
        if status in (401, 403):
            return SourceError("auth", f"認証に失敗した（HTTP {status}）")
        if status == 429:
            return SourceError("throttled", "要求が多すぎると断られた（HTTP 429）", _retry_after(response))
        if status >= 500:
            return SourceError("server", f"相手の側の誤り（HTTP {status}）", _retry_after(response))
        return SourceError("client", f"予期しない応答（HTTP {status}）: {detail}" if detail
                           else f"予期しない応答（HTTP {status}）")
