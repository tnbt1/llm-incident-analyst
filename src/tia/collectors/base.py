"""収集に共通の型と、秘密の扱い。"""
from __future__ import annotations

import base64
import json
import logging
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from tia.models import Source
from tia.normalize import clean_text

ERROR_LIMIT = 200
SECRET_LIMIT = 4096
# これより短い値は、伏せ字にすると記録が読めなくなるので伏せない。短い秘密は read_secret が受け付けない。
SECRET_MIN = 8
REJECTED_MEMORY = 1000
MASK = "***"
# 秘密を探す文の長さの上限。残すのは先頭の ERROR_LIMIT 文字だけなので、これより先は見ない。
SCRUB_LIMIT = 8000
# 文の末尾に、秘密の先頭がこの文字数以上あれば、途中で切れた秘密とみなして消す。
CUT_SECRET_MIN = 4
# 待ちを長く取る失敗。認証の誤りは繰り返しても直らず、相手の記録を埋めるだけになる。
CREDENTIAL_KINDS = frozenset({"auth", "credential"})


class SourceError(Exception):
    """1 つの系統の収集の失敗。

    kind は待ち方を決め、画面にも出る。値は timeout、unreachable、tls、auth、credential、throttled、
    server、client、too_large、invalid_response、rpc、partial、internal。
    """

    def __init__(self, kind: str, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.retry_after = retry_after


@dataclass(frozen=True)
class PollReport:
    """1 回の収集の結果。counts の名前は fetched、created、recurred、skipped、duplicate、known、
    rejected、resolved、reopened、hidden、missing。complete は、上限や停止の要求で打ち切らずに読み切ったか。"""

    source: Source
    counts: Mapping[str, int] = field(default_factory=dict)
    complete: bool = True
    watermark: str | None = None


def _shapes(secret: str) -> set[str]:
    """相手が秘密を返してくるときの形。そのまま、JSON の文字列、URL、フォーム、base64。

    JSON の文字列は、JSON の本文の中でもう一度包まれることがあるので、2 重に包んだ形も含める。
    """
    raw = secret.encode("utf-8", "replace")
    quoted = {json.dumps(secret, ensure_ascii=ascii_only)[1:-1] for ascii_only in (True, False)}
    twice = {json.dumps(once, ensure_ascii=ascii_only)[1:-1] for once in quoted for ascii_only in (True, False)}
    return {secret, *quoted, *twice,
            urllib.parse.quote(secret), urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret),
            base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()}


def _hide(text: str, shapes: list[str]) -> str:
    """秘密の先頭 SECRET_MIN 文字から始まる並びを、秘密と一致する限り消す。

    先頭だけを返してくる相手と、途中で切れた本文に備える。形が複数合うときは、最も長く合うものを消す。
    """
    kept: list[str] = []
    at = 0
    while at < len(text):
        longest = 0
        for shape in shapes:
            if not text.startswith(shape[:SECRET_MIN], at):
                continue
            size = SECRET_MIN
            while size < len(shape) and at + size < len(text) and text[at + size] == shape[size]:
                size += 1
            longest = max(longest, size)
        kept.append(MASK if longest else text[at])
        at += longest or 1
    hidden = "".join(kept)
    for shape in shapes:
        for size in range(min(SECRET_MIN - 1, len(hidden)), CUT_SECRET_MIN - 1, -1):
            if hidden.endswith(shape[:size]):
                return hidden[:-size] + MASK
    return hidden


def hide_secrets(text: str, secrets: tuple[str, ...]) -> str:
    """文の長さを変えずに秘密だけを消す。確認の出力のように、長い文をそのまま残すときに使う。"""
    shapes = sorted({shape for secret in secrets if len(secret) >= SECRET_MIN for shape in _shapes(secret)})
    return _hide(text, shapes) if shapes else text


def scrub(text: object, secrets: tuple[str, ...] = ()) -> str:
    """記録に残す文から秘密を消し、制御文字を除いて長さを切る。残すのは短い抜粋だけ。"""
    cleaned = str(text)[:SCRUB_LIMIT]
    shapes = sorted({shape for secret in secrets if len(secret) >= SECRET_MIN for shape in _shapes(secret)})
    if shapes:
        cleaned = _hide(cleaned, shapes)
    return clean_text(cleaned, ERROR_LIMIT)


def note_rejected(seen: set[str], log: logging.Logger, label: str, key: str, reason: object) -> None:
    """読み飛ばしを記録する。同じ番号については 1 回だけ。同じものが収集のたびに届くことがあるため。"""
    if key in seen:
        return
    if len(seen) >= REJECTED_MEMORY:
        seen.clear()
    seen.add(key)
    log.warning("%sを読み飛ばした: %s", label, scrub(reason))


def read_secret(path: Path, name: str, *, header_safe: bool = False) -> str:
    """秘密を 1 行のファイルから読む。失敗の表示に中身は出さない。

    header_safe は、値を HTTP のヘッダーにそのまま載せる場合。空白と ASCII 以外を受け付けない。
    """
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(SECRET_LIMIT + 1)
    except OSError as exc:
        raise SourceError("credential", f"{name} のファイルを読めない（{type(exc).__name__}）: {path}") from None
    if len(raw) > SECRET_LIMIT:
        raise SourceError("credential", f"{name} のファイルが {SECRET_LIMIT} バイトを超える: {path}")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise SourceError("credential", f"{name} のファイルが UTF-8 でない: {path}") from None
    if len(value) < SECRET_MIN:
        raise SourceError("credential", f"{name} が空か、{SECRET_MIN} 文字より短い: {path}")
    if not value.isprintable() or (header_safe and (not value.isascii() or " " in value)):
        raise SourceError("credential", f"{name} に使えない文字がある: {path}")
    return value
