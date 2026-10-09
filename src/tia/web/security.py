"""画面の守り。応答のヘッダー、同じ画面から出た操作かの確認、セッションの印。

認証は Caddy の basic 認証が行う。ここで防ぐのは、別のサイトから操作を飛ばされること（CSRF）と、
文字列を HTML や script として解釈されることである。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from starlette.responses import Response

SESSION_COOKIE = "tia_sid"
TOKEN_FIELD = "_token"
TOKEN_HEADER = "x-tia-token"
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# 外部のサーバーへは一切つながない。script と style は自前のファイルだけ。
# style 属性（位置と進捗の値）は許す。script の属性と要素の中身は許さない。
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; "
       "img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def new_session_id() -> str:
    return secrets.token_hex(16)


def token_for(secret: bytes, session_id: str) -> str:
    """セッションの印から操作の印を作る。鍵は起動のたびに変わるので、再起動の後は画面を読み直す。"""
    return hmac.new(secret, session_id.encode(), hashlib.sha256).hexdigest()[:32]


def session_of(request: Request) -> str:
    """要求のセッションの印。Cookie になければ新しく作り、応答で渡す。"""
    existing = getattr(request.state, "session_id", None)
    if existing:
        return existing
    value = request.cookies.get(SESSION_COOKIE, "")
    fresh = not (len(value) == 32 and all(c in "0123456789abcdef" for c in value))
    if fresh:
        value = new_session_id()
    request.state.session_id = value
    request.state.session_is_new = fresh
    return value


def apply_headers(request: Request, response: Response, *, cookie_secure: bool) -> None:
    for name, value in HEADERS.items():
        response.headers.setdefault(name, value)
    content_type = response.headers.get("content-type", "")
    if content_type.startswith(("text/html", "application/json", "text/event-stream")):
        # 画面と部品と監視の応答は、保存させない。静的なファイルは除く
        response.headers.setdefault("Cache-Control", "no-store")
    if getattr(request.state, "session_is_new", False):
        response.set_cookie(SESSION_COOKIE, request.state.session_id, httponly=True, samesite="strict",
                            secure=cookie_secure, path="/")


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except ValueError:
        return ""


def check_same_origin(request: Request) -> None:
    """別のサイトから飛んできた操作を断る。ブラウザが付けるヘッダーだけを見る。X-Forwarded-* は信じない。"""
    site = request.headers.get("sec-fetch-site")
    if site is not None and site not in ("same-origin", "none"):
        raise HTTPException(403, "別のサイトからの操作は受け付けない")
    origin = request.headers.get("origin")
    if origin is not None and origin != "null":
        if _host_of(origin) != request.headers.get("host", "").lower():
            raise HTTPException(403, "別のサイトからの操作は受け付けない")
    elif origin == "null":
        raise HTTPException(403, "別のサイトからの操作は受け付けない")


def check_token(request: Request, secret: bytes, token: str | None) -> None:
    """フォームの印が、この要求のセッションのものか。"""
    session_id = request.cookies.get(SESSION_COOKIE, "")
    presented = token or request.headers.get(TOKEN_HEADER) or ""
    if not session_id or not presented or not hmac.compare_digest(token_for(secret, session_id), presented):
        raise HTTPException(403, "画面を読み直してください。画面の印が合わない（再起動の後など）")
