"""テンプレートの関数。文は全部エスケープし、リンクにするのは http と https の URL だけ。"""
from __future__ import annotations

import re
from datetime import datetime
from zoneinfo import ZoneInfo

from markupsafe import Markup, escape

from tia.analysis.schema import CONFIDENCE_LABELS, KIND_LABELS, URGENCY_LABELS
from tia.knowledge.safety import RESERVED_TAGS
from tia.web.queries import ICONS, TYPE_LABELS, clock_text, duration_text, short_host

URL = re.compile(r"https?://[^\s<>\"'()\[\]{}]+")
TRAILING = ".,;:!?。、）)]"
TEXT_LIMIT = 4000


def linkify(text: object) -> Markup:
    """文の中の http と https の URL だけをリンクにする。ほかの文字は全部エスケープする。

    `javascript:` や `data:` はリンクにならない。Markdown と HTML のタグは文字のまま。
    """
    value = str(text or "")[:TEXT_LIMIT]
    pieces: list[str] = []
    last = 0
    for match in URL.finditer(value):
        url = match.group(0)
        end = match.end()
        while url and url[-1] in TRAILING:
            url = url[:-1]
            end -= 1
        pieces.append(str(escape(value[last:match.start()])))
        shown = escape(url)
        pieces.append(f'<a href="{shown}" rel="noopener noreferrer nofollow" target="_blank">{shown}</a>')
        last = end
    pieces.append(str(escape(value[last:])))
    return Markup("".join(pieces))


def plain(text: object) -> str:
    """区切りのタグが文に入っていても、文字として見せる（エスケープは自動で行われる）。"""
    return str(text or "")


def is_reserved_tag_text(text: object) -> bool:
    lowered = str(text or "").lower()
    return any(f"<{name}" in lowered or f"</{name}" in lowered for name in RESERVED_TAGS)


def register(env, tz: ZoneInfo) -> None:
    env.filters["linkify"] = linkify
    env.filters["plain"] = plain
    env.filters["clock"] = lambda value: clock_text(value, tz)
    env.filters["duration"] = duration_text
    env.filters["short_host"] = short_host
    env.filters["urgency_label"] = lambda value: URGENCY_LABELS.get(value or "", "")
    env.filters["kind_label"] = lambda value: KIND_LABELS.get(value or "", "")
    env.filters["confidence_label"] = lambda value: CONFIDENCE_LABELS.get(value or "", value or "")
    env.filters["type_label"] = lambda value: TYPE_LABELS.get(value or "", value or "")
    env.filters["icon"] = lambda value: ICONS.get(value or "", "pg-other")
    env.filters["thousands"] = lambda value: f"{int(value):,}" if isinstance(value, (int, float)) else "—"
    env.globals["now_text"] = lambda now: now.astimezone(tz).strftime("%H:%M") if isinstance(now, datetime) else ""
