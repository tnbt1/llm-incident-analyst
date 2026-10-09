"""LLM の出力の形。要求の `response_format` と検証で同じ物を使う。"""
from __future__ import annotations

KINDS = ("availability", "performance", "security", "configuration", "noise")
URGENCIES = ("now", "today", "watch", "ignore")
CONFIDENCES = ("high", "medium", "low")
MAX_CAUSES = 3
MAX_CHECKS = 5
SCHEMA_NAME = "analysis"

# 画面の表示に使う日本語。値そのものは英語の識別子にして、スキーマと設定で扱いやすくする。
KIND_LABELS = {"availability": "可用性", "performance": "性能", "security": "セキュリティ", "configuration": "構成",
               "noise": "ノイズ"}
URGENCY_LABELS = {"now": "今すぐ", "today": "今日中", "watch": "経過観察", "ignore": "無視可"}
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低"}


def _text(limit: int, minimum: int = 0) -> dict:
    schema: dict = {"type": "string", "maxLength": limit}
    if minimum:
        schema["minLength"] = minimum
    return schema


def _texts(limit: int, max_items: int) -> dict:
    return {"type": "array", "maxItems": max_items, "items": _text(limit)}


OUTPUT_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "classification", "probable_causes", "impact", "recommended_checks", "correlation",
                 "needs_human_decision", "unknowns"],
    "properties": {
        "summary": _text(400, 1),
        "classification": {
            "type": "object", "additionalProperties": False, "required": ["kind", "urgency"],
            "properties": {"kind": {"type": "string", "enum": list(KINDS)},
                           "urgency": {"type": "string", "enum": list(URGENCIES)}},
        },
        "probable_causes": {
            "type": "array", "maxItems": MAX_CAUSES,
            "items": {"type": "object", "additionalProperties": False, "required": ["cause", "confidence", "evidence"],
                      "properties": {"cause": _text(200, 1), "confidence": {"type": "string", "enum": list(CONFIDENCES)},
                                     "evidence": _text(220)}},
        },
        "impact": {
            "type": "object", "additionalProperties": False, "required": ["services", "scope"],
            "properties": {"services": _texts(120, 10), "scope": _text(200)},
        },
        "recommended_checks": {
            "type": "array", "maxItems": MAX_CHECKS,
            "items": {"type": "object", "additionalProperties": False, "required": ["purpose", "where", "command"],
                      "properties": {"purpose": _text(160, 1), "where": _text(120), "command": _text(300)}},
        },
        "correlation": {
            "type": "object", "additionalProperties": False, "required": ["incidents", "changes"],
            "properties": {"incidents": _texts(120, 10), "changes": _texts(200, 10)},
        },
        "needs_human_decision": {"type": "boolean"},
        "unknowns": _texts(160, 10),
    },
}


def response_format() -> dict:
    """要求に付ける `response_format`。llama.cpp はこれを文法にして出力を制約する。"""
    return {"type": "json_schema", "json_schema": {"name": SCHEMA_NAME, "strict": True, "schema": OUTPUT_SCHEMA}}
