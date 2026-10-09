"""出力の検証。JSON スキーマの確認、スキーマでは書けない確認、推奨コマンドの照合。"""
from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass

from tia.analysis.commands import commands_in, destructive_reason, matches_template, normalise_command
from tia.analysis.schema import OUTPUT_SCHEMA
from tia.knowledge.safety import neutralise, reserved_tag_pattern

MAX_PROBLEMS = 20
# 閉じた形の区切りのタグ。入力の無害化（knowledge.safety）と同じ定義。
RESERVED_TAG_PATTERN = reserved_tag_pattern()
# 端末や画面、次の要求に害のある文字。C0 と C1 の制御文字（タブと改行を除く）、双方向の上書き、チャットの印。
# 見え方だけを変える文字（軟らかいハイフン、異体字セレクタなど）は害がないので、黙って取り除く。
DANGEROUS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]|<[|｜]")


@dataclass(frozen=True)
class Problem:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass(frozen=True)
class Validation:
    problems: tuple[Problem, ...]
    output: dict | None
    # 規則により推奨から除外した確認の数。除外は失敗ではない。読み取りの確認が混ざっていても解析そのものは通す
    excluded: int = 0

    @property
    def ok(self) -> bool:
        return not self.problems

    def summary(self, limit: int = 3) -> str:
        """作り直しの要求と、失敗の理由に使う短い文。"""
        shown = "; ".join(str(problem) for problem in self.problems[:limit])
        rest = len(self.problems) - limit
        return shown + (f"; ほか {rest} 件" if rest > 0 else "")


def check_schema(value: object, schema: dict, path: str = "$") -> list[Problem]:
    """この計画のスキーマが使う範囲だけを確かめる小さな検証。依存を増やさないため。"""
    problems: list[Problem] = []
    kind = schema.get("type")
    if "enum" in schema:
        if value not in schema["enum"]:
            problems.append(Problem(path, f"{', '.join(map(str, schema['enum']))} のどれかで書く"))
        return problems
    if kind == "object":
        if not isinstance(value, dict):
            return [Problem(path, "対応表で書く")]
        for name in schema.get("required", ()):
            if name not in value:
                problems.append(Problem(f"{path}.{name}", "必要な項目がない"))
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    problems.append(Problem(f"{path}.{name}", "知らない項目"))
        for name, sub in properties.items():
            if name in value:
                problems.extend(check_schema(value[name], sub, f"{path}.{name}"))
    elif kind == "array":
        if not isinstance(value, list):
            return [Problem(path, "配列で書く")]
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            problems.append(Problem(path, f"{schema['maxItems']} 件まで"))
        for number, item in enumerate(value):
            problems.extend(check_schema(item, schema.get("items", {}), f"{path}[{number}]"))
    elif kind == "string":
        if not isinstance(value, str):
            return [Problem(path, "文字列で書く")]
        if len(value) > schema.get("maxLength", len(value)):
            problems.append(Problem(path, f"{schema['maxLength']} 文字まで"))
        if len(value.strip()) < schema.get("minLength", 0):
            problems.append(Problem(path, "空にしない"))
    elif kind == "boolean":
        if not isinstance(value, bool):
            return [Problem(path, "true か false で書く")]
    return problems[:MAX_PROBLEMS]


def _neutralised(value: object) -> object:
    """文字列を無害にした写し。見え方だけを変える文字を取り除く。"""
    if isinstance(value, str):
        return neutralise(value)[0]
    if isinstance(value, dict):
        return {name: _neutralised(item) for name, item in value.items()}
    if isinstance(value, list):
        return [_neutralised(item) for item in value]
    return value


def _strings(value: object, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for name, item in value.items():
            yield from _strings(item, f"{path}.{name}")
    elif isinstance(value, list):
        for number, item in enumerate(value):
            yield from _strings(item, f"{path}[{number}]")


def validate_output(data: object, templates: Collection[str] = ()) -> Validation:
    """スキーマと規則で検証し、通れば推奨コマンドに照合の結果を付けた出力を返す。

    照合は、文書のコマンドひな形と形をそろえて比べる。一致したものだけ `verified` が真になる。
    LLM の申告は使わない。
    """
    problems = check_schema(data, OUTPUT_SCHEMA)
    if problems or not isinstance(data, dict):
        return Validation(tuple(problems), None)
    for path, text in _strings(data, "$"):
        if RESERVED_TAG_PATTERN.search(text):
            problems.append(Problem(path, "区切りのタグを含めない"))
        if DANGEROUS.search(text):
            problems.append(Problem(path, "制御文字や特殊な印を含めない"))
    if problems:
        return Validation(tuple(problems[:MAX_PROBLEMS]), None)
    data = _neutralised(data)
    checks: list[dict] = []
    excluded: list[dict] = []
    for check in data["recommended_checks"]:
        command = check["command"]
        reason = destructive_reason(command)
        if reason:
            # 変更や破壊を伴う確認は、解析を失敗にせず、その 1 件だけを推奨から外して記録に残す。
            # 同じ入力で作り直しても同じ提案が返るだけで、GPU と待ち行列の時間を失うため
            excluded.append({"purpose": check.get("purpose", ""), "where": check.get("where", ""),
                             "command": command, "reason": reason})
            continue
        checks.append({**check, "verified": matches_template(command, templates)})
    return Validation((), {**data, "recommended_checks": checks, "excluded_checks": excluded}, len(excluded))
