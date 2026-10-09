"""`tia config show` と `tia config env-template`。設定の値と由来の表示、`.env.example` の生成。"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import Field, fields
from pathlib import Path

from tia.config import (CLOCK_TIME, ENV_FILE_VAR, EXTERNAL_VARIABLES, INT_RANGES, KNOWLEDGE_MODES,
                        LLM_TEMPERATURE_RANGE, RETRY_DELAY_RANGE, Config, env_name, format_value, inspect_config)

SECRET_WORDS = ("key", "token", "password", "secret")
PATH_SUFFIXES = ("_file", "_dir", "_path")
MASK = "********"
DEFAULT_YAML = Path("config/analyzer.yaml")
# YAML の `  キー: 値   # 意味` の行
YAML_KEY = re.compile(r"^\s+([A-Za-z_]+):[^#]*?(?:#\s*(.*))?$")
YAML_SECTION = re.compile(r"^([A-Za-z_]+):\s*(?:#.*)?$")


def mask_value(name: str, value: str) -> str:
    """名前が秘密を表す値は伏せる。ファイルの場所は見せる。"""
    lower = name.lower()
    if value and any(word in lower for word in SECRET_WORDS) and not lower.endswith(PATH_SUFFIXES):
        return MASK
    return value


def _section(name: str) -> str:
    return name.split("_", 1)[0]


def _meanings(path: Path | None) -> dict[str, str]:
    """YAML の行末のコメントを、項目ごとの意味として拾う。"""
    meanings: dict[str, str] = {}
    if path is None or not path.is_file():
        return meanings
    section = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        head = YAML_SECTION.match(line)
        if head:
            section = head.group(1)
            continue
        item = YAML_KEY.match(line)
        if item and section and item.group(2):
            meanings[f"{section}_{item.group(1)}"] = item.group(2).strip()
    return meanings


def _kind(field: Field) -> str:
    kind = str(field.type)
    if field.name in INT_RANGES:
        low, high = INT_RANGES[field.name]
        if kind == "int | None":
            return f"整数 {low}〜{high}、空なら 1 と zabbix.min_severity の小さい方"
        return f"整数 {low}〜{high}"
    if kind == "int":
        return "整数"
    if kind == "float":
        low, high = LLM_TEMPERATURE_RANGE
        return f"数 {low}〜{high}"
    if kind == "bool":
        return "真偽 true/false"
    if kind == "tuple[int, ...]":
        low, high = RETRY_DELAY_RANGE
        return f"整数の並び、コンマ区切り、各 {low}〜{high}"
    if kind == "frozenset[str]":
        return "文字列の並び、コンマ区切り"
    if field.name == "knowledge_mode":
        return " か ".join(KNOWLEDGE_MODES)
    if field.name.endswith("_at") and CLOCK_TIME.fullmatch(str(field.default)):
        return "HH:MM"
    return "文字列"


HEADER = """\
# 設定の上書き（.env の雛形）。`tia config env-template` が作る。
#
# すべての設定は環境変数で上書きできる。項目 `節.キー` の変数名は `TIA_節_キー` の大文字。
# 優先は 環境変数 > .env > analyzer.yaml > 既定。
# .env の場所は、{env_file} があればその場所、なければ analyzer.yaml と同じフォルダの .env。
# Compose では compose.yaml の env_file がこのファイルをコンテナに渡す。TIA_IMAGE_TAG は Compose 自身が読む。
# 変えたい行の先頭の # を外す。値の引用符は要らない。並びはコンマ区切り。
# 現在の値と由来は `tia config show --config <analyzer.yaml>` で見る。
"""


def render_template(yaml_path: Path | None) -> str:
    """すべての項目を、意味、型と範囲、既定とともにコメントにした `.env.example`。"""
    meanings = _meanings(yaml_path)
    lines = [HEADER.format(env_file=ENV_FILE_VAR).rstrip("\n")]
    sections: dict[str, list[Field]] = {}
    for field in fields(Config):
        sections.setdefault(_section(field.name), []).append(field)
    for section, members in sections.items():
        lines.append(f"\n## {section}")
        for field in members:
            label = field.name.replace("_", ".", 1)
            meaning = meanings.get(field.name, label)
            default = format_value(field.default) or "空"
            lines.append(f"# {label}: {meaning}（{_kind(field)}、既定 {default}）")
            lines.append(f"#{env_name(field.name)}={format_value(field.default)}")
    lines.append("\n## 接続先、秘密のファイルの場所、Compose")
    for name, meaning in EXTERNAL_VARIABLES:
        if name == ENV_FILE_VAR:
            continue
        lines.append(f"# {meaning}")
        lines.append(f"#{name}=")
    return "\n".join(lines) + "\n"


def _show(args: argparse.Namespace) -> int:
    """終了コードは、成功が 0、設定の誤りが 2。"""
    before = dict(os.environ)
    try:
        loaded = inspect_config(args.config)
    except (ValueError, OSError) as exc:
        print(f"設定の誤り: {exc}", file=sys.stderr)
        return 2
    print(f"# yaml={args.config or 'なし'}  .env={loaded.env_file or 'なし'}  env=環境変数  default=既定")
    for field in fields(Config):
        name = env_name(field.name)
        value = mask_value(name, format_value(getattr(loaded.config, field.name)))
        print(f"{name}={value}  # {field.name.replace('_', '.', 1)}  {loaded.sources[field.name]}")
    for name, _meaning in EXTERNAL_VARIABLES:
        if name == ENV_FILE_VAR:
            continue
        source = "env" if name in before else ".env" if name in os.environ else "unset"
        print(f"{name}={mask_value(name, os.environ.get(name, ''))}  # {source}")
    return 0


def _template(args: argparse.Namespace) -> int:
    path = args.config if args.config is not None else DEFAULT_YAML if DEFAULT_YAML.is_file() else None
    sys.stdout.write(render_template(path))
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    config = sub.add_parser("config", help="設定の値と由来を見る。.env.example を作る")
    commands = config.add_subparsers(dest="config_command", required=True)
    show = commands.add_parser("show", help="すべての設定を、値と由来（default、yaml、.env、env）とともに出す")
    show.add_argument("--config", type=Path, default=None)
    show.set_defaults(func=_show)
    template = commands.add_parser("env-template", help="すべての設定をコメントにした .env.example を出す")
    template.add_argument("--config", type=Path, default=None,
                          help="意味を拾う analyzer.yaml。省略すると config/analyzer.yaml があればそれ")
    template.set_defaults(func=_template)
