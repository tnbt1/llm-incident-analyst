"""ナレッジのコマンド。束を作る、中身を見る、節の選び方を試す。"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import yaml

from tia.config import Config, load_config
from tia.knowledge.build import BuildError, build_bundle
from tia.knowledge.bundle import BundleError, freshness, full_document, load_bundle
from tia.knowledge.recipe import RecipeError, load_recipe
from tia.knowledge.safety import KIND_LABELS, SecretFound
from tia.knowledge.select import resolve_hosts, select_sections
from tia.models import IncidentType

EXIT_ERROR = 2
EXIT_SECRET = 3
LARGEST = 5


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"日付は 年-月-日 で書く: {value}") from None


def _config(path: Path | None) -> Config:
    try:
        return load_config(path)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"設定が読めない: {path}: {type(exc).__name__}") from None


def _today(args: argparse.Namespace) -> date:
    """生成日は、束を作る機械の日付。文書の日付と同じ時間帯で比べるため。"""
    return args.today or date.today()


def _build(args: argparse.Namespace) -> int:
    cfg = _config(args.config)
    recipe = load_recipe(args.recipe or Path(cfg.knowledge_recipe))
    result = build_bundle(args.source or Path(cfg.knowledge_source_dir), args.out or Path(cfg.knowledge_bundle_dir),
                          recipe, _today(args), card_budget=cfg.knowledge_card_budget_tokens)
    estimator = load_bundle(result.path).estimator
    print(f"版 {result.version}")
    print(f"節 {result.sections}、トークン {result.tokens:,}（見積もり {estimator}）")
    print(f"環境カード {result.card_tokens:,} / {cfg.knowledge_card_budget_tokens:,}")
    print(f"無害化 {result.neutralised} か所、注意 {len(result.notices)} 件")
    print(f"置き場所 {result.path}")
    history = result.history
    if recipe.recent_changes is not None:
        print(f"変更履歴: {history.rows} 行を読み、期間内 {history.inside}、期間外 {history.outside}、"
              f"日付を読めない行 {history.unreadable}")
    if result.card_children:
        print("環境カードに含めた下位の節: " + "、".join(f"{file}「{heading}」" for file, heading in result.card_children))
    if result.allowed:
        print(f"秘密の検査で許可した行 {result.allowed}")
    for entry in result.stale_allowed:
        print(f"注意: 許可の一覧の項目が、どの行にも当たらない: {entry.file}（理由: {entry.reason}）", file=sys.stderr)
    if result.neutralised_files:
        print("無害化の内訳: " + "、".join(f"{name} {count}" for name, count in result.neutralised_files))
    for notice in result.notices:
        print(f"注意: {notice.file}:{notice.line} 指示を上書きする言い回し「{notice.phrase}」", file=sys.stderr)
    return 0


def _show(args: argparse.Namespace) -> int:
    cfg = _config(args.config)
    bundle = load_bundle(args.bundle or Path(cfg.knowledge_bundle_dir))
    state = freshness(bundle, _today(args), stale_after_days=cfg.knowledge_stale_after_days, source_dir=args.source)
    in_card = sum(1 for section in bundle.sections if section.in_card)
    print(f"版 {bundle.version}（生成日 {bundle.built_on.isoformat()}、{state.age_days} 日前）")
    print(f"節 {len(bundle.sections)}（うち環境カード {in_card}）、トークン {bundle.tokens:,}（見積もり {bundle.estimator}）")
    print(f"選択方式で先頭に置く量 {bundle.card_tokens:,}、全文方式で先頭に置く量 {full_document(bundle)[1]:,}")
    print("大きい節:")
    for section in sorted(bundle.sections, key=lambda s: -s.tokens)[:LARGEST]:
        print(f"  {section.tokens:>6,}  {section.file}「{section.heading}」")
    if state.source_changed is None:
        print("出典: 確認していない")
    elif state.source_changed:
        print(f"出典: 生成の後に変更あり（{'、'.join(state.changed_files)}）。束を作り直す")
    else:
        print("出典: 生成の後の変更なし")
    if state.stale:
        print(f"注意: 生成から {state.age_days} 日。{cfg.knowledge_stale_after_days} 日を過ぎたので、束を作り直す")
    for notice in bundle.notices:
        print(f"注意: {notice.get('file')}:{notice.get('line')} 指示を上書きする言い回し")
    return 0


def _tag(value: str) -> str:
    """`名前=値` の形なら値だけを使う。Zabbix のタグと同じ扱い。"""
    return value.split("=", 1)[1] if "=" in value else value


def _select(args: argparse.Namespace) -> int:
    cfg = _config(args.config)
    bundle = load_bundle(args.bundle or Path(cfg.knowledge_bundle_dir))
    budget = cfg.knowledge_section_budget_tokens if args.budget is None else args.budget
    count = cfg.knowledge_max_sections if args.max_sections is None else args.max_sections
    selected = select_sections(bundle, hosts=args.host, incident_type=args.type, title=args.title,
                               tags=[_tag(tag) for tag in args.tag], budget=budget, max_sections=count)
    unknown = resolve_hosts(bundle, args.host)[1]
    if unknown:
        print("束にないホスト: " + "、".join(unknown))
    if not selected:
        print("該当なし")
        return 0
    print(f"{len(selected)} 節、合計 {sum(item.section.tokens for item in selected):,} / {budget:,}")
    for item in selected:
        section = item.section
        print(f"  {item.score:>4} {section.tokens:>6,}  {section.file}「{section.heading}」  {section.id}")
        print(f"              {'、'.join(item.reasons)}")
    return 0


def _run(func):
    def wrapped(args: argparse.Namespace) -> int:
        try:
            return func(args)
        except SecretFound as exc:
            show_digest = getattr(args, "line_hashes", False)
            for finding in exc.findings:
                digest = f" 行のハッシュ {finding.digest}" if show_digest else ""
                print(f"秘密の形をした文字列: {finding.file}:{finding.line} "
                      f"{KIND_LABELS.get(finding.kind, finding.kind)}（{finding.hint}）{digest}", file=sys.stderr)
            print("束は作らない。文書から取り除いてから、やり直す", file=sys.stderr)
            print("秘密ではないと確かめた行は、--line-hashes で行のハッシュを表示し、"
                  "レシピの allow_secrets に理由と共に書く。秘密鍵のブロックは許可できない", file=sys.stderr)
            return EXIT_SECRET
        except (BuildError, BundleError, RecipeError, ValueError) as exc:
            print(f"中止: {exc}", file=sys.stderr)
            return EXIT_ERROR
    return wrapped


def register(sub: argparse._SubParsersAction) -> None:
    """`tia knowledge ...` を、コマンドの入口に加える。"""
    knowledge = sub.add_parser("knowledge", help="知識の束を作る、確かめる")
    actions = knowledge.add_subparsers(dest="knowledge_command", required=True)

    build = actions.add_parser("build", help="文書から束を作る")
    build.add_argument("--source", type=Path, default=None, help="出典の場所。省くと設定の値")
    build.add_argument("--out", type=Path, default=None, help="束の置き場所。省くと設定の値")
    build.add_argument("--recipe", type=Path, default=None, help="束の作り方。省くと設定の値")
    build.add_argument("--line-hashes", action="store_true",
                       help="秘密の形をした行のハッシュを表示する。許可の一覧に書くときに使う")
    build.set_defaults(func=_run(_build))

    show = actions.add_parser("show", help="束の版、量、鮮度を表示する")
    show.add_argument("--bundle", type=Path, default=None, help="束の置き場所。省くと設定の値")
    show.add_argument("--source", type=Path, default=None, help="出典と比べる場合に指定する")
    show.set_defaults(func=_run(_show))

    select = actions.add_parser("select", help="インシデントに渡す節を選んでみる")
    select.add_argument("--bundle", type=Path, default=None, help="束の置き場所。省くと設定の値")
    select.add_argument("--host", action="append", default=[], help="ホスト名。繰り返せる")
    select.add_argument("--type", default="other", choices=[str(kind) for kind in IncidentType])
    select.add_argument("--title", default="")
    select.add_argument("--tag", action="append", default=[], help="タグ。値だけか、名前=値。繰り返せる")
    select.add_argument("--budget", type=int, default=None, help="トークンの予算。省くと設定の値")
    select.add_argument("--max-sections", type=int, default=None, help="節の数の上限。省くと設定の値")
    select.set_defaults(func=_run(_select))

    for command in (build, show, select):
        command.add_argument("--config", type=Path, default=None)
    for command in (build, show):
        command.add_argument("--today", type=_date, default=None, help="日付を固定する。年-月-日")
