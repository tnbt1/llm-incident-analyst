import hashlib
from datetime import date
from pathlib import Path

import pytest
from knowledge_helpers import build_fixture

from tia.knowledge.bundle import Bundle, Section, load_bundle
from tia.knowledge.index import build_index
from tia.knowledge.select import MIN_SCORE, select_sections
from tia.models import IncidentType


@pytest.fixture
def bundle(tmp_path):
    return load_bundle(build_fixture(tmp_path).path)


def _headings(selected):
    return [item.section.heading for item in selected]


def make_bundle(*specs: dict) -> Bundle:
    """点数を確かめるための、手で組んだ束。"""
    sections = []
    for order, spec in enumerate(specs):
        text = f"## {spec['heading']}\n\n{spec.get('body', '本文')}"
        sections.append(Section(
            id=f"a-{order:010x}", file="a.md", heading=spec["heading"], level=2, parent="", order=order,
            line=order + 1, text=text, hosts=spec.get("hosts", {}), types=spec.get("types", {}), confirmed_on=None,
            tokens=spec.get("tokens", 100), sha256=hashlib.sha256(text.encode()).hexdigest(),
            in_card=spec.get("in_card", False), preferred=spec.get("preferred", False)))
    index = build_index([{"id": s.id, "heading": s.heading, "text": s.text, "hosts": s.hosts, "types": s.types}
                         for s in sections])
    return Bundle(version="20260929-000000000000", built_on=date(2026, 9, 29), path=Path("."),
                  sections=tuple(sections), card="", card_tokens=0, tokens=sum(s.tokens for s in sections),
                  index=index, source_hashes={}, notices=(), estimator="test")


def test_router_problem_gets_the_router_sections(bundle):
    selected = select_sections(bundle, hosts=["vm-router01"], incident_type="net", title="IPsec tunnel is down")
    assert _headings(selected)[:2] == ["FRRの状態", "IPsecを切り分ける"]
    assert len(selected) <= 3
    assert sum(item.section.tokens for item in selected) <= 3000


def test_monitor_disk_problem_gets_the_monitor_section_first(bundle):
    selected = select_sections(bundle, hosts=["vm-monitor01"], incident_type=IncidentType.DISK,
                               title="Disk space is low (used > 80%)")
    assert _headings(selected)[0] == "監視VMの状態"


def test_reasons_say_why_the_section_was_chosen(bundle):
    first = select_sections(bundle, hosts=["vm-router01"], incident_type="net", title="IPsec tunnel is down")[0]
    assert first.reasons == ("ホスト vm-router01 が見出しにある", "種類 net の言葉が本文にある",
                             "題名の言葉が一致: ipsec", "ホストの状態を見る節")
    assert first.score == 100 + 20 + 10 + 40
    second = select_sections(bundle, hosts=["vm-router01"], incident_type="net", title="IPsec tunnel is down")[1]
    assert second.reasons[-1] == "解析に向く見出し" and second.score == 60 + 20 + 20


def test_nothing_is_chosen_when_nothing_matches(bundle):
    assert select_sections(bundle, hosts=["unknown"], incident_type="other", title="zzz qqq") == ()
    assert select_sections(bundle, hosts=[], incident_type="other", title="") == ()


def test_sections_of_the_card_are_not_chosen_again(bundle):
    card = {s.heading for s in bundle.sections if s.in_card}
    assert "VM台帳（実測）" in card
    for host in ("vm-router01", "vm-monitor01", "vm-game01"):
        selected = select_sections(bundle, hosts=[host], incident_type="net", title="VM台帳 公開ポート台帳",
                                   max_sections=20, budget=100000)
        assert not card & set(_headings(selected))


def test_same_input_gives_the_same_result(bundle):
    arguments = {"hosts": ["vm-monitor01", "vm-router01"], "incident_type": "container",
                 "title": "Docker コンテナが再起動を繰り返す", "tags": ["docker", "performance"]}
    first = select_sections(bundle, **arguments)
    assert first == select_sections(bundle, **arguments)
    arguments["hosts"] = ["vm-router01", "vm-monitor01"]
    arguments["tags"] = ["performance", "docker"]
    assert first == select_sections(bundle, **arguments)


@pytest.mark.parametrize(("spec", "score"), [
    ({"hosts": {"vm-a": 2}}, None),
    ({"hosts": {"vm-a": 2}, "preferred": True}, 140),
    ({"hosts": {"vm-a": 1}, "preferred": True}, None),
    ({"hosts": {"vm-a": 1}}, None),
    ({"types": {"net": 2}}, 60),
    ({"types": {"net": 1}}, None),
    ({"hosts": {"vm-a": 1}, "types": {"net": 1}}, 50),
    ({"hosts": {"vm-a": 2}, "types": {"net": 1}}, 120),
    ({"hosts": {"vm-a": 2}, "types": {"net": 2}}, 160),
    ({"hosts": {"vm-a": 2}, "types": {"net": 1}, "preferred": True}, 160),
    ({"types": {"net": 2}, "preferred": True}, 80),
    ({"preferred": True}, None),
    ({"hosts": {"vm-b": 2}}, None),
    ({"hosts": {"vm-b": 2}, "types": {"net": 2}}, None),
    ({"types": {"disk": 2}}, None),
])
def test_points_for_host_and_type(spec, score):
    """ホストが合うだけの節と、50 点に満たない節は選ばない。別のホストの節も選ばない。

    ホストが見出しにあり、見出しが解析に向く節は、そのホストの状態を見る節として選ぶ。
    """
    assert MIN_SCORE == 50
    bundle = make_bundle({"heading": "節", **spec}, {"heading": "束が vm-a を知るための節", "hosts": {"vm-a": 1}})
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="net", title="")
    assert [item.score for item in selected] == ([] if score is None else [score])


def test_points_for_words():
    bundle = make_bundle(
        {"heading": "経路の確認", "body": "説明", "hosts": {"vm-a": 1}},
        {"heading": "別の節", "body": "経路 を見る", "hosts": {"vm-a": 1}},
        {"heading": "関係ない節", "body": "説明", "hosts": {"vm-a": 1}},
        {"heading": "埋め草 1"}, {"heading": "埋め草 2"}, {"heading": "埋め草 3"},
    )
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="other", title="経路が切れた")
    assert [(item.section.heading, item.score) for item in selected] == [("経路の確認", 30 + 20)], \
        "見出しでの一致は 20 点、本文での一致は 10 点。本文だけの節は 40 点で、選ばれない"


def test_points_for_words_are_capped():
    words = " ".join(f"word{n:02d}" for n in range(20))
    bundle = make_bundle({"heading": "節", "body": words}, {"heading": "埋め草 1"}, {"heading": "埋め草 2"})
    selected = select_sections(bundle, hosts=[], incident_type="other", title=words)
    assert [item.score for item in selected] == [80]
    assert selected[0].reasons[0].startswith("題名の言葉が一致: word00、word01、word02、word03、word04 ほか 15 語")


def test_strongest_host_counts_once():
    bundle = make_bundle({"heading": "節", "hosts": {"vm-a": 1, "vm-b": 2, "vm-c": 2}, "types": {"net": 1}})
    selected = select_sections(bundle, hosts=["vm-a", "vm-b", "vm-c", "vm-b"], incident_type="net", title="")
    assert [item.score for item in selected] == [100 + 20]
    assert selected[0].reasons == ("ホスト vm-b が見出しにある", "種類 net の言葉が本文にある")


def test_equal_points_keep_the_order_of_the_bundle():
    bundle = make_bundle(*({"heading": f"節 {n}", "hosts": {"vm-a": 2}, "types": {"net": 1}} for n in range(5)))
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="net", title="", max_sections=5)
    assert _headings(selected) == ["節 0", "節 1", "節 2", "節 3", "節 4"]


def test_higher_points_come_first():
    bundle = make_bundle({"heading": "弱い", "hosts": {"vm-a": 2}, "types": {"net": 1}},
                         {"heading": "強い", "hosts": {"vm-a": 2}, "types": {"net": 2}})
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="net", title="")
    assert _headings(selected) == ["強い", "弱い"]


def test_budget_is_kept_and_a_smaller_section_fills_the_rest():
    bundle = make_bundle(
        {"heading": "大", "hosts": {"vm-a": 2}, "types": {"net": 2}, "tokens": 1500},
        {"heading": "中", "hosts": {"vm-a": 2}, "types": {"net": 1}, "preferred": True, "tokens": 1400},
        {"heading": "小", "hosts": {"vm-a": 2}, "types": {"net": 1}, "tokens": 900},
        {"heading": "極小", "hosts": {"vm-a": 1}, "types": {"net": 1}, "tokens": 100},
    )
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="net", title="", budget=3000)
    assert _headings(selected) == ["大", "中", "極小"]
    assert sum(item.section.tokens for item in selected) == 3000


def test_section_larger_than_the_budget_is_never_chosen():
    bundle = make_bundle({"heading": "巨大", "hosts": {"vm-a": 2}, "types": {"net": 2}, "tokens": 3001},
                         {"heading": "普通", "hosts": {"vm-a": 2}, "types": {"net": 1}, "tokens": 3000})
    assert _headings(select_sections(bundle, hosts=["vm-a"], incident_type="net", title="")) == ["普通"]


@pytest.mark.parametrize(("budget", "max_sections"), [(0, 3), (-1, 3), (3000, 0), (3000, -1)])
def test_no_room_means_no_sections(budget, max_sections):
    bundle = make_bundle({"heading": "節", "hosts": {"vm-a": 2}})
    assert select_sections(bundle, hosts=["vm-a"], incident_type="other", title="", budget=budget,
                           max_sections=max_sections) == ()


def test_number_of_sections_is_limited():
    bundle = make_bundle(*({"heading": f"節 {n}", "hosts": {"vm-a": 2}, "types": {"net": 1}} for n in range(10)))
    assert len(select_sections(bundle, hosts=["vm-a"], incident_type="net", title="")) == 3
    assert len(select_sections(bundle, hosts=["vm-a"], incident_type="net", title="", max_sections=7)) == 7


def test_section_that_is_only_a_heading_is_not_chosen():
    bundle = make_bundle({"heading": "空", "hosts": {"vm-a": 2}, "types": {"net": 2}, "tokens": 0},
                         {"heading": "題名だけ", "hosts": {"vm-a": 2}, "types": {"net": 2}, "tokens": 29},
                         {"heading": "短い本文", "hosts": {"vm-a": 2}, "types": {"net": 2}, "tokens": 30})
    assert _headings(select_sections(bundle, hosts=["vm-a"], incident_type="net", title="")) == ["短い本文"]


def test_tags_are_used_as_words():
    bundle = make_bundle({"heading": "節", "body": "swanctl の使い方", "hosts": {"vm-a": 2}},
                         {"heading": "埋め草 1"}, {"heading": "埋め草 2"})
    plain = select_sections(bundle, hosts=["vm-a"], incident_type="other", title="", tags=["swanctl"])
    zabbix = select_sections(bundle, hosts=["vm-a"], incident_type="other", title="",
                             tags=[{"tag": "component", "value": "swanctl"}])
    assert [item.score for item in plain] == [100 + 15]
    assert plain == zabbix


@pytest.mark.parametrize("arguments", [
    {"hosts": None, "incident_type": None, "title": None, "tags": None},
    {"hosts": [None, 3, {"a": 1}], "incident_type": 3, "title": 3, "tags": [None, 3, {"tag": "x"}, {"value": None}]},
    {"hosts": "vm-a", "incident_type": "net", "title": "x" * 100000, "tags": "docker"},
])
def test_odd_input_does_not_break_the_selection(arguments):
    bundle = make_bundle({"heading": "節", "hosts": {"vm-a": 2}})
    assert isinstance(select_sections(bundle, **arguments), tuple)


def test_single_host_given_as_text_is_one_host():
    bundle = make_bundle({"heading": "節", "hosts": {"vm-a": 2}, "types": {"net": 1}})
    assert len(select_sections(bundle, hosts="vm-a", incident_type="net", title="")) == 1


def test_title_is_cut_before_the_words_are_taken():
    words = " ".join(f"word{n:02d}" for n in range(40))
    bundle = make_bundle({"heading": "節", "body": words, "hosts": {"vm-a": 2}}, {"heading": "埋め草 1"},
                         {"heading": "埋め草 2"})
    selected = select_sections(bundle, hosts=["vm-a"], incident_type="other", title=words)
    assert selected[0].reasons[1].endswith("ほか 23 語"), "題名は 200 文字で切る。取り込みの題名の上限と同じ"
